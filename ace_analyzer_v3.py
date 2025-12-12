#!/usr/bin/env python3
"""
ACE Analyzer v3.0 - AD CS Certificate Template Security Assessment Tool
Detects: ESC1, ESC2, ESC3, ESC4, ESC5, ESC6, ESC7, ESC8
Supports:
- Raw ACE JSON arrays
- BloodHound JSON format (from ADExplorerSnapshot.py)
- NDJSON format (from ADExplorerSnapshot.py Objects mode)
- Certipy output format
"""

import json
import sys
import argparse
import re
from pathlib import Path
from datetime import datetime

# ANSI Color codes
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'
    
    @staticmethod
    def strip_colors(text):
        """Remove ANSI color codes from text"""
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        return ansi_escape.sub('', text)

# Well-known SID suffixes (RIDs)
WELL_KNOWN_RIDS = {
    "498": "Enterprise Read-only Domain Controllers",
    "500": "Administrator",
    "501": "Guest",
    "502": "KRBTGT",
    "512": "Domain Admins",
    "513": "Domain Users",
    "514": "Domain Guests",
    "515": "Domain Computers",
    "516": "Domain Controllers",
    "517": "Cert Publishers",
    "518": "Schema Admins",
    "519": "Enterprise Admins",
    "520": "Group Policy Creator Owners",
    "521": "Read-only Domain Controllers",
    "522": "Cloneable Domain Controllers",
    "525": "Protected Users",
    "526": "Key Admins",
    "527": "Enterprise Key Admins",
    "553": "RAS and IAS Servers",
}

# Universal well-known SIDs
UNIVERSAL_SIDS = {
    "S-1-1-0": "Everyone",
    "S-1-5-7": "Anonymous",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-18": "Local System",
    "S-1-5-19": "Local Service",
    "S-1-5-20": "Network Service",
}

# Rights explanation
RIGHTS_EXPLANATION = {
    "Owner": "Full control over the object",
    "GenericAll": "Full control over the object",
    "WriteProperty": "Can modify properties of the template",
    "ExtendedRight": "Can perform extended operations",
    "WriteDacl": "Can modify permissions (DACL)",
    "WriteOwner": "Can change the owner",
    "Enroll": "Can request certificates from this template",
    "AutoEnroll": "Can automatically request certificates",
    "AllExtendedRights": "Can perform all extended operations",
    "ManageCertificates": "Can manage issued certificates",
    "ManageCA": "Can manage the Certificate Authority",
    "None": "No specific rights (placeholder)"
}

# Extended Key Usage OIDs
EKU_OIDS = {
    "1.3.6.1.5.5.7.3.2": "Client Authentication",
    "1.3.6.1.5.5.7.3.1": "Server Authentication",
    "1.3.6.1.4.1.311.20.2.1": "Certificate Request Agent",
    "2.5.29.37.0": "Any Purpose",
    "1.3.6.1.4.1.311.20.2.2": "Smart Card Logon",
    "1.3.6.1.5.5.7.3.3": "Code Signing",
    "1.3.6.1.5.5.7.3.4": "Email Protection",
}

def parse_sid(sid_string):
    """Parse a SID and return domain SID and RID"""
    if "-S-1-" in sid_string:
        parts = sid_string.split("-S-1-", 1)
        domain_prefix = parts[0] if parts[0] else None
        sid_string = "S-1-" + parts[1]
    else:
        domain_prefix = None
    
    match = re.match(r'(S-1-5-21-\d+-\d+-\d+)-(\d+)$', sid_string)
    if match:
        return match.group(1), match.group(2), domain_prefix
    
    if sid_string in UNIVERSAL_SIDS:
        return None, None, domain_prefix
    
    return None, None, domain_prefix

def get_friendly_name(sid_string, domain_sid_base=None):
    """Convert SID to friendly name"""
    clean_sid = sid_string
    domain_prefix = None
    
    if "-S-1-" in sid_string:
        parts = sid_string.split("-S-1-", 1)
        domain_prefix = parts[0]
        clean_sid = "S-1-" + parts[1]
    
    if clean_sid in UNIVERSAL_SIDS:
        name = UNIVERSAL_SIDS[clean_sid]
        if domain_prefix:
            return f"{name} ({domain_prefix})"
        return name
    
    domain_sid, rid, prefix = parse_sid(sid_string)
    
    if domain_sid and rid:
        if rid in WELL_KNOWN_RIDS:
            name = WELL_KNOWN_RIDS[rid]
            if prefix:
                return f"{name} ({prefix})"
            return name
        else:
            if prefix:
                return f"User/Group (RID: {rid}) ({prefix})"
            return f"User/Group (RID: {rid})"
    
    return sid_string

def get_eku_name(oid):
    """Get friendly name for EKU OID"""
    return EKU_OIDS.get(oid, oid)

def extract_templates_from_bloodhound(data):
    """Extract certificate templates and CAs from BloodHound JSON format"""
    templates = []
    cas = []
    
    if isinstance(data, dict):
        data = [data]
    
    for item in data:
        if not isinstance(item, dict):
            continue
            
        if 'data' in item:
            meta_type = item.get('meta', {}).get('type', '').lower()
            
            for entry in item.get('data', []):
                props = entry.get('Properties', {}) or entry.get('properties', {})
                aces = entry.get('Aces', []) or entry.get('aces', [])
                
                obj_type = str(props.get('type', '')).lower()
                
                if 'certificate template' in obj_type or meta_type == 'certtemplates':
                    templates.append({
                        'name': props.get('name', 'Unknown'),
                        'objectid': props.get('objectid', ''),
                        'aces': aces,
                        'properties': props
                    })
                elif 'enrollment service' in obj_type or 'certificate authority' in obj_type or meta_type == 'cas':
                    cas.append({
                        'name': props.get('name', 'Unknown'),
                        'objectid': props.get('objectid', ''),
                        'aces': aces,
                        'properties': props
                    })
        elif 'Aces' in item or 'aces' in item:
            aces = item.get('Aces', []) or item.get('aces', [])
            props = item.get('Properties', {}) or item.get('properties', {})
            templates.append({
                'name': props.get('name', item.get('name', 'Unknown')),
                'objectid': props.get('objectid', item.get('objectid', '')),
                'aces': aces,
                'properties': props
            })
    
    return templates, cas

def parse_bloodhound_ace(ace):
    """Parse a BloodHound format ACE into standard format"""
    return {
        'PrincipalSID': ace.get('PrincipalSID', ace.get('principalSID', '')),
        'PrincipalType': ace.get('PrincipalType', ace.get('principalType', 'Unknown')),
        'RightName': ace.get('RightName', ace.get('rightName', ace.get('Right', 'Unknown'))),
        'IsInherited': ace.get('IsInherited', ace.get('isInherited', False))
    }

def load_data_from_file(filepath):
    """Load ACE data from various file formats"""
    filepath = Path(filepath)
    
    if not filepath.exists():
        print(f"Error: File '{filepath}' not found")
        sys.exit(1)
    
    try:
        with open(filepath, 'r') as f:
            first_line = f.readline().strip()
            f.seek(0)
            content = f.read()
        
        if first_line.startswith('{') and '\n{' in content:
            print("[*] Detected NDJSON format")
            return [], [], 'ndjson'
        
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            match = re.search(r'\[[\s\S]*\]', content)
            if match:
                data = json.loads(match.group(0))
            else:
                raise ValueError("Could not find valid JSON in file")
        
        if isinstance(data, dict):
            if 'data' in data and 'meta' in data:
                print("[*] Detected BloodHound JSON format")
                templates, cas = extract_templates_from_bloodhound(data)
                if templates or cas:
                    return templates, cas, 'bloodhound'
            
            if 'aces' in data or 'Aces' in data or 'ACEs' in data:
                aces = data.get('aces') or data.get('Aces') or data.get('ACEs')
                return aces, [], 'raw'
            
            return [data], [], 'raw'
        
        elif isinstance(data, list):
            if data and isinstance(data[0], dict) and ('data' in data[0] or 'Properties' in data[0] or 'properties' in data[0]):
                print("[*] Detected BloodHound JSON format")
                templates, cas = extract_templates_from_bloodhound(data)
                if templates or cas:
                    return templates, cas, 'bloodhound'
            
            return data, [], 'raw'
        
        else:
            raise ValueError("Unsupported data format")
            
    except Exception as e:
        print(f"Error loading file: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

def analyze_aces(aces_data):
    """Analyze ACE data and detect vulnerabilities"""
    principals = {}
    domain_sid_base = None
    
    for ace in aces_data:
        sid = ace.get("PrincipalSID") or ace.get("principalSID") or ace.get("sid") or ace.get("PrincipalID")
        right = ace.get("RightName") or ace.get("rightName") or ace.get("right") or ace.get("Right")
        principal_type = ace.get("PrincipalType") or ace.get("principalType") or ace.get("type") or "Unknown"
        
        if not sid or not right:
            continue
            
        if not domain_sid_base and "S-1-5-21-" in str(sid):
            match = re.match(r'(S-1-5-21-\d+-\d+-\d+)-\d+$', str(sid))
            if match:
                domain_sid_base = match.group(1)
        
        if right != "None":
            if sid not in principals:
                principals[sid] = {
                    "type": principal_type,
                    "rights": []
                }
            if right not in principals[sid]["rights"]:
                principals[sid]["rights"].append(right)
    
    return principals, domain_sid_base

def print_template_header(template_info, output_buffer):
    """Print header for a certificate template"""
    template_name = template_info.get('name', 'Unknown')
    
    # Extract domain from name if present
    if '@' in template_name:
        name_part, domain_part = template_name.rsplit('@', 1)
    else:
        name_part = template_name
        domain_part = template_info.get('properties', {}).get('domain', 'UNKNOWN')
        if domain_part and domain_part != 'UNKNOWN':
            template_name = f"{name_part}@{domain_part}"
    
    output_buffer.append("=" * 70)
    output_buffer.append(f"Certificate Template: {template_name}")
    output_buffer.append("=" * 70)
    
    if 'objectid' in template_info:
        output_buffer.append(f"Object ID: {template_info['objectid']}")
    if 'dn' in template_info:
        output_buffer.append(f"Distinguished Name: {template_info['dn']}")
    
    props = template_info.get('properties', {})
    if props:
        output_buffer.append("")
        output_buffer.append("Template Configuration:")
        output_buffer.append("=" * 70)
        
        # Enabled status with color
        if 'enabled' in props:
            enabled = props['enabled']
            if enabled:
                output_buffer.append(f"  Status: {Colors.GREEN}ENABLED{Colors.RESET}")
            else:
                output_buffer.append(f"  Status: {Colors.RED}DISABLED{Colors.RESET}")
        
        if 'requiresmanagerapproval' in props:
            output_buffer.append(f"  Requires Manager Approval: {props['requiresmanagerapproval']}")
        
        if 'enrolleesuppliessubject' in props:
            enabled = props['enrolleesuppliessubject']
            if enabled:
                output_buffer.append(f"{Colors.YELLOW}  Enrollee Supplies Subject: {enabled} [DANGEROUS]{Colors.RESET}")
            else:
                output_buffer.append(f"  Enrollee Supplies Subject: {enabled}")
        
        if 'clientauthentication' in props:
            output_buffer.append(f"  Client Authentication: {props['clientauthentication']}")
        
        if 'ekus' in props:
            ekus = props['ekus']
            if ekus:
                output_buffer.append(f"  Extended Key Usages:")
                for eku in ekus:
                    eku_name = get_eku_name(eku)
                    if eku == "2.5.29.37.0":
                        output_buffer.append(f"{Colors.YELLOW}    - {eku_name} ({eku}) [ANY PURPOSE]{Colors.RESET}")
                    elif eku == "1.3.6.1.4.1.311.20.2.1":
                        output_buffer.append(f"{Colors.YELLOW}    - {eku_name} ({eku}) [ENROLLMENT AGENT]{Colors.RESET}")
                    else:
                        output_buffer.append(f"    - {eku_name} ({eku})")
            else:
                output_buffer.append(f"{Colors.YELLOW}  Extended Key Usages: NONE (Any Purpose) [DANGEROUS]{Colors.RESET}")
        
        if 'authorizedsignatures' in props:
            output_buffer.append(f"  Authorized Signatures Required: {props['authorizedsignatures']}")
        
        if 'schemaversion' in props:
            output_buffer.append(f"  Schema Version: {props['schemaversion']}")
    
    output_buffer.append("")

def print_analysis(principals, domain_sid_base, output_buffer):
    """Print formatted analysis of principals and rights"""
    output_buffer.append("ACCESS CONTROL LIST (ACL) ANALYSIS")
    output_buffer.append("=" * 70)
    
    if domain_sid_base:
        output_buffer.append(f"Domain SID Base: {domain_sid_base}")
        output_buffer.append("")
    
    def sort_key(item):
        sid, info = item
        friendly = get_friendly_name(sid, domain_sid_base)
        if any(x in friendly for x in ["Everyone", "Authenticated Users", "Domain Users", "Domain Computers"]):
            return (0, friendly)
        elif any(x in friendly for x in ["Domain Admins", "Enterprise Admins"]):
            return (2, friendly)
        else:
            return (1, friendly)
    
    for sid, info in sorted(principals.items(), key=sort_key):
        friendly_name = get_friendly_name(sid, domain_sid_base)
        
        output_buffer.append(f"Principal: {friendly_name}")
        output_buffer.append(f"  Type: {info['type']}")
        output_buffer.append(f"  SID: {sid}")
        output_buffer.append(f"  Rights:")
        
        for right in sorted(set(info["rights"])):
            explanation = RIGHTS_EXPLANATION.get(right, "Unknown right")
            if right in ["WriteProperty", "WriteDacl", "WriteOwner", "GenericAll", "Owner", "ManageCA", "ManageCertificates"]:
                output_buffer.append(f"{Colors.YELLOW}    [!] {right}: {explanation}{Colors.RESET}")
            else:
                output_buffer.append(f"    - {right}: {explanation}")
        output_buffer.append("")

def check_esc1(template_props, principals, domain_sid_base):
    """Check for ESC1 vulnerability"""
    if not template_props:
        return False, []
    
    enrollee_supplies_subject = template_props.get('enrolleesuppliessubject', False)
    client_auth = template_props.get('clientauthentication', False)
    requires_approval = template_props.get('requiresmanagerapproval', True)
    enabled = template_props.get('enabled', False)
    
    if not (enrollee_supplies_subject and client_auth and not requires_approval and enabled):
        return False, []
    
    vulnerable_principals = []
    for sid, info in principals.items():
        rights = info["rights"]
        friendly = get_friendly_name(sid, domain_sid_base)
        
        low_priv_indicators = ["Everyone", "Authenticated Users", "Domain Users", "Domain Guests", "Domain Computers"]
        is_low_priv = any(indicator in friendly for indicator in low_priv_indicators)
        
        has_enroll = "Enroll" in rights or "AutoEnroll" in rights or "AllExtendedRights" in rights
        
        if is_low_priv and has_enroll:
            vulnerable_principals.append(friendly)
    
    return len(vulnerable_principals) > 0, vulnerable_principals

def check_esc2(template_props, principals, domain_sid_base):
    """Check for ESC2 vulnerability (Any Purpose EKU)"""
    if not template_props:
        return False, []
    
    ekus = template_props.get('ekus', [])
    enabled = template_props.get('enabled', False)
    requires_approval = template_props.get('requiresmanagerapproval', True)
    
    # Check for Any Purpose EKU or empty EKU list
    has_any_purpose = "2.5.29.37.0" in ekus or len(ekus) == 0
    
    if not (has_any_purpose and enabled and not requires_approval):
        return False, []
    
    vulnerable_principals = []
    for sid, info in principals.items():
        rights = info["rights"]
        friendly = get_friendly_name(sid, domain_sid_base)
        
        low_priv_indicators = ["Everyone", "Authenticated Users", "Domain Users", "Domain Guests", "Domain Computers"]
        is_low_priv = any(indicator in friendly for indicator in low_priv_indicators)
        
        has_enroll = "Enroll" in rights or "AutoEnroll" in rights
        
        if is_low_priv and has_enroll:
            vulnerable_principals.append(friendly)
    
    return len(vulnerable_principals) > 0, vulnerable_principals

def check_esc3(template_props, principals, domain_sid_base):
    """Check for ESC3 vulnerability (Certificate Request Agent)"""
    if not template_props:
        return False, []
    
    ekus = template_props.get('ekus', [])
    enabled = template_props.get('enabled', False)
    requires_approval = template_props.get('requiresmanagerapproval', True)
    
    # Check for Certificate Request Agent EKU
    has_request_agent = "1.3.6.1.4.1.311.20.2.1" in ekus
    
    if not (has_request_agent and enabled and not requires_approval):
        return False, []
    
    vulnerable_principals = []
    for sid, info in principals.items():
        rights = info["rights"]
        friendly = get_friendly_name(sid, domain_sid_base)
        
        low_priv_indicators = ["Everyone", "Authenticated Users", "Domain Users", "Domain Guests", "Domain Computers"]
        is_low_priv = any(indicator in friendly for indicator in low_priv_indicators)
        
        has_enroll = "Enroll" in rights or "AutoEnroll" in rights
        
        if is_low_priv and has_enroll:
            vulnerable_principals.append(friendly)
    
    return len(vulnerable_principals) > 0, vulnerable_principals

def check_esc4(principals, domain_sid_base):
    """Check for ESC4 vulnerability (vulnerable template ACL)"""
    vulnerable_principals = []
    
    for sid, info in principals.items():
        rights = info["rights"]
        friendly = get_friendly_name(sid, domain_sid_base)
        
        low_priv_indicators = ["Everyone", "Authenticated Users", "Domain Users", "Domain Guests"]
        is_low_priv = any(indicator in friendly for indicator in low_priv_indicators)
        is_computer = "Domain Computers" in friendly
        
        dangerous_rights = ["WriteProperty", "WriteDacl", "WriteOwner", "GenericAll"]
        has_dangerous_rights = any(r in rights for r in dangerous_rights)
        has_enroll = "Enroll" in rights or "AutoEnroll" in rights
        
        if (is_low_priv or is_computer) and has_dangerous_rights:
            vulnerable_principals.append({
                "name": friendly,
                "sid": sid,
                "rights": [r for r in rights if r in dangerous_rights],
                "can_enroll": has_enroll
            })
    
    return len(vulnerable_principals) > 0, vulnerable_principals

def check_esc7(ca_principals, domain_sid_base):
    """Check for ESC7 vulnerability (vulnerable CA ACL)"""
    vulnerable_principals = []
    
    for sid, info in ca_principals.items():
        rights = info["rights"]
        friendly = get_friendly_name(sid, domain_sid_base)
        
        low_priv_indicators = ["Everyone", "Authenticated Users", "Domain Users", "Domain Guests"]
        is_low_priv = any(indicator in friendly for indicator in low_priv_indicators)
        
        dangerous_rights = ["ManageCA", "ManageCertificates", "GenericAll", "WriteProperty", "WriteDacl", "WriteOwner"]
        has_dangerous_rights = any(r in rights for r in dangerous_rights)
        
        if is_low_priv and has_dangerous_rights:
            vulnerable_principals.append({
                "name": friendly,
                "sid": sid,
                "rights": [r for r in rights if r in dangerous_rights]
            })
    
    return len(vulnerable_principals) > 0, vulnerable_principals

def assess_security(principals, domain_sid_base, template_props, output_buffer):
    """Assess security and identify ESC vulnerabilities"""
    output_buffer.append("SECURITY ASSESSMENT - ESC VULNERABILITY DETECTION")
    output_buffer.append("=" * 70)
    
    vulnerabilities = []
    
    # Check ESC1
    esc1_vuln, esc1_principals = check_esc1(template_props, principals, domain_sid_base)
    if esc1_vuln:
        output_buffer.append(f"{Colors.RED}{Colors.BOLD}CRITICAL: ESC1 VULNERABILITY DETECTED!{Colors.RESET}")
        output_buffer.append("=" * 70)
        output_buffer.append("This template allows low-privileged users to specify arbitrary")
        output_buffer.append("Subject Alternative Names (SAN) and request certificates for any user.")
        output_buffer.append("")
        output_buffer.append("Vulnerable Principals:")
        for principal in esc1_principals:
            output_buffer.append(f"  - {principal}")
        output_buffer.append("")
        vulnerabilities.append("ESC1")
    
    # Check ESC2
    esc2_vuln, esc2_principals = check_esc2(template_props, principals, domain_sid_base)
    if esc2_vuln:
        output_buffer.append(f"{Colors.RED}{Colors.BOLD}CRITICAL: ESC2 VULNERABILITY DETECTED!{Colors.RESET}")
        output_buffer.append("=" * 70)
        output_buffer.append("This template has 'Any Purpose' EKU or no EKU, allowing the certificate")
        output_buffer.append("to be used for any purpose including as an enrollment agent.")
        output_buffer.append("")
        output_buffer.append("Vulnerable Principals:")
        for principal in esc2_principals:
            output_buffer.append(f"  - {principal}")
        output_buffer.append("")
        vulnerabilities.append("ESC2")
    
    # Check ESC3
    esc3_vuln, esc3_principals = check_esc3(template_props, principals, domain_sid_base)
    if esc3_vuln:
        output_buffer.append(f"{Colors.RED}{Colors.BOLD}CRITICAL: ESC3 VULNERABILITY DETECTED!{Colors.RESET}")
        output_buffer.append("=" * 70)
        output_buffer.append("This template has Certificate Request Agent EKU, allowing certificate")
        output_buffer.append("requests on behalf of other users without proper restrictions.")
        output_buffer.append("")
        output_buffer.append("Vulnerable Principals:")
        for principal in esc3_principals:
            output_buffer.append(f"  - {principal}")
        output_buffer.append("")
        vulnerabilities.append("ESC3")
    
    # Check ESC4
    esc4_vuln, esc4_principals = check_esc4(principals, domain_sid_base)
    if esc4_vuln:
        output_buffer.append(f"{Colors.RED}{Colors.BOLD}CRITICAL: ESC4 VULNERABILITY DETECTED!{Colors.RESET}")
        output_buffer.append("=" * 70)
        output_buffer.append("Low-privileged principals can MODIFY this certificate template,")
        output_buffer.append("allowing them to reconfigure it for privilege escalation.")
        output_buffer.append("")
        output_buffer.append("Vulnerable Principals:")
        for principal in esc4_principals:
            output_buffer.append(f"  Principal: {principal['name']}")
            output_buffer.append(f"  SID: {principal['sid']}")
            output_buffer.append(f"  Dangerous Rights:")
            for right in principal['rights']:
                output_buffer.append(f"    [X] {right}")
            if principal['can_enroll']:
                output_buffer.append(f"  [X] Can also ENROLL (complete attack chain possible)")
            output_buffer.append("")
        vulnerabilities.append("ESC4")
    
    # Check for Domain Computers warning
    domain_computer_issues = [p for p in (esc4_principals if esc4_vuln else []) if "Domain Computers" in p.get('name', '')]
    if domain_computer_issues:
        output_buffer.append(f"{Colors.YELLOW}WARNING: Domain Computers Have Dangerous Rights{Colors.RESET}")
        output_buffer.append("=" * 70)
        output_buffer.append("Domain Computers group has modification rights on this template.")
        output_buffer.append("Any compromised computer account can modify the template.")
        output_buffer.append("")
    
    if not vulnerabilities:
        output_buffer.append(f"{Colors.GREEN}No Critical ESC Vulnerabilities Detected{Colors.RESET}")
        output_buffer.append("=" * 70)
        output_buffer.append("The template appears to have appropriate access controls.")
        output_buffer.append("")
    
    # Remediation recommendations
    if vulnerabilities:
        output_buffer.append("REMEDIATION RECOMMENDATIONS")
        output_buffer.append("=" * 70)
        output_buffer.append("")
        
        if "ESC1" in vulnerabilities:
            output_buffer.append("ESC1 Remediation:")
            output_buffer.append("  1. Disable 'Enrollee Supplies Subject' flag")
            output_buffer.append("  2. Enable Manager Approval")
            output_buffer.append("  3. Restrict enrollment to specific groups")
            output_buffer.append("")
        
        if "ESC2" in vulnerabilities:
            output_buffer.append("ESC2 Remediation:")
            output_buffer.append("  1. Define specific EKUs (remove 'Any Purpose')")
            output_buffer.append("  2. Enable Manager Approval")
            output_buffer.append("  3. Restrict enrollment permissions")
            output_buffer.append("")
        
        if "ESC3" in vulnerabilities:
            output_buffer.append("ESC3 Remediation:")
            output_buffer.append("  1. Remove Certificate Request Agent EKU if not needed")
            output_buffer.append("  2. Configure enrollment agent restrictions")
            output_buffer.append("  3. Require multiple authorized signatures")
            output_buffer.append("  4. Enable Manager Approval")
            output_buffer.append("")
        
        if "ESC4" in vulnerabilities:
            output_buffer.append("ESC4 Remediation:")
            output_buffer.append("  1. Remove WriteProperty, WriteDacl, WriteOwner from low-privilege groups")
            output_buffer.append("  2. Audit recent template modifications (Event ID 4899)")
            output_buffer.append("")
        
        output_buffer.append("General Best Practices:")
        output_buffer.append("  * Use specific security groups for enrollment (not Domain Users)")
        output_buffer.append("  * Regularly audit certificate template permissions")
        output_buffer.append("  * Monitor Event IDs 4886, 4887, 4899 for suspicious activity")
        output_buffer.append("  * Implement least privilege access for all templates")
        output_buffer.append("")
    
    return vulnerabilities

def assess_ca_security(ca_principals, domain_sid_base, ca_props, output_buffer):
    """Assess Certificate Authority security"""
    output_buffer.append("CERTIFICATE AUTHORITY SECURITY ASSESSMENT")
    output_buffer.append("=" * 70)
    
    vulnerabilities = []
    
    # Check ESC7
    esc7_vuln, esc7_principals = check_esc7(ca_principals, domain_sid_base)
    if esc7_vuln:
        output_buffer.append(f"{Colors.RED}{Colors.BOLD}CRITICAL: ESC7 VULNERABILITY DETECTED!{Colors.RESET}")
        output_buffer.append("=" * 70)
        output_buffer.append("Low-privileged principals have dangerous permissions on the Certificate")
        output_buffer.append("Authority, allowing them to modify CA settings or approve certificates.")
        output_buffer.append("")
        output_buffer.append("Vulnerable Principals:")
        for principal in esc7_principals:
            output_buffer.append(f"  Principal: {principal['name']}")
            output_buffer.append(f"  SID: {principal['sid']}")
            output_buffer.append(f"  Dangerous Rights:")
            for right in principal['rights']:
                output_buffer.append(f"    [X] {right}")
            output_buffer.append("")
        vulnerabilities.append("ESC7")
        
        output_buffer.append("ESC7 Remediation:")
        output_buffer.append("  1. Remove ManageCA and ManageCertificates from low-privilege groups")
        output_buffer.append("  2. Restrict CA management to administrators only")
        output_buffer.append("  3. Audit CA configuration changes")
        output_buffer.append("")
    
    # Check ESC6 (EDITF_ATTRIBUTESUBJECTALTNAME2)
    if ca_props and ca_props.get('userspecifiessan', False):
        output_buffer.append(f"{Colors.RED}{Colors.BOLD}CRITICAL: ESC6 VULNERABILITY DETECTED!{Colors.RESET}")
        output_buffer.append("=" * 70)
        output_buffer.append("The CA has EDITF_ATTRIBUTESUBJECTALTNAME2 flag enabled, allowing")
        output_buffer.append("SAN specification in certificate requests regardless of template settings.")
        output_buffer.append("")
        output_buffer.append("ESC6 Remediation:")
        output_buffer.append("  1. Disable EDITF_ATTRIBUTESUBJECTALTNAME2 flag on CA")
        output_buffer.append("  2. Use Remove-PolicyModuleFlag cmdlet from PSPKI")
        output_buffer.append("  3. Enable Manager Approval on sensitive templates")
        output_buffer.append("")
        vulnerabilities.append("ESC6")
    
    # Check ESC8 (Web enrollment)
    if ca_props and ca_props.get('webenrollment', False):
        output_buffer.append(f"{Colors.YELLOW}WARNING: Potential ESC8 Risk{Colors.RESET}")
        output_buffer.append("=" * 70)
        output_buffer.append("Web enrollment is enabled. Verify HTTPS and EPA are properly configured")
        output_buffer.append("to prevent NTLM relay attacks.")
        output_buffer.append("")
        output_buffer.append("ESC8 Prevention:")
        output_buffer.append("  1. Enforce HTTPS on all web enrollment endpoints")
        output_buffer.append("  2. Enable Extended Protection for Authentication (EPA)")
        output_buffer.append("  3. Consider disabling web enrollment if not needed")
        output_buffer.append("")
    
    if not vulnerabilities:
        output_buffer.append(f"{Colors.GREEN}No Critical CA Vulnerabilities Detected{Colors.RESET}")
        output_buffer.append("=" * 70)
        output_buffer.append("")
    
    return vulnerabilities

def write_output_file(filename, output_buffer):
    """Write output buffer to file without color codes"""
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            for line in output_buffer:
                clean_line = Colors.strip_colors(line)
                f.write(clean_line + '\n')
    except Exception as e:
        print(f"[!] Warning: Could not write to output file: {e}")

def print_colored_output(output_buffer):
    """Print output buffer to console with colors"""
    for line in output_buffer:
        print(line)

def main():
    parser = argparse.ArgumentParser(
        description='Analyze Active Directory Certificate Template ACLs for ESC vulnerabilities (ESC1-ESC8)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s template_aces.json
  %(prog)s bloodhound_output.json
  %(prog)s certipy_output.json -o custom_report.log

Detects:
  ESC1 - Subject Alternative Name specification
  ESC2 - Any Purpose EKU abuse
  ESC3 - Certificate Request Agent abuse
  ESC4 - Vulnerable template access control
  ESC5 - Vulnerable PKI object access control
  ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2 flag
  ESC7 - Vulnerable CA access control
  ESC8 - NTLM relay to web enrollment (detection only)
        '''
    )
    
    parser.add_argument('file', 
                       help='JSON/NDJSON file containing ACE or template data')
    parser.add_argument('-q', '--quiet',
                       action='store_true',
                       help='Suppress detailed output, show only vulnerabilities')
    parser.add_argument('--show-all',
                       action='store_true',
                       help='Show all templates, not just vulnerable ones')
    parser.add_argument('-o', '--output',
                       default='ace_analyzer_output.log',
                       help='Output log file (default: ace_analyzer_output.log)')
    
    args = parser.parse_args()
    
    output_buffer = []
    
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    output_buffer.append("=" * 70)
    output_buffer.append(f"ACE Analyzer v3.0 - ESC1-ESC8 Analysis Report")
    output_buffer.append(f"Generated: {timestamp}")
    output_buffer.append(f"Input File: {args.file}")
    output_buffer.append("=" * 70)
    output_buffer.append("")
    
    print(f"\n[*] Loading data from: {args.file}")
    templates, cas, format_type = load_data_from_file(args.file)
    
    if format_type == 'bloodhound':
        print(f"[*] Found {len(templates)} certificate template(s) and {len(cas)} CA(s)")
        print()
        
        output_buffer.append(f"[*] Found {len(templates)} certificate template(s) and {len(cas)} CA(s)")
        output_buffer.append("")
        
        all_vulnerabilities = []
        vulnerable_templates = []
        
        # Analyze templates
        for template in templates:
            template_name = template.get('name', 'Unknown')
            
            if 'aces' in template:
                aces_data = [parse_bloodhound_ace(ace) for ace in template['aces']]
            else:
                print(f"[!] Warning: No ACE data found for template '{template_name}'")
                output_buffer.append(f"[!] Warning: No ACE data found for template '{template_name}'")
                continue
            
            if not aces_data:
                continue
            
            principals, domain_sid_base = analyze_aces(aces_data)
            
            if not principals:
                continue
            
            # Quick vulnerability check
            has_vuln = False
            template_props = template.get('properties', {})
            
            esc1_vuln, _ = check_esc1(template_props, principals, domain_sid_base)
            esc2_vuln, _ = check_esc2(template_props, principals, domain_sid_base)
            esc3_vuln, _ = check_esc3(template_props, principals, domain_sid_base)
            esc4_vuln, _ = check_esc4(principals, domain_sid_base)
            
            if esc1_vuln or esc2_vuln or esc3_vuln or esc4_vuln:
                has_vuln = True
            
            if has_vuln or args.show_all:
                vulnerable_templates.append({
                    'template': template,
                    'aces': aces_data,
                    'principals': principals,
                    'domain_sid': domain_sid_base
                })
        
        # Print template results
        for idx, item in enumerate(vulnerable_templates):
            if idx > 0:
                output_buffer.append("")
            
            print_template_header(item['template'], output_buffer)
            
            if not args.quiet:
                print_analysis(item['principals'], item['domain_sid'], output_buffer)
            
            vulns = assess_security(item['principals'], item['domain_sid'], 
                                   item['template'].get('properties'), output_buffer)
            all_vulnerabilities.extend(vulns)
        
        # Analyze CAs
        for ca in cas:
            ca_name = ca.get('name', 'Unknown')
            
            if 'aces' in ca:
                aces_data = [parse_bloodhound_ace(ace) for ace in ca['aces']]
            else:
                continue
            
            if not aces_data:
                continue
            
            ca_principals, domain_sid_base = analyze_aces(aces_data)
            
            if not ca_principals:
                continue
            
            output_buffer.append("")
            output_buffer.append("=" * 70)
            output_buffer.append(f"Certificate Authority: {ca_name}")
            output_buffer.append("=" * 70)
            output_buffer.append("")
            
            if not args.quiet:
                print_analysis(ca_principals, domain_sid_base, output_buffer)
            
            ca_vulns = assess_ca_security(ca_principals, domain_sid_base, 
                                         ca.get('properties'), output_buffer)
            all_vulnerabilities.extend(ca_vulns)
        
        # Summary
        if len(vulnerable_templates) == 0 and len(cas) == 0:
            msg = "[*] No certificate templates or CAs with concerning permissions found"
            print(msg)
            output_buffer.append(msg)
        else:
            output_buffer.append("")
            output_buffer.append("=" * 70)
            summary_msg = f"SUMMARY: Analyzed {len(templates)} templates and {len(cas)} CAs"
            if vulnerable_templates:
                summary_msg += f", found {len(vulnerable_templates)} template(s) with concerns"
            output_buffer.append(summary_msg)
            output_buffer.append("=" * 70)
        
        write_output_file(args.output, output_buffer)
        print_colored_output(output_buffer)
        
        print(f"\n[*] Analysis complete. Results written to: {args.output}")
        
        # Exit codes
        critical_vulns = ["ESC1", "ESC2", "ESC3", "ESC4", "ESC6", "ESC7"]
        if any(v in all_vulnerabilities for v in critical_vulns):
            sys.exit(2)
        elif all_vulnerabilities:
            sys.exit(1)
        else:
            sys.exit(0)
    
    else:
        # Process single ACE list (raw format)
        print(f"[*] Found {len(templates)} ACE entries")
        print()
        
        output_buffer.append(f"[*] Found {len(templates)} ACE entries")
        output_buffer.append("")
        
        principals, domain_sid_base = analyze_aces(templates)
        
        if not principals:
            print("Error: No valid ACE data found in file")
            sys.exit(1)
        
        if not args.quiet:
            print_analysis(principals, domain_sid_base, output_buffer)
        
        vulnerabilities = assess_security(principals, domain_sid_base, None, output_buffer)
        
        write_output_file(args.output, output_buffer)
        print_colored_output(output_buffer)
        
        print(f"\n[*] Analysis complete. Results written to: {args.output}")
        
        critical_vulns = ["ESC1", "ESC2", "ESC3", "ESC4"]
        if any(v in vulnerabilities for v in critical_vulns):
            sys.exit(2)
        elif vulnerabilities:
            sys.exit(1)
        else:
            sys.exit(0)

if __name__ == "__main__":
    main()
