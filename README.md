Updated version got not fully tested yet, so no guarantee for the output, in the end always keep using your own brain.

# ACE Analyzer v4.2

A Python tool for assessing Active Directory Certificate Services (AD CS) security. It parses output from **Certipy**, **Certify**, **Certify 2.0**, **BloodHound / ADExplorerSnapshot.py**, and raw PowerShell ACE exports, then detects ESC1–ESC16 privilege-escalation misconfigurations.

---

## Requirements

- Python 3.6 or above — no additional packages required
- Clone: `git clone https://github.com/vianic/ace_analyzer.git`

---

## Usage

```
python3 ace_analyzer.py [options] <input-file>
```

| Flag | Description |
|------|-------------|
| `<file>` | Input file (JSON, plaintext, or raw ACE array — format auto-detected; optional when using `--attack-path` standalone) |
| `-q / --quiet` | Only print vulnerability findings, suppress the ACL detail table |
| `--show-all` | Show every template, including ones with no findings |
| `-o FILE` | Write a clean (no ANSI colour) copy of the report to FILE (default: `ace_analyzer_output.log`) |
| `--attack-path / -ap ESC` | Show exploitation commands for a specific ESC (e.g. `ESC1`, `ESC4`, `ESC15`, or `ALL` for every detected ESC). Can be used without a scan file for standalone reference. |
| `--show-advanced` | Show advanced post-exploitation techniques: Golden Certificate, DCSync via Pass-the-Certificate, Schannel LDAP shell, Shadow Credentials |
| `--remediation` | Show consolidated remediation guidance for all detected vulnerabilities |
| `--html FILE` | Generate a self-contained dark-themed HTML report with three tabs: **Vulnerability Overview**, **Abuse Techniques**, **ACL Analysis** (e.g. `report.html`) |

### Examples

```bash
# Scan Certipy JSON output for all vulnerabilities
python3 ace_analyzer.py certipy_output.json

# Scan Certify plaintext output, only show findings
python3 ace_analyzer.py -q certify_find.txt

# Scan BloodHound dump — show every template including secure ones
python3 ace_analyzer.py --show-all bloodhound_certtemplates.json

# Scan and save a clean report
python3 ace_analyzer.py certipy_output.json -o report_$(date +%F).log

# Show exploitation commands for a specific ESC
python3 ace_analyzer.py --attack-path ESC1 certipy_output.json

# Show exploitation commands without a scan file (standalone reference)
python3 ace_analyzer.py --attack-path ESC5

# Show remediation guidance alongside the scan
python3 ace_analyzer.py --remediation certipy_output.json

# Generate a full HTML report
python3 ace_analyzer.py --html report.html certipy_output.json

# Full output: attack paths + remediation + HTML report in one run
python3 ace_analyzer.py --attack-path ALL --html report.html --remediation scan.json
```

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No vulnerabilities found |
| `1` | Non-critical findings only (ESC9, ESC10, ESC13, ESC16) |
| `2` | Critical vulnerability found (ESC1–4, ESC6, ESC7, ESC11, ESC15) |

---

## Supported Input Formats

The tool auto-detects the format — no flag needed.

| Format | Detected by | Source |
|--------|-------------|--------|
| **Certipy JSON** | Top-level `Certificate Templates` / `Certificate Authorities` keys | `certipy find -json` |
| **Certify / Certify 2.0 plaintext** | Lines matching `CA Name :` or `Template Name :` before any JSON structure | `Certify.exe find` or `enum-cas` / `enum-templates` |
| **BloodHound JSON** | Top-level `meta` + `data` keys | ADExplorerSnapshot.py `-m BloodHound` |
| **Raw ACE array** | JSON array with `PrincipalSID` + `RightName` fields | PowerShell `nTSecurityDescriptor` export |
| **NDJSON** | Multiple `{…}` objects, one per line | ADExplorerSnapshot.py `-m Objects` (not fully parsed — convert first) |

---

## Enumeration Guide

Pick **one** of the following methods to generate input for the tool. Certipy JSON gives the widest ESC coverage. Certify plaintext is useful when Python is unavailable on the attack host. BloodHound is best for large environments where you also want visual graph queries.

---

### Method 1 — Certipy (recommended)

**Requires:** Domain credentials, network access to DC and CA. Python on attack host.

```bash
pip install certipy-ad
```

#### Option A: JSON output (best coverage — detects ESC1–16)

```bash
certipy find -u 'user@domain.local' -p 'Password123' -dc-ip 10.0.0.1 -json
# Produces: <timestamp>_Certipy.json
```

```bash
python3 ace_analyzer.py 20240101_120000_Certipy.json
```

#### Option B: Only enumerate vulnerable templates (faster, fewer results)

```bash
certipy find -u 'user@domain.local' -p 'Password123' -dc-ip 10.0.0.1 -json -vulnerable
# Produces smaller JSON with only flagged templates
```

```bash
python3 ace_analyzer.py -q 20240101_120000_Certipy.json
```

#### Option C: BloodHound export (for graph queries + ace_analyzer)

```bash
certipy find -u 'user@domain.local' -p 'Password123' -dc-ip 10.0.0.1 -bloodhound
# Produces: <timestamp>_Certipy.zip  (contains *_certtemplates.json, *_cas.json, etc.)
```

Unzip, then run on the cert-templates file:

```bash
unzip 20240101_120000_Certipy.zip
python3 ace_analyzer.py 20240101_120000_certtemplates.json
```

> **OPSEC note:** Certipy issues LDAP queries to the DC. These are not inherently suspicious but will appear in DC logs. Use `-timeout` and avoid `-vulnerable` scans if stealth matters — they generate fewer LDAP calls.

#### Certipy with alternative authentication

```bash
# Pass-the-hash
certipy find -u 'user@domain.local' -hashes ':ntlmhash' -dc-ip 10.0.0.1 -json

# Kerberos ticket (ccache)
KRB5CCNAME=/tmp/user.ccache certipy find -u 'user@domain.local' -k -dc-ip 10.0.0.1 -json

# LDAPS (port 636)
certipy find -u 'user@domain.local' -p 'Password123' -dc-ip 10.0.0.1 -json -ldap-scheme ldaps
```

---

### Method 2 — Certify (GhostPack, Windows host)

**Requires:** Domain-joined Windows host (or `runas /netonly`), .NET 4.0+. No Python needed on the attack host.

**Certify v1** uses a `find` command. **Certify 2.0** uses `enum-cas` and `enum-templates`.

#### Certify v1 — enumerate all templates

```cmd
Certify.exe find /outfile:certify_all.txt
```

#### Certify v1 — only vulnerable templates (faster)

```cmd
Certify.exe find /vulnerable /outfile:certify_vuln.txt
```

#### Certify v1 — scope to a specific CA or domain

```cmd
Certify.exe find /ca:dc01.domain.local\DOMAIN-CA /outfile:certify_ca.txt
Certify.exe find /domain:child.domain.local /outfile:certify_child.txt
```

Transfer `certify_*.txt` to the analysis host, then:

```bash
python3 ace_analyzer.py certify_all.txt
python3 ace_analyzer.py -q certify_vuln.txt
```

---

### Method 3 — Certify 2.0 (GhostPack, Windows host)

Certify 2.0 splits enumeration into separate commands with expanded output fields (`Schema Version`, `Certificate Issuance Policies`, `RPC Request Encryption`, `Disabled Extensions`, `No Security Extension`).

#### Enumerate Certificate Authorities

```cmd
Certify.exe enum-cas /outfile:certify2_cas.txt
```

#### Enumerate certificate templates

```cmd
Certify.exe enum-templates /outfile:certify2_templates.txt
```

#### Enumerate only vulnerable templates

```cmd
Certify.exe enum-templates /vulnerable /outfile:certify2_vuln.txt
```

#### Enumerate PKI objects (ESC5 investigation)

```cmd
Certify.exe enum-pkiobjects /outfile:certify2_pki.txt
```

Transfer output files to the analysis host, then:

```bash
# Analyse CAs
python3 ace_analyzer.py certify2_cas.txt

# Analyse templates
python3 ace_analyzer.py certify2_templates.txt

# Combined: run both and merge the findings manually
python3 ace_analyzer.py certify2_cas.txt -o report_cas.log
python3 ace_analyzer.py certify2_templates.txt -o report_templates.log
```

> **Note:** Certify 2.0 output files containing only CA blocks or only template blocks are both supported. If a file has both, the parser handles them in a single pass.

---

### Method 4 — ADExplorer + ADExplorerSnapshot.py (offline / no network to CA)

**Requires:** ADExplorer.exe (Sysinternals) on a domain-joined host to take the snapshot. ADExplorerSnapshot.py on the analysis host to convert it.

This is the best approach when you want **no live queries to the CA** after the initial snapshot — the snapshot is taken offline from a single LDAP session to the DC.

#### Step 1 — Take a snapshot (on domain-joined Windows host)

```cmd
# GUI: run ADExplorer.exe, connect to DC, File > Create Snapshot
# CLI:
ADExplorer.exe -snapshot "" snapshot.dat
ADExplorer.exe -snapshot "ldap://dc01.domain.local" snapshot.dat
```

#### Step 2 — Convert to BloodHound JSON (on analysis host)

```bash
pip install impacket
git clone https://github.com/c3c/ADExplorerSnapshot.py
cd ADExplorerSnapshot.py

# BloodHound format — best for ace_analyzer (contains template properties)
python3 ADExplorerSnapshot.py snapshot.dat -o ./output/ -m BloodHound

# Objects/NDJSON format — complete AD dump (not fully parsed by ace_analyzer)
python3 ADExplorerSnapshot.py snapshot.dat -o ./output/ -m Objects
```

#### Step 3 — Run ace_analyzer on the cert-templates file

```bash
# The BloodHound output directory will contain files like:
#   20240101120000_certtemplates.json
#   20240101120000_cas.json
#   20240101120000_users.json   (ignored by ace_analyzer)

python3 ace_analyzer.py output/20240101120000_certtemplates.json
```

> **Tip:** If both `*_certtemplates.json` and `*_cas.json` are available, run the tool on both files separately to get CA-level findings (ESC6, ESC7, ESC8, ESC11, ESC16).

---

### Method 5 — Raw PowerShell ACE Export

**Requires:** PowerShell with AD module on a domain-joined host.

This is the most manual method and gives **ACL data only** — template properties like EKUs and enrollment flags are not exported, so ESC1/2/3/9/15 cannot be detected. Only ESC4 (ACL analysis) is available.

#### Export ACEs for a single template

```powershell
$template = Get-ADObject `
    -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local" `
    -Filter {cn -eq "TemplateName"} `
    -Properties nTSecurityDescriptor

$template.nTSecurityDescriptor.Access | Select-Object `
    @{N="PrincipalSID";  E={$_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value}},
    @{N="PrincipalType"; E={"Unknown"}},
    @{N="RightName";     E={$_.ActiveDirectoryRights.ToString()}},
    @{N="IsInherited";   E={$_.IsInherited}} |
ConvertTo-Json -Depth 3 > TemplateName_aces.json
```

#### Export ACEs for all cert templates

```powershell
$base = "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local"
$templates = Get-ADObject -SearchBase $base `
    -Filter {objectClass -eq "pKICertificateTemplate"} `
    -Properties nTSecurityDescriptor

foreach ($t in $templates) {
    $t.nTSecurityDescriptor.Access | Select-Object `
        @{N="PrincipalSID";  E={$_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value}},
        @{N="PrincipalType"; E={"Unknown"}},
        @{N="RightName";     E={$_.ActiveDirectoryRights.ToString()}},
        @{N="IsInherited";   E={$_.IsInherited}} |
    ConvertTo-Json -Depth 3 > "$($t.Name)_aces.json"
}
```

```bash
python3 ace_analyzer.py TemplateName_aces.json
```

---

## ESC Coverage per Input Method

| ESC | Certipy JSON | Certify text | BloodHound JSON | Raw ACE |
|-----|:---:|:---:|:---:|:---:|
| ESC1 — Enrollee Supplies Subject | ✓ | ✓ | ✓ | — |
| ESC2 — Any Purpose EKU | ✓ | ✓ | ✓ | — |
| ESC3 — Certificate Request Agent | ✓ | ✓ | ✓ | — |
| ESC4 — Vulnerable Template ACL | ✓ | ✓ | ✓ | ✓ |
| ESC5 — Vulnerable PKI Object ACL | note | note | note | — |
| ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2 | ✓ | ✓ | ✓ | — |
| ESC7 — Vulnerable CA ACL | ✓ | ✓ | ✓ | — |
| ESC8 — NTLM Relay to Web Enrollment | ✓ | ✓ | ✓ | — |
| ESC9 — No Security Extension (template) | ✓ | ✓ | ✓ | — |
| ESC10 — Weak Certificate Mapping | partial | partial | — | — |
| ESC11 — CA RPC Without Encryption | ✓ | ✓ | ✓ | — |
| ESC12 — TPM Attestation Bypass | note | note | note | — |
| ESC13 — OID Group Link | ✓ | ✓ | ✓ | — |
| ESC15 — Schema v1 Arbitrary EKU | ✓ | ✓ | ✓ | — |
| ESC16 — CA SID Extension Disabled | ✓ | ✓ | ✓ | — |

**Legend:** ✓ = detected, — = not detectable from this format, note = informational note printed (manual verification required)

> ESC4 in raw ACE format: `WriteProperty` alone is flagged as **HIGH (verify)** rather than CRITICAL because PowerShell ACEs can scope `WriteProperty` to a single attribute. Use Certipy or Certify for confirmation.

---

## ESC Vulnerability Reference

### ESC1 — Subject Alternative Name Specification

**Requirements:** Enrollee Supplies Subject flag enabled · Client Authentication EKU · Low-priv users can enroll · Manager approval disabled

**Impact:** Any low-privileged user can request a certificate for any identity (e.g. Domain Admin), then authenticate with it.

**Attack chain:** Low-priv user → request cert with DA SAN → authenticate as DA → domain compromise

---

### ESC2 — Any Purpose EKU

**Requirements:** Template has Any Purpose EKU (`2.5.29.37.0`) or no EKU at all · Low-priv enrollment · No approval

**Impact:** Certificate can be used as an enrollment agent to request certificates on behalf of other users.

**Attack chain:** User → obtain Any Purpose cert → enroll on behalf of DA → authenticate as DA → domain compromise

---

### ESC3 — Certificate Request Agent

**Requirements:** Certificate Request Agent EKU (`1.3.6.1.4.1.311.20.2.1`) · Low-priv enrollment · No approval

**Impact:** Allows requesting certificates on behalf of other users without explicit per-user authorisation.

**Attack chain:** User → get enrollment agent cert → request DA cert → authenticate as DA → domain compromise

---

### ESC4 — Vulnerable Template ACL

**Requirements:** Low-privileged principal has `GenericAll`, `GenericWrite`, `WriteDacl`, `WriteOwner`, or `WriteProperty` on the template object

**Impact:** Attacker modifies the template (e.g. enables Enrollee Supplies Subject) to create an ESC1 condition.

**Attack chain:** Low-priv user → modify template to enable ESC1 → request cert as DA → domain compromise

---

### ESC5 — Vulnerable PKI Object ACL

**Requirements:** Write access to the CA computer object, `NTAuthCertificates`, or the Enrollment Services container in `CN=Public Key Services`

**Impact:** Allows adding rogue CAs, extracting the CA private key via RBCD/Shadow Credentials, or forging certificates.

> Detection requires checking CA computer object ACLs and PKI container objects not present in standard cert template dumps. Use BloodHound CE or `certipy find -vulnerable` for full analysis.

---

### ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2

**Requirements:** CA has `EDITF_ATTRIBUTESUBJECTALTNAME2` flag set · At least one enrollable template with Client Authentication EKU

**Impact:** Even "safe" templates become vulnerable — any certificate request can include an arbitrary SAN.

**Attack chain:** User → request cert from any template + add DA SAN → authenticate as DA → domain compromise

---

### ESC7 — Vulnerable CA ACL

**Requirements:** Low-priv user has `ManageCA` or `ManageCertificates` on the CA object

**Impact:** `ManageCA` lets the attacker enable `EDITF_ATTRIBUTESUBJECTALTNAME2` (→ ESC6) or add themselves as a Certificate Officer. `ManageCertificates` lets them approve pending requests.

**Attack chain:** User → set ManageCA → enable ESC6 → exploit any template → domain compromise

---

### ESC8 — NTLM Relay to Web Enrollment

**Requirements:** Web enrollment interface (`/certsrv/`) active over HTTP · No Extended Protection for Authentication (EPA) · Ability to coerce authentication (PetitPotam, PrinterBug, etc.)

**Impact:** NTLM relay to the web enrollment endpoint to request a certificate as the relayed account (e.g. a domain controller).

**Attack chain:** Attacker → coerce DC auth → relay to certsrv → request DC cert → DCSync

---

### ESC9 — No Security Extension (Template-Level)

**Requirements:** `CT_FLAG_NO_SECURITY_EXTENSION` (0x80000) set in `msPKI-Enrollment-Flag` · Low-priv enrollment · `StrongCertificateBindingEnforcement` < 2 on DCs · Attacker has `GenericWrite` over target user

**Impact:** Certificates lack the `szOID_NTDS_CA_SECURITY_EXT` SID binding. Attacker changes the target's UPN, enrolls a cert in the target's name, restores the UPN, and authenticates as the target.

---

### ESC10 — Weak Certificate Mapping (Domain-Level)

**Requirements:** `StrongCertificateBindingEnforcement` = 0 (disabled) or = 1 (compatibility) on domain controllers

**Impact:** Unlike ESC9 (per-template), ESC10 affects the entire domain. Certificates without SID binding (from any CA or template) can be used for impersonation.

> Detection requires DC registry values not always present in enumeration output. Use `certipy find` with sufficient privileges for reliable ESC10 detection.

---

### ESC11 — CA RPC Without Encryption

**Requirements:** CA does not have `IF_ENFORCEENCRYPTICERTREQUEST` set · Ability to coerce NTLM auth

**Impact:** NTLM relay to the MS-ICPR RPC interface (`ncacn_ip_tcp`) instead of the HTTP web enrollment endpoint. No HTTPS involved.

**Attack chain:** Attacker → coerce DC auth (PetitPotam) → relay to CA RPC → request DC certificate → DCSync

---

### ESC12 — TPM Attestation Bypass

**Requirements:** CA uses Microsoft Platform Crypto Provider without proper TPM attestation validation

**Impact:** Attacker can request certificates that are supposed to be tied to a TPM-protected key without a TPM.

> Detection requires inspecting CA server configuration. Not detectable from LDAP-based enumeration output.

---

### ESC13 — OID Group Link (Issuance Policy)

**Requirements:** Template has an issuance policy OID · That OID links to an AD security group in `CN=OID,CN=Public Key Services` · Low-priv enrollment · Client Authentication EKU

**Impact:** Certificate holder gains effective membership of the linked group. If the group is privileged, this escalates directly.

**Attack chain:** User → enroll in template with linked policy OID → Windows grants group membership → privilege escalation

> The OID-to-group mapping must be verified manually by reading `CN=OID,CN=Public Key Services,CN=Services,CN=Configuration`.

---

### ESC15 — Schema Version 1 Arbitrary EKU (EKUwu / CVE-2024-49019)

**Requirements:** Template `msPKI-Template-Schema-Version` = 1 · Low-priv enrollment · No approval · No authorized signatures required

**Impact:** Schema v1 templates do not enforce or override the Application Policy (EKU) from the CSR. Attacker submits a CSR with Client Authentication EKU even if the template does not grant it. Patched November 2024 — apply patches.

**Attack chain:** User → craft CSR with Client Auth EKU → enroll in schema v1 template → receive cert with Client Auth → authenticate as any SAN identity

---

### ESC16 — CA-Level SID Extension Disabled

**Requirements:** CA has `szOID_NTDS_CA_SECURITY_EXT` (`1.3.6.1.4.1.311.25.2`) in its `DisableExtensionList` · `StrongCertificateBindingEnforcement` < 2 on DCs

**Impact:** CA-wide version of ESC9. Every certificate from this CA lacks SID binding, making all of them usable for impersonation when DC mapping is weak.

**Attack chain:** Same as ESC9, but no specific template is required — any certificate from this CA is affected.

---

## Format Reference

### Certipy JSON structure

```json
{
  "Certificate Authorities": {
    "0": {
      "CA Name": "CONTOSO-CA",
      "DNS Name": "dc.contoso.local",
      "Web Enrollment": {"HTTP": false, "HTTPS": false, "Channel Binding": false},
      "User Specified SAN": false,
      "Enforce Encryption for Requests": true,
      "No Security Extension": false,
      "Permissions": {
        "Owner": "CONTOSO.LOCAL\\Administrators",
        "Access Rights": {
          "ManageCa":            ["CONTOSO.LOCAL\\Administrators"],
          "ManageCertificates":  ["CONTOSO.LOCAL\\Administrators"],
          "Enroll":              ["CONTOSO.LOCAL\\Authenticated Users"]
        }
      }
    }
  },
  "Certificate Templates": {
    "0": {
      "Template Name": "VulnerableTemplate",
      "Enabled": true,
      "Client Authentication": true,
      "Enrollee Supplies Subject": true,
      "Requires Manager Approval": false,
      "Authorized Signatures Required": 0,
      "Schema Version": 1,
      "No Security Extension": false,
      "Enrollment Flag": ["AutoEnrollment"],
      "Certificate Name Flag": ["EnrolleeSuppliesSubject"],
      "Extended Key Usage": ["Client Authentication"],
      "Any Purpose": false,
      "Issuance Policies": [],
      "Permissions": {
        "Enrollment Permissions": {
          "Enrollment Rights":   ["CONTOSO.LOCAL\\Domain Users"],
          "All Extended Rights": ["CONTOSO.LOCAL\\Authenticated Users"]
        },
        "Object Control Permissions": {
          "Owner":                   "CONTOSO.LOCAL\\Enterprise Admins",
          "Write Dacl Principals":   ["CONTOSO.LOCAL\\Domain Users"],
          "Write Owner Principals":  [],
          "Write Property Principals": []
        }
      },
      "[!] Vulnerabilities": {
        "ESC1": "Enrollee supplies subject and template allows client authentication"
      }
    }
  }
}
```

> Certipy v5.x emits `"Enrollment Flag"` and `"Certificate Name Flag"` as **integer arrays** (`[32, 524288]`) rather than string arrays. Both are handled automatically.

---

### Certify / Certify 2.0 plaintext structure

```
    CA Name                               : CONTOSO\CONTOSO-CA
    DNS Name                              : dc.contoso.local
    Web Enrollment                        : Enabled (HTTP)
    User Specified SAN                    : Disabled
    Enforce Encryption for Requests       : Disabled
    Permissions
      ManageCa                            : CONTOSO.LOCAL\Domain Admins   S-1-5-21-111-222-333-512
      Enrollment Rights                   : CONTOSO.LOCAL\Authenticated Users  S-1-5-11
    [!] Vulnerabilities
      ESC11                               : RPC endpoint does not enforce encryption

    Template Name                         : VulnerableTemplate
    Enabled                               : True
    Client Authentication                 : True
    Enrollee Supplies Subject             : True
    Certificate Name Flag                 : EnrolleeSuppliesSubject
    Enrollment Flag                       : AutoEnrollment
    Schema Version                        : 1
    Extended Key Usage                    : Client Authentication
    Requires Manager Approval             : False
    Authorized Signatures Required        : 0
    Certificate Issuance Policies         : 1.3.6.1.4.1.311.21.8.12345
    Permissions
      Enrollment Permissions
        Enrollment Rights                 : NT AUTHORITY\Authenticated Users  S-1-5-11
      Object Control Permissions
        Owner                             : CONTOSO.LOCAL\Enterprise Admins   S-1-5-21-111-222-333-519
        WriteDacl Principals              : NT AUTHORITY\Authenticated Users  S-1-5-11
    [!] Vulnerabilities
      ESC1                                : Enrollee supplies subject, client auth EKU, low-priv enrollment
      ESC4                                : Authenticated Users has dangerous permissions
```

> Certify 2.0 uses `enum-cas` / `enum-templates` instead of `find`. The output format is identical — the tool detects both.

---

### BloodHound JSON structure

```json
{
  "meta": {"type": "certtemplates", "count": 1, "version": 5},
  "data": [
    {
      "Properties": {
        "name": "VulnerableTemplate@CONTOSO.LOCAL",
        "enabled": true,
        "enrolleesuppliessubject": true,
        "clientauthentication": true,
        "requiresmanagerapproval": false,
        "authorizedsignatures": 0,
        "schemaversion": 1,
        "nosecurityextension": false,
        "ekus": ["1.3.6.1.5.5.7.3.2"],
        "type": "Certificate Template"
      },
      "Aces": [
        {"PrincipalSID": "S-1-5-11",             "PrincipalType": "Group", "RightName": "Enroll"},
        {"PrincipalSID": "S-1-5-21-111-222-333-513", "PrincipalType": "Group", "RightName": "Enroll"},
        {"PrincipalSID": "S-1-5-11",             "PrincipalType": "Group", "RightName": "WriteDacl"}
      ]
    }
  ]
}
```

---

### Raw ACE array structure

```json
[
  {
    "PrincipalSID":  "S-1-5-21-111-222-333-513",
    "PrincipalType": "Group",
    "RightName":     "Enroll",
    "IsInherited":   false
  },
  {
    "PrincipalSID":  "S-1-5-11",
    "PrincipalType": "Group",
    "RightName":     "WriteProperty",
    "IsInherited":   false
  }
]
```

> Raw ACE format does not contain template properties. Only ESC4 (ACL analysis) is detectable.

---

## Troubleshooting

| Problem | Cause | Fix |
|---------|-------|-----|
| `No valid ACE data found` | Unsupported or malformed file | Validate with `jq . file.json`; check it has `PrincipalSID` and `RightName` fields |
| `BloodHound format but no templates` | File is for users/computers, not cert templates | Use the `*_certtemplates.json` file from the ADExplorerSnapshot.py output |
| No findings on any template | Templates are properly secured | Use `--show-all` to print all templates and verify data was parsed |
| Certify text: no templates parsed | File has unusual indentation or header format | Open the file and confirm `Template Name   :` lines are present |
| False-positive ESC4 (raw format) | `WriteProperty` may be scoped to one attribute | Verify with `certipy find` or BloodHound — the tool labels these as HIGH (verify) |
| ESC10 not detected | DC registry values not in enumeration output | Run `certipy find` with elevated privileges or check DC registry manually |

---

## Performance

| Format | Typical file size | Parse time | Notes |
|--------|------------------|------------|-------|
| Certipy JSON | 50 KB – 5 MB | < 1 s | Recommended |
| Certify plaintext | 10 KB – 1 MB | < 1 s | |
| BloodHound JSON | 10 KB – 5 MB | < 1 s | |
| Raw ACE array | 1 KB – 100 KB | < 1 s | ACL only — limited ESC coverage |
| NDJSON | 100 MB – 5 GB | N/A | Not parsed — convert to BloodHound format first |

---

## Resources

- [Certified Pre-Owned — SpecterOps Whitepaper](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [Certipy (ly4k)](https://github.com/ly4k/Certipy)
- [Certipy Wiki — Privilege Escalation](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)
- [Certify (GhostPack)](https://github.com/GhostPack/Certify)
- [Certify 2.0 Release — SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [ADExplorerSnapshot.py](https://github.com/c3c/ADExplorerSnapshot.py)
- [BloodHound CE](https://github.com/SpecterOps/BloodHound)
- [ESC15 / EKUwu — TrustedSec](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [ESC16 — SpecterOps Ghostpack Docs](https://docs.specterops.io/ghostpack-docs/Certify.wik-mdx/esc16-security-extension-disabled-on-certificate-authority)
- [Microsoft AD CS Documentation](https://docs.microsoft.com/en-us/windows-server/identity/ad-cs/)
