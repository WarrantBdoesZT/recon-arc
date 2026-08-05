"""
ReconARC — Active Directory Enumeration
========================================
AD discovery via LDAP, RPC, and SMB — all unauthenticated/null-session.
NO exploitation (no Kerberoasting, no AS-REP roasting, no DCSync).
"""

import re
from typing import Dict, List, Optional

from utils import run_command


def discover_domain(dc_ip: str) -> Optional[dict]:
    """Discover AD domain info via LDAP null session."""
    # Try anonymous LDAP search
    cmd = (
        f"ldapsearch -x -H ldap://{dc_ip} -s base "
        f"'(objectclass=*)' 2>/dev/null | head -50"
    )
    result = run_command(cmd, timeout=15)
    if not result["stdout"]:
        # Try cracker-style via ldapsearch with empty credentials
        cmd = (
            f"ldapsearch -xt -H ldap://{dc_ip} "
            f"-D '' -w '' -b '' -s sub '(objectclass=domain)' 2>/dev/null"
        )
        result = run_command(cmd, timeout=15)

    domain = {"dc_ip": dc_ip, "name": "", "functional_level": "",
              "users": [], "groups": [], "computers": [], "spns": [],
              "trusts": [], "ca_servers": []}

    text = result.get("stdout", "")

    # Extract domain name from defaultNamingContext
    m = re.search(r"defaultNamingContext:\s*(\S+)", text)
    if m:
        nc = m.group(1)
        # DC=local,DC=zsm -> zsm.local
        parts = nc.split(",")
        dc_parts = [p.split("=")[1] for p in parts if p.startswith("DC=")]
        domain["name"] = ".".join(reversed(dc_parts))

    m = re.search(r"domainControllerFunctionality:\s*(\d+)", text)
    if m:
        levels = {0: "2000", 1: "2003 Interim", 2: "2003", 3: "2008",
                  4: "2008 R2", 5: "2012", 6: "2012 R2", 7: "2016"}
        domain["functional_level"] = levels.get(int(m.group(1)), f"Level {m.group(1)}")

    if not domain["name"]:
        # Try rpcclient null session
        cmd = f"rpcclient -U '' -N {dc_ip} -c 'querydominfo' 2>/dev/null"
        result = run_command(cmd, timeout=10)
        if result["stdout"]:
            # Try to get domain via ldapsearch search
            cmd = (
                f"ldapsearch -x -H ldap://{dc_ip} -b '' -s base "
                f"'(objectclass=*)' 2>/dev/null"
            )
            result = run_command(cmd, timeout=10)
            text = result.get("stdout", "")
            m = re.search(r"defaultNamingContext:\s*(\S+)", text)
            if m:
                nc = m.group(1)
                parts = nc.split(",")
                dc_parts = [p.split("=")[1] for p in parts if p.startswith("DC=")]
                domain["name"] = ".".join(reversed(dc_parts))

    return domain if domain["name"] else None


def enumerate_domain_users(dc_ip: str, domain: str = "") -> List[str]:
    """Enumerate domain users via LDAP anonymous / rpcclient null session."""
    users = []

    # Method 1: LDAP anonymous
    if domain:
        base_dn = ",".join(f"DC={p}" for p in domain.split(".")[::-1])
        cmd = (
            f"ldapsearch -x -H ldap://{dc_ip} -b '{base_dn}' "
            f"'(&(objectClass=user)(objectCategory=person))' sAMAccountName 2>/dev/null "
            f"| grep 'sAMAccountName:' | awk '{{print $2}}'"
        )
        result = run_command(cmd, timeout=30)
        if result["stdout"]:
            users = [u.strip() for u in result["stdout"].split("\n") if u.strip()]

    # Method 2: rpcclient null session
    if not users:
        cmd = f"rpcclient -U '' -N {dc_ip} -c 'enumdomusers' 2>/dev/null"
        result = run_command(cmd, timeout=15)
        if result["stdout"]:
            for line in result["stdout"].split("\n"):
                parts = line.split("[")
                if len(parts) >= 2:
                    username = parts[1].rstrip("]")
                    if username:
                        users.append(username)

    # Method 3: CrackMapExec (if available)
    if not users:
        cmd = f"crackmapexec smb {dc_ip} -u '' -p '' --users 2>/dev/null"
        result = run_command(cmd, timeout=20)
        if result["stdout"]:
            for line in result["stdout"].split("\n"):
                if "\\" in line and "SMB" in line:
                    parts = line.split()
                    for p in parts:
                        if "\\" in p:
                            users.append(p.split("\\")[-1])

    return sorted(set(users))


def enumerate_domain_groups(dc_ip: str, domain: str = "") -> List[str]:
    """Enumerate domain groups."""
    groups = []

    if domain:
        base_dn = ",".join(f"DC={p}" for p in domain.split(".")[::-1])
        cmd = (
            f"ldapsearch -x -H ldap://{dc_ip} -b '{base_dn}' "
            f"'(objectClass=group)' cn 2>/dev/null "
            f"| grep '^cn:' | awk '{{print $2}}'"
        )
        result = run_command(cmd, timeout=20)
        if result["stdout"]:
            groups = [g.strip() for g in result["stdout"].split("\n") if g.strip()]

    if not groups:
        cmd = f"rpcclient -U '' -N {dc_ip} -c 'enumdomgroups' 2>/dev/null"
        result = run_command(cmd, timeout=15)
        if result["stdout"]:
            for line in result["stdout"].split("\n"):
                parts = line.split("[")
                if len(parts) >= 2:
                    groups.append(parts[1].rstrip("]"))

    return sorted(set(groups))


def enumerate_computers(dc_ip: str, domain: str = "") -> List[str]:
    """Enumerate domain computers."""
    computers = []

    if domain:
        base_dn = ",".join(f"DC={p}" for p in domain.split(".")[::-1])
        cmd = (
            f"ldapsearch -x -H ldap://{dc_ip} -b '{base_dn}' "
            f"'(objectClass=computer)' cn operatingSystem 2>/dev/null "
            f"| grep -E '^(cn|operatingSystem):' "
        )
        result = run_command(cmd, timeout=30)
        if result["stdout"]:
            current_cn = None
            for line in result["stdout"].split("\n"):
                if line.startswith("cn:"):
                    current_cn = line.split(":", 1)[1].strip()
                elif line.startswith("operatingSystem:") and current_cn:
                    os = line.split(":", 1)[1].strip()
                    computers.append(f"{current_cn} ({os})")
                    current_cn = None
                elif current_cn and not line.strip():
                    computers.append(current_cn)
                    current_cn = None

    return sorted(set(computers))


def enumerate_spns(dc_ip: str, domain: str = "") -> List[str]:
    """Enumerate Service Principal Names (for potential Kerberoasting — identified, not executed)."""
    spns = []

    if domain:
        base_dn = ",".join(f"DC={p}" for p in domain.split(".")[::-1])
        cmd = (
            f"ldapsearch -x -H ldap://{dc_ip} -b '{base_dn}' "
            f"'(servicePrincipalName=*)' servicePrincipalName sAMAccountName 2>/dev/null"
        )
        result = run_command(cmd, timeout=30)
        if result["stdout"]:
            current_user = None
            for line in result["stdout"].split("\n"):
                if line.startswith("sAMAccountName:"):
                    current_user = line.split(":", 1)[1].strip()
                elif line.startswith("servicePrincipalName:") and current_user:
                    spn = line.split(":", 1)[1].strip()
                    spns.append(f"{current_user}: {spn}")

    return sorted(set(spns))


def enumerate_adcs(dc_ip: str, domain: str = "") -> List[dict]:
    """Discover ADCS Certificate Authorities and templates."""
    cas = []

    # Check if CA service is accessible
    cmd = (
        f"nmap -p 445 --script smb-os-discovery {dc_ip} -oN - 2>/dev/null"
    )
    result = run_command(cmd, timeout=15)
    if "Windows Server" in result.get("stdout", ""):
        # Try to enumerate CA info via certutil or rpcclient
        cmd = f"rpcclient -U '' -N {dc_ip} -c 'enumprivs' 2>/dev/null"
        result = run_command(cmd, timeout=10)

    # Check for CA via LDAP
    if domain:
        base_dn = ",".join(f"DC={p}" for p in domain.split(".")[::-1])
        # Search for pKIEnrollmentService objects
        cmd = (
            f"ldapsearch -x -H ldap://{dc_ip} -b 'CN=Public Key Services,"
            f"CN=Services,CN=Configuration,{base_dn}' "
            f"'(objectClass=pKIEnrollmentService)' cn dNSHostName 2>/dev/null"
        )
        result = run_command(cmd, timeout=15)
        if result["stdout"]:
            for line in result["stdout"].split("\n"):
                if line.startswith("cn:"):
                    ca_name = line.split(":", 1)[1].strip()
                    cas.append({"name": ca_name, "type": "ADCS CA"})
                    print(f"    [+] ADCS CA found: {ca_name}")
                elif line.startswith("dNSHostName:"):
                    hostname = line.split(":", 1)[1].strip()
                    if cas:
                        cas[-1]["hostname"] = hostname

    return cas


def enumerate_smb_shares(target_ip: str) -> List[dict]:
    """Enumerate SMB shares via null session (read-only)."""
    shares = []

    # List shares via smbclient null session
    cmd = f"smbclient -L '//{target_ip}/' -N 2>/dev/null"
    result = run_command(cmd, timeout=15)

    if result["stdout"]:
        for line in result["stdout"].split("\n"):
            # smbclient share listing format
            m = re.match(r"\s+(\S+)\s+(Disk|IPC|Printer)\s+(.*)", line)
            if m:
                shares.append({
                    "name": m.group(1),
                    "type": m.group(2),
                    "comment": m.group(3).strip(),
                    "accessible": True,
                })

    # Also try rpcclient null session for share enum
    if not shares:
        cmd = f"rpcclient -U '' -N {target_ip} -c 'enumshares' 2>/dev/null"
        result = run_command(cmd, timeout=10)
        if result["stdout"]:
            for line in result["stdout"].split("\n"):
                line = line.strip()
                if line and not line.startswith("num_shares"):
                    shares.append({"name": line.strip('"'), "type": "unknown", "accessible": True})

    return shares


def check_smb_signing(target_ip: str) -> Optional[bool]:
    """Check if SMB signing is required (affects relay attacks)."""
    cmd = (
        f"nmap -p 445 --script smb-security-mode {target_ip} -oN - 2>/dev/null"
    )
    result = run_command(cmd, timeout=15)
    if "signing" in result.get("stdout", "").lower():
        return "not required" in result["stdout"].lower()
    return None


def run_enum4linux(target_ip: str) -> dict:
    """Run enum4linux for comprehensive Windows/Samba enumeration."""
    result = {"output": "", "users": [], "shares": [], "groups": [],
              "password_policy": {}, "os_info": {}}

    cmd = f"enum4linux -a {target_ip} 2>/dev/null"
    out = run_command(cmd, timeout=60)
    text = out.get("stdout", "")
    result["output"] = text[:2000]  # Keep summary

    if not text:
        # Try enum4linux-ng
        cmd = f"enum4linux-ng -A {target_ip} 2>/dev/null"
        out = run_command(cmd, timeout=60)
        text = out.get("stdout", "")
        result["output"] = text[:2000]

    if not text:
        return result

    # Parse users (user:[username] rpc_client.h)
    for m in re.finditer(r"user:\[(\S+)\]", text):
        result["users"].append(m.group(1))

    # Parse share enumeration
    for m in re.finditer(r"\t(\\S+)\s+(Disk|IPC|Printer)", text):
        result["shares"].append({"name": m.group(1), "type": m.group(2)})

    # Parse password policy
    pw_section = re.search(
        r"Password Policy.*?(?=\n\n|\Z)", text, re.DOTALL,
    )
    if pw_section:
        pw_text = pw_section.group(0)
        for m in re.finditer(r"(\w[\w\s]+):\s*(\d+)", pw_text):
            result["password_policy"][m.group(1).strip()] = int(m.group(2))

    # Parse OS info
    os_match = re.search(r"OS:\s*(.+)", text)
    if os_match:
        result["os_info"]["os"] = os_match.group(1).strip()
    os_version = re.search(r"os_version:\s*(.+)", text, re.IGNORECASE)
    if os_version:
        result["os_info"]["version"] = os_version.group(1).strip()

    return result


def get_password_policy(dc_ip: str, domain: str = "") -> Optional[dict]:
    """Get AD password policy via LDAP or rpcclient."""
    policy = {}

    # Method 1: rpcclient
    cmd = f"rpcclient -U '' -N {dc_ip} -c 'getdompwinfo' 2>/dev/null"
    result = run_command(cmd, timeout=15)
    if result["stdout"]:
        for line in result["stdout"].split("\n"):
            if "min_password_length" in line:
                m = re.search(r"(\d+)", line)
                if m:
                    policy["min_length"] = int(m.group(1))
            elif "password_history_length" in line:
                m = re.search(r"(\d+)", line)
                if m:
                    policy["history"] = int(m.group(1))
            elif "maximum_password_age" in line:
                m = re.search(r"(\d+)", line)
                if m:
                    policy["max_age"] = int(m.group(1))
            elif "password_properties" in line:
                policy["complexity"] = "0x00" not in line

    # Method 2: LDAP — search for domainDNS policy attributes
    if domain and not policy:
        base_dn = ",".join(f"DC={p}" for p in domain.split(".")[::-1])
        cmd = (
            f"ldapsearch -x -H ldap://{dc_ip} -b '{base_dn}' "
            f"'(objectClass=domainDNS)' "
            f"minPwdLength minPwdAge maxPwdAge pwdHistoryLength pwdProperties 2>/dev/null"
        )
        result = run_command(cmd, timeout=15)
        if result["stdout"]:
            for line in result["stdout"].split("\n"):
                if "minPwdLength:" in line:
                    m = re.search(r"(\d+)", line)
                    if m:
                        policy["min_length"] = int(m.group(1))
                elif "pwdHistoryLength:" in line:
                    m = re.search(r"(\d+)", line)
                    if m:
                        policy["history"] = int(m.group(1))
                elif "pwdProperties:" in line:
                    m = re.search(r"(\d+)", line)
                    if m:
                        policy["complexity"] = int(m.group(1)) > 0

    return policy if policy else None


def check_gpp_password(target_ip: str, domain: str = "") -> List[dict]:
    """Check for Group Policy Preferences (GPP) passwords in SMB shares (cpassword)."""
    findings = []

    # GPP XML files are typically in SYSVOL
    # \\\\domain\\SYSVOL\\domain\\Policies\\*\\Machine\\Preferences\\Groups\\Groups.xml
    # This is read-only enumeration — we only check if the files exist

    cmd = (
        f"smbclient '//{target_ip}/SYSVOL' -N -c "
        f"'ls; recurse on; ls' 2>/dev/null | grep -i 'groups.xml\\|services.xml'"
    )
    result = run_command(cmd, timeout=20)
    if result["stdout"] and ("Groups.xml" in result["stdout"] or "Services.xml" in result["stdout"]):
        findings.append({
            "type": "gpp_password",
            "detail": "GPP XML files found in SYSVOL — may contain cpassword (AES-encrypted)",
            "severity": "high",
        })

    return findings


def enumerate_smb_share_content(target_ip: str, share_name: str = "IPC$") -> List[str]:
    """List files in accessible SMB shares (read-only)."""
    files = []

    cmd = f"smbclient '//{target_ip}/{share_name}' -N -c 'ls' 2>/dev/null"
    result = run_command(cmd, timeout=15)
    if result["stdout"]:
        for line in result["stdout"].split("\n"):
            m = re.match(r"\s+(\S+)\s+\w+\s+\d+\s+(.+)", line)
            if m:
                files.append(m.group(1))

    return files


def check_webdav(target_ip: str) -> bool:
    """Check if WebDAV is enabled on the target."""
    from utils import http_get

    for port in [80, 443, 8080, 8443]:
        scheme = "https" if port in [443, 8443] else "http"
        url = f"{scheme}://{target_ip}:{port}/"
        resp = http_get(url, timeout=3, allow_redirects=False,
                        headers={"Depth": "0", "Content-Type": "text/xml"})
        if resp and "DAV:" in resp.text or (resp and resp.headers.get("DAV")):
            return True

    return False


def bloodhound_collector(dc_ip: str, domain: str = "", username: str = "", password: str = "") -> bool:
    """Check if BloodHound data can be collected (only if creds available)."""
    # This is enumeration, not exploitation — bloodhound-python just collects LDAP data
    if not domain:
        return False

    if username and password:
        cmd = (
            f"bloodhound-python -u '{username}' -p '{password}' "
            f"-d '{domain}' -dc '{dc_ip}' -c All 2>/dev/null"
        )
        result = run_command(cmd, timeout=120)
        return result.get("returncode") == 0

    return False
