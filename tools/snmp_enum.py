"""
SNMP enumeration module for ReconARC.

Provides passive SNMP enumeration functions to extract system information,
processes, installed software, network interfaces, and users from targets
exposing SNMP (typically UDP 161). All functions handle failures gracefully
and return empty structures on error.

Usage:
    from tools.snmp_enum import (
        snmp_walk,
        snmp_enum_system,
        snmp_enum_processes,
        snmp_enum_software,
        snmp_enum_network,
        snmp_enum_users,
        try_communities,
    )
"""

import re
from typing import Dict, List, Optional

from utils import run_command


def snmp_walk(target_ip: str, community: str = 'public',
              oid: str = '.1.3.6.1') -> str:
    """Run a raw snmpwalk against the target and return stdout.

    Args:
        target_ip: Target host IP or hostname.
        community: SNMP community string (default 'public').
        oid: Root OID to walk (default '.1.3.6.1').

    Returns:
        Raw snmpwalk stdout as a string. Empty string on failure or no output.
    """
    print(f"    [+] SNMP: walking {oid} on {target_ip} (community={community})")
    cmd = f"snmpwalk -v2c -c {community} {target_ip} {oid} 2>/dev/null"
    try:
        result = run_command(cmd, timeout=60)
        if result and result.get('returncode') == 0:
            return result.get('stdout', '') or ''
    except Exception as e:
        print(f"    [+] SNMP: snmp_walk error: {e}")
    return ''


def _walk_oid(target_ip: str, community: str, oid: str) -> List[str]:
    """Helper: walk a specific OID and return non-empty output lines."""
    output = snmp_walk(target_ip, community=community, oid=oid)
    if not output:
        return []
    return [line.strip() for line in output.splitlines() if line.strip()]


def _parse_value(line: str) -> str:
    """Extract the value portion from an snmpwalk output line.

    Handles common formats:
        OID = INTEGER: 42
        OID = STRING: "hostname"
        OID = OID: .1.3.6...
        OID = Hex-STRING: 01 02 03
        OID = Timeticks: (12345) 3:25:45.00
    """
    if '=' not in line:
        return ''
    # Take everything after the first '='
    _, _, raw = line.partition('=')
    raw = raw.strip()
    # Strip leading type prefix: INTEGER:, STRING:, OID:, etc.
    m = re.match(r'^([A-Za-z0-9-]+):\s*(.*)$', raw)
    if m:
        value = m.group(2).strip()
    else:
        value = raw
    # Strip surrounding quotes from STRING values
    if len(value) >= 2 and value.startswith('"') and value.endswith('"'):
        value = value[1:-1]
    return value.strip()


def snmp_enum_system(target_ip: str, community: str = 'public') -> dict:
    """Extract system information via SNMP system OIDs (.1.3.6.1.2.1.1.*).

    Gathers:
        - hostname (sysName, .1.3.6.1.2.1.1.5.0)
        - description (sysDescr, .1.3.6.1.2.1.1.1.0)
        - uptime (sysUpTime, .1.3.6.1.2.1.1.3.0)
        - contact (sysContact, .1.3.6.1.2.1.1.4.0)
        - location (sysLocation, .1.3.6.1.2.1.1.6.0)

    Args:
        target_ip: Target host IP or hostname.
        community: SNMP community string.

    Returns:
        Dict with keys: hostname, description, uptime, contact, location.
        Values are empty strings if unavailable.
    """
    print(f"    [+] SNMP: enumerating system info on {target_ip}")
    sys_info: Dict[str, str] = {
        'hostname': '',
        'description': '',
        'uptime': '',
        'contact': '',
        'location': '',
    }

    oid_map = {
        'description': '.1.3.6.1.2.1.1.1.0',
        'uptime': '.1.3.6.1.2.1.1.3.0',
        'contact': '.1.3.6.1.2.1.1.4.0',
        'hostname': '.1.3.6.1.2.1.1.5.0',
        'location': '.1.3.6.1.2.1.1.6.0',
    }

    try:
        for key, oid in oid_map.items():
            lines = _walk_oid(target_ip, community, oid)
            if lines:
                value = _parse_value(lines[0])
                if value:
                    sys_info[key] = value
                    print(f"    [+] SNMP: {key} = {value}")
    except Exception as e:
        print(f"    [+] SNMP: snmp_enum_system error: {e}")

    if any(sys_info.values()):
        print(f"    [+] SNMP: system info retrieved for {target_ip}")
    else:
        print(f"    [+] SNMP: no system info retrieved for {target_ip}")

    return sys_info


def snmp_enum_processes(target_ip: str, community: str = 'public') -> List[str]:
    """Enumerate running processes via HOST-RESOURCES-MIB hrSWRun.

    OID .1.3.6.1.2.1.25.4.2.1.2 returns process names. This can reveal
    running services, and command-line arguments sometimes expose credentials.

    Interesting process keywords (case-insensitive): sshd, telnet, ftp, smb,
    nmb, snmp, sql, mysql, postgres, oracle, http, nginx, apache, vpn, rdp,
    vnc, docker, passw, key, token, secret, admin.

    Args:
        target_ip: Target host IP or hostname.
        community: SNMP community string.

    Returns:
        List of process-name strings flagged as interesting. Empty list on
        failure.
    """
    print(f"    [+] SNMP: enumerating processes on {target_ip}")
    interesting_keywords = [
        'sshd', 'telnet', 'ftp', 'smb', 'nmb', 'snmp', 'sql', 'mysql',
        'postgres', 'oracle', 'mssql', 'http', 'nginx', 'apache', 'tomcat',
        'vpn', 'openvpn', 'rdp', 'vnc', 'docker', 'kubernetes', 'kubelet',
        'passw', 'pwd', 'key', 'token', 'secret', 'admin', 'root',
        'credential', 'auth', 'ldap', 'redis', 'mongo', 'memcache',
    ]

    interesting: List[str] = []
    try:
        lines = _walk_oid(
            target_ip, community, '.1.3.6.1.2.1.25.4.2.1.2'
        )
        print(f"    [+] SNMP: {len(lines)} processes enumerated")
        lower_keywords = [k.lower() for k in interesting_keywords]
        for line in lines:
            value = _parse_value(line).lower()
            if value and any(kw in value for kw in lower_keywords):
                interesting.append(_parse_value(line))
    except Exception as e:
        print(f"    [+] SNMP: snmp_enum_processes error: {e}")

    if interesting:
        print(f"    [+] SNMP: {len(interesting)} interesting processes found")
    return interesting


def snmp_enum_software(target_ip: str,
                       community: str = 'public') -> List[str]:
    """Enumerate installed software via hrSWInstalledName.

    OID .1.3.6.1.2.1.25.6.3.1.2 returns names of installed software packages.
    Useful for identifying vulnerable or outdated applications.

    Args:
        target_ip: Target host IP or hostname.
        community: SNMP community string.

    Returns:
        List of installed software names. Empty list on failure.
    """
    print(f"    [+] SNMP: enumerating installed software on {target_ip}")
    software: List[str] = []
    try:
        lines = _walk_oid(
            target_ip, community, '.1.3.6.1.2.1.25.6.3.1.2'
        )
        for line in lines:
            value = _parse_value(line)
            if value:
                software.append(value)
        print(f"    [+] SNMP: {len(software)} software packages found")
    except Exception as e:
        print(f"    [+] SNMP: snmp_enum_software error: {e}")
    return software


def snmp_enum_network(target_ip: str,
                      community: str = 'public') -> List[dict]:
    """Enumerate network interfaces and IP addresses via ipAddrTable.

    OID .1.3.6.1.2.1.4.20.1.* returns IP address entries:
        .1 = ipAdEntAddr (IP address)
        .2 = ipAdEntIfIndex (interface index)
        .3 = ipAdEntNetMask (subnet mask)

    Can reveal internal networks, multi-homed hosts, and potential pivot
    points.

    Args:
        target_ip: Target host IP or hostname.
        community: SNMP community string.

    Returns:
        List of dicts, each with keys: ip, ifindex, netmask. Empty list on
        failure.
    """
    print(f"    [+] SNMP: enumerating network interfaces on {target_ip}")
    interfaces: List[dict] = []
    try:
        # Gather addresses, ifindexes, and netmasks separately
        addrs = {}
        for line in _walk_oid(target_ip, community, '.1.3.6.1.2.1.4.20.1.1'):
            value = _parse_value(line)
            if value:
                # OID suffix after .1.3.6.1.2.1.4.20.1.1 is the IP itself
                suffix = line.split('=')[0].strip().split('.')[-4:]
                key = '.'.join(suffix) if len(suffix) == 4 else value
                addrs[key] = {'ip': value, 'ifindex': '', 'netmask': ''}

        if not addrs:
            print(f"    [+] SNMP: no network addresses found")
            return interfaces

        # Interface indexes
        for line in _walk_oid(target_ip, community, '.1.3.6.1.2.1.4.20.1.2'):
            suffix = line.split('=')[0].strip().split('.')[-4:]
            key = '.'.join(suffix) if len(suffix) == 4 else ''
            value = _parse_value(line)
            if key in addrs:
                addrs[key]['ifindex'] = value

        # Netmasks
        for line in _walk_oid(target_ip, community, '.1.3.6.1.2.1.4.20.1.3'):
            suffix = line.split('=')[0].strip().split('.')[-4:]
            key = '.'.join(suffix) if len(suffix) == 4 else ''
            value = _parse_value(line)
            if key in addrs:
                addrs[key]['netmask'] = value

        for entry in addrs.values():
            interfaces.append(entry)
            print(
                f"    [+] SNMP: interface {entry['ifindex']} -> "
                f"{entry['ip']}/{entry['netmask']}"
            )
        print(f"    [+] SNMP: {len(interfaces)} network interfaces found")
    except Exception as e:
        print(f"    [+] SNMP: snmp_enum_network error: {e}")
    return interfaces


def snmp_enum_users(target_ip: str,
                    community: str = 'public') -> List[str]:
    """Enumerate local users via SNMP user-related OIDs.

    Attempts multiple user-enumeration OIDs since support varies by OS and
    SNMP agent:
        - UCD-SNMP-MIB extUserPath / process table (Linux hints)
        - HOST-RESOURCES-MIB hrSWRunPath (service users, indirect)
        - SNMPv2-MIB sysORTable (limited)
        - Net-SNMP prCount / user-related extensions

    Best-effort: many SNMP agents do not expose user lists directly. Falls
    back to extracting usernames from process command lines where possible.

    Args:
        target_ip: Target host IP or hostname.
        community: SNMP community string.

    Returns:
        List of discovered usernames. Empty list on failure.
    """
    print(f"    [+] SNMP: attempting user enumeration on {target_ip}")
    users: List[str] = []
    seen = set()

    # Candidate OIDs that may reveal user information on various agents
    candidate_oids = [
        '.1.3.6.1.4.1.2021.9',      # UCD-SNMP-MIB dskTable (mount info)
        '.1.3.6.1.2.1.25.4.2.1.2',  # hrSWRunName (processes -> infer users)
    ]

    user_pattern = re.compile(
        r'\b([a-zA-Z][a-zA-Z0-9._-]{2,31})\b'
    )

    try:
        # Try process names for user-like tokens
        lines = _walk_oid(target_ip, community, '.1.3.6.1.2.1.25.4.2.1.2')
        for line in lines:
            value = _parse_value(line)
            if value:
                for match in user_pattern.findall(value):
                    low = match.lower()
                    if low not in seen and not low.startswith(('snmp', 'system')):
                        seen.add(low)
                        users.append(match)

        # Also try the UCD-SNMP-MIB for any embedded user strings
        for oid in candidate_oids[:-1]:
            for line in _walk_oid(target_ip, community, oid):
                value = _parse_value(line)
                if value:
                    for match in user_pattern.findall(value):
                        low = match.lower()
                        if low not in seen:
                            seen.add(low)
                            users.append(match)

        print(f"    [+] SNMP: {len(users)} potential users identified")
    except Exception as e:
        print(f"    [+] SNMP: snmp_enum_users error: {e}")
    return users


def try_communities(target_ip: str) -> Optional[str]:
    """Try common SNMP community strings against the target.

    Attempts: public, private, community, cisco, admin, manager, monitor,
    test, guest, default.

    Args:
        target_ip: Target host IP or hostname.

    Returns:
        The first working community string, or None if none succeed.
    """
    print(f"    [+] SNMP: testing common community strings on {target_ip}")
    communities = [
        'public', 'private', 'community', 'cisco', 'admin',
        'manager', 'monitor', 'test', 'guest', 'default',
    ]
    for community in communities:
        print(f"    [+] SNMP: trying community '{community}'")
        cmd = (
            f"snmpwalk -v2c -c {community} {target_ip} "
            f"1.3.6.1.2.1.1.1.0 2>/dev/null"
        )
        try:
            result = run_command(cmd, timeout=15)
            if (
                result
                and result.get('returncode') == 0
                and result.get('stdout', '').strip()
            ):
                print(
                    f"    [+] SNMP: valid community string found: "
                    f"'{community}'"
                )
                return community
        except Exception as e:
            print(f"    [+] SNMP: error testing '{community}': {e}")
            continue

    print(f"    [+] SNMP: no valid community string found for {target_ip}")
    return None
