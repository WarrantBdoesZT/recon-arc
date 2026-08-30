"""
DNS Enumeration Module for StrikeARC.

Provides passive DNS enumeration capabilities:
  - Zone transfer (AXFR) attempts
  - Standard DNS record enumeration (A, AAAA, MX, NS, TXT, SRV, CNAME, SOA, PTR)
  - Reverse DNS sweep across a /24 subnet
  - Subdomain brute-forcing from a wordlist
  - DNS recursion (open resolver) detection
  - Active Directory SRV record enumeration

This module performs enumeration only — it does NOT execute exploits.
"""

import re
from typing import Dict, List, Optional

from utils import run_command, swallow


# ---------------------------------------------------------------------------
# Default wordlists
# ---------------------------------------------------------------------------

# Common subdomains used when no external wordlist is supplied.
DEFAULT_SUBDOMAIN_WORDLIST: List[str] = [
    "www", "mail", "ftp", "admin", "dev", "test", "api", "vpn", "portal",
    "intranet", "owa", "autodiscover", "cpanel", "git", "jenkins", "grafana",
    "kibana", "prometheus", "staging", "prod", "beta", "demo", "stage",
    "internal", "secure", "remote", "support", "helpdesk", "wiki", "docs",
    "blog", "shop", "app", "m", "mobile", "ns1", "ns2", "dns", "smtp",
    "imap", "pop", "pop3", "webmail", "exchange", "sso", "auth", "ldap",
    "directory", "ad", "dc", "file", "files", "storage", "backup", "db",
    "database", "sql", "mysql", "postgres", "redis", "elastic", "search",
    "monitor", "status", "metrics", "log", "logs", "siem", "ids", "ips",
    "proxy", "firewall", "gateway", "router", "switch", "cache", "cdn",
    "assets", "static", "media", "images", "img", "video", "cdn2",
]

# Common Active Directory / service SRV record prefixes to probe.
DEFAULT_SRV_PREFIXES: List[str] = [
    "_ldap._tcp",
    "_ldap._tcp.Default-First-Site-Name._sites",
    "_kerberos._tcp",
    "_kerberos._tcp.Default-First-Site-Name._sites",
    "_kpasswd._tcp",
    "_gc._tcp",
    "_gc._tcp.Default-First-Site-Name._sites",
    "_sip._tcp",
    "_sipinternal._tcp",
    "_sip._tls",
    "_sips._tcp",
    "_imap._tcp",
    "_imaps._tcp",
    "_submission._tcp",
    "_pop3._tcp",
    "_pop3s._tcp",
    "_caldav._tcp",
    "_caldavs._tcp",
    "_carddav._tcp",
    "_carddavs._tcp",
    "_xmpp-server._tcp",
    "_xmpp-client._tcp",
    "_h323cs._tcp",
    "_h323ls._tcp",
    "_ntp._udp",
    "_vlmcs._tcp",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_dig_answer_section(stdout: str) -> List[str]:
    """
    Extract the ANSWER SECTION lines from raw dig output.

    Returns a list of record lines (without the leading tab) for lines that
    look like DNS answers. dig prints answer records indented with a tab and
    they typically contain whitespace-separated fields ending in a type token
    such as A, CNAME, MX, etc.
    """
    if not stdout:
        return []

    records: List[str] = []
    in_answer = False
    for line in stdout.splitlines():
        stripped = line.strip()

        # Section markers are printed on their own line inside the ;; comments.
        if ";; ANSWER SECTION:" in line:
            in_answer = True
            continue
        if line.startswith(";;") and "SECTION:" in line:
            # Entering a different (non-answer) section
            if "ANSWER" not in line:
                in_answer = False
            continue

        if in_answer and stripped and not stripped.startswith(";"):
            records.append(stripped)
    return records


def _empty_result(default) -> object:
    """Return an empty container matching the requested default type."""
    return default


# ---------------------------------------------------------------------------
# 1. Zone transfer
# ---------------------------------------------------------------------------

def zone_transfer(target_ip: str, domain: str) -> dict:
    """
    Attempt an AXFR zone transfer against `target_ip` for `domain`.

    Runs:  dig @{target_ip} {domain} AXFR

    A successful zone transfer returns the full zone contents; we parse out
    each record line. Returns a dict shaped like:

        {
            "success": bool,
            "domain": str,
            "records": [ {name, ttl, class, type, value}, ... ],
            "raw": str,            # full dig stdout (truncated to a sane size)
            "error": Optional[str]
        }

    Returns an empty/error dict on failure or timeout.
    """
    print(f"    [+] DNS: Attempting AXFR zone transfer on {domain} via {target_ip}")
    result: Dict = {
        "success": False,
        "domain": domain,
        "records": [],
        "raw": "",
        "error": None,
    }

    if not target_ip or not domain:
        result["error"] = "target_ip and domain are required"
        return result

    cmd = f"dig @{target_ip} {domain} AXFR"
    try:
        proc = run_command(cmd, timeout=30)
    except Exception as exc:  # pragma: no cover - defensive
        result["error"] = f"exception running dig: {exc}"
        print(f"    [+] DNS: zone transfer failed: {exc}")
        return result

    stdout = proc.get("stdout", "") or ""
    stderr = proc.get("stderr", "") or ""
    returncode = proc.get("returncode", -1)

    raw = stdout.strip()
    result["raw"] = raw[:20000]  # keep output bounded

    # dig returns 0 even when the transfer fails; detect success heuristically.
    transfer_failed_markers = (
        "Transfer failed",
        "connection refused",
        "timed out",
        "no servers could be reached",
        "; Transfer failed",
        "XFR size: 0 records",
    )

    has_records = False
    for line in raw.splitlines():
        if line and not line.startswith(";") and "\t" in line:
            # A real record line in AXFR output contains tab-separated fields.
            parts = [p for p in line.split() if p]
            if len(parts) >= 5 and parts[-2] in {
                "A", "AAAA", "MX", "NS", "TXT", "SRV", "CNAME",
                "SOA", "PTR", "CAA", "DNSKEY", "RRSIG", "NSEC", "AXFR",
            }:
                has_records = True
                break

    failed = any(marker.lower() in raw.lower() for marker in transfer_failed_markers)

    if has_records and not failed:
        result["success"] = True
        for line in raw.splitlines():
            if not line or line.startswith(";"):
                continue
            parts = [p for p in line.split() if p]
            if len(parts) < 5:
                continue
            # Expected layout: <name> <ttl> <class> <type> <value...>
            # Some lines may omit ttl or class; be defensive.
            try:
                ttl_idx = next(i for i, p in enumerate(parts) if p.isdigit())
            except StopIteration:
                ttl_idx = 1
            name = parts[0]
            ttl = parts[ttl_idx] if ttl_idx < len(parts) else ""
            rec_class = parts[ttl_idx + 1] if ttl_idx + 1 < len(parts) else ""
            rtype = parts[ttl_idx + 2] if ttl_idx + 2 < len(parts) else ""
            value = " ".join(parts[ttl_idx + 3:]) if ttl_idx + 3 < len(parts) else ""
            result["records"].append({
                "name": name,
                "ttl": ttl,
                "class": rec_class,
                "type": rtype,
                "value": value,
            })
        print(f"    [+] DNS: zone transfer succeeded — {len(result['records'])} records retrieved")
    else:
        reason = stderr.strip() or raw or "transfer failed or no records"
        # Keep the reason short for readability.
        reason = reason.splitlines()[0] if reason else "transfer failed or no records"
        result["error"] = reason[:500]
        print(f"    [+] DNS: zone transfer failed (rc={returncode}): {reason[:120]}")

    return result


# ---------------------------------------------------------------------------
# 2. Standard DNS record enumeration
# ---------------------------------------------------------------------------

def enum_dns_records(target_ip: str, domain: str) -> dict:
    """
    Query standard DNS record types for `domain` against `target_ip`.

    Probes A, AAAA, MX, NS, TXT, SRV, CNAME, SOA, and PTR in turn using:
        dig @{target_ip} {domain} TYPE

    Returns a dict keyed by record type, each value a list of parsed answer
    strings (the value portion of each record). Example:

        {
            "A": ["10.0.0.5", "10.0.0.6"],
            "MX": ["10 mail.example.com."],
            "NS": ["ns1.example.com."],
            ...
        }

    Returns an empty dict on hard failure; missing types map to empty lists.
    """
    print(f"    [+] DNS: enumerating DNS records for {domain} via {target_ip}")

    if not target_ip or not domain:
        print("    [+] DNS: enum_dns_records — target_ip and domain are required")
        return {}

    record_types = ["A", "AAAA", "MX", "NS", "TXT", "SRV", "CNAME", "SOA", "PTR"]
    results: Dict[str, List[str]] = {rt: [] for rt in record_types}

    for rtype in record_types:
        cmd = f"dig @{target_ip} {domain} {rtype}"
        try:
            proc = run_command(cmd, timeout=15)
        except Exception as exc:
            print(f"    [+] DNS: {rtype} query failed: {exc}")
            continue

        stdout = proc.get("stdout", "") or ""
        answer_lines = _parse_dig_answer_section(stdout)

        for line in answer_lines:
            parts = line.split()
            if len(parts) < 5:
                continue
            # Layout: name ttl class type value...
            # Find the type token to slice out the value robustly.
            try:
                type_idx = next(
                    i for i, p in enumerate(parts)
                    if p.upper() in record_types or p.upper() in {"CAA", "DNSKEY"}
                )
            except StopIteration:
                # Fallback: assume standard layout.
                if len(parts) >= 5 and parts[-2].upper() == rtype:
                    value = " ".join(parts[-1:])
                else:
                    continue
            else:
                if parts[type_idx].upper() != rtype:
                    # Line is a different type (e.g. CNAME returned in an A query).
                    continue
                value = " ".join(parts[type_idx + 1:]).strip()
            if value:
                results[rtype].append(value)

        count = len(results[rtype])
        if count:
            print(f"    [+] DNS: {rtype:6s} -> {count} record(s)")

    return results


# ---------------------------------------------------------------------------
# 3. Reverse DNS sweep
# ---------------------------------------------------------------------------

def reverse_dns_sweep(subnet: str) -> List[dict]:
    """
    Perform a reverse DNS sweep across a /24 subnet.

    `subnet` should be the first three octets, e.g. "192.168.1" or
    "192.168.1.0/24". For each host (1..254) it runs `dig -x {ip}` and records
    any PTR hostname resolved.

    Returns a list of dicts: [{"ip": str, "hostname": str}, ...] for hosts that
    resolved a name. Returns an empty list on failure.
    """
    # Normalize the subnet prefix.
    prefix = subnet.strip()
    if prefix.endswith("/24"):
        prefix = prefix[:-3]
    if prefix.endswith(".0"):
        prefix = prefix[:-2]
    # Validate we have three octets.
    octets = prefix.split(".")
    if len(octets) != 3 or not all(o.isdigit() for o in octets):
        print(f"    [+] DNS: reverse_dns_sweep — invalid subnet '{subnet}' (expected x.y.z or x.y.z.0/24)")
        return []

    print(f"    [+] DNS: reverse DNS sweep across {prefix}.0/24 (1-254)")

    found: List[Dict[str, str]] = []

    for host in range(1, 255):
        ip = f"{prefix}.{host}"
        cmd = f"dig -x {ip} +short"
        try:
            proc = run_command(cmd, timeout=10)
        except Exception as exc:
            print(f"    [+] DNS: reverse lookup {ip} failed: {exc}")
            continue

        stdout = (proc.get("stdout", "") or "").strip()
        # `dig +short` prints the PTR target (or nothing if NXDOMAIN).
        if stdout:
            # Take the first non-empty line and strip trailing dot.
            hostname = stdout.splitlines()[0].strip().rstrip(".")
            if hostname:
                found.append({"ip": ip, "hostname": hostname})
                print(f"    [+] DNS: {ip:15s} -> {hostname}")

    print(f"    [+] DNS: reverse sweep complete — {len(found)} host(s) resolved")
    return found


# ---------------------------------------------------------------------------
# 4. Subdomain brute-force
# ---------------------------------------------------------------------------

# v10: real subdomain wordlists — SecLists if installed, builtin fallback
_SECLISTS_DNS_DIRS = [
    "/usr/share/seclists/Discovery/DNS/fierce-hostlist.txt",     # 2280
    "/usr/share/seclists/Discovery/DNS/deepmagic.com-prefixes-top500.txt",  # 500
]


def _load_subdomain_wordlist() -> List[str]:
    """Union of SecLists DNS wordlists + builtin. Deduped, order-preserving."""
    seen = set()
    words: List[str] = []
    for path in _SECLISTS_DNS_DIRS:
        try:
            with open(path) as f:
                for line in f:
                    w = line.strip().lower()
                    if w and w not in seen:
                        seen.add(w)
                        words.append(w)
        except FileNotFoundError:
            continue
    for w in DEFAULT_SUBDOMAIN_WORDLIST:
        if w not in seen:
            seen.add(w)
            words.append(w)
    return words


def subdomain_bruteforce(
    target_ip: str,
    domain: str,
    wordlist: Optional[List[str]] = None,
) -> List[str]:
    """
    Brute-force subdomains for `domain` using a wordlist.

    For each candidate word `w`, runs `dig @{target_ip} {w}.{domain}` and
    records the subdomain if it resolves to an A/AAAA/CNAME record.

    Args:
        target_ip: DNS server to query.
        domain: Base domain, e.g. "example.com".
        wordlist: Iterable of subdomain candidates. If None or empty, the
            built-in DEFAULT_SUBDOMAIN_WORDLIST is used.

    Returns a sorted list of discovered subdomains (FQDNs). Empty list on
    failure.
    """
    if wordlist is None or len(wordlist) == 0:
        wordlist = _load_subdomain_wordlist()

    if not target_ip or not domain:
        print("    [+] DNS: subdomain_bruteforce — target_ip and domain are required")
        return []

    # v10: session-level dedup — three call sites (cert-domain, mail-domain,
    # DNS-service) can request the same domain; brute each (ip, domain) once
    _key = f"subdone:{target_ip}:{domain.lower()}"
    if _key in globals().get("_SUBDOMAIN_BRUTED", set()):
        print(f"    [+] DNS: subdomain brute already done for {domain} via {target_ip} — skipping")
        return []
    globals().setdefault("_SUBDOMAIN_BRUTED", set()).add(_key)

    print(f"    [+] DNS: brute-forcing {len(wordlist)} subdomains for {domain} via {target_ip}")

    discovered: List[str] = []

    def _try_subdomain(word: str) -> Optional[str]:
        """Resolve a single subdomain candidate."""
        word = str(word).strip().lower()
        if not word:
            return None
        fqdn = f"{word}.{domain}"
        cmd = f"dig @{target_ip} {fqdn} +short +time=3 +tries=1"
        try:
            proc = run_command(cmd, timeout=5)
            stdout = (proc.get("stdout", "") or "").strip()
            # Filter out DNS error messages (timeouts, SERVFAIL, etc.)
            if stdout and not any(
                err in stdout.lower() for err in [
                    "timed out", "communications error", "connection refused",
                    "no servers", "server can't find", "not found",
                ]
            ):
                # Validate it looks like an IP or CNAME
                first = stdout.splitlines()[0].strip()
                if re.match(r"^\d+\.\d+\.\d+\.\d+$", first) or "." in first:
                    return f"{fqdn} -> {first}"
        except Exception as e:
            swallow(__name__ + ":408", e)
        return None

    # Parallel subdomain resolution with thread pool
    # v10: SecLists wordlist is ~2.8k entries — need more workers + longer
    # window (old 15/60s truncated the run and silently dropped candidates)
    from concurrent.futures import ThreadPoolExecutor, as_completed
    est = max(60, min(300, len(wordlist) // 20))
    pool = ThreadPoolExecutor(max_workers=30)
    try:
        futures = {pool.submit(_try_subdomain, w): w for w in wordlist}
        for future in as_completed(futures, timeout=est):
            try:
                result = future.result(timeout=5)
                if result:
                    discovered.append(result)
                    print(f"    [+] DNS: FOUND {result}")
            except Exception as e:
                swallow(__name__ + ":423", e)
    except Exception:
        pass  # Timeout — cancel the rest instead of grinding through them
    finally:
        pool.shutdown(wait=False, cancel_futures=True)

    print(f"    [+] DNS: subdomain brute-force complete — {len(discovered)} found")
    return sorted(set(discovered))


# ---------------------------------------------------------------------------
# 5. DNS recursion check (open resolver)
# ---------------------------------------------------------------------------


def resolve_and_promote(
    discovered: List[str],
    dns_server: str,
    known_ips: Optional[set] = None,
) -> List[dict]:
    """v10: turn 'sub.domain -> 10.x.x.x' brute results into new scan targets.

    Parses the 'fqdn -> ip' strings from subdomain_bruteforce, keeps only IPs
    NOT already in scope, and returns [{'ip':..., 'via': 'sub.domain'}] entries
    ready for state['hosts'] promotion.
    """
    import ipaddress
    known = known_ips or set()
    out = []
    seen = set()
    for entry in discovered or []:
        if "->" not in entry:
            continue
        fqdn, _, ip = entry.rpartition("->")
        fqdn = fqdn.strip()
        ip = ip.strip()
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        # v10.1: lab DNS often answers loopback (vhosts on the box itself).
        # Promote ONLY private-range IPs — never loopback/link-local/multicast,
        # never public (out-of-scope) addresses.
        if not addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast:
            continue
        if ip in known or ip in seen:
            continue
        seen.add(ip)
        out.append({"ip": ip, "via": fqdn})
    return out

def check_dns_recursion(target_ip: str) -> bool:
    """
    Test whether `target_ip` allows recursive DNS queries (an open resolver).

    Runs a query for a well-known external name through the server:
        dig @{target_ip} google.com A

    If the server returns an answer section (rather than a REFUSED/SERVFAIL
    status or no answer), recursion is enabled and the resolver is "open".

    Returns True if recursion is permitted, False otherwise (including on
    failure/timeout).
    """
    print(f"    [+] DNS: checking recursion on {target_ip}")

    if not target_ip:
        print("    [+] DNS: check_dns_recursion — target_ip is required")
        return False

    # Query a name the server is unlikely to have cached/authoritative for.
    probe = "google.com"
    cmd = f"dig @{target_ip} {probe} A"
    try:
        proc = run_command(cmd, timeout=15)
    except Exception as exc:
        print(f"    [+] DNS: recursion check failed: {exc}")
        return False

    stdout = proc.get("stdout", "") or ""

    # Recursion indicated by "ra" (recursion available) flag in the response.
    recursion_available = re.search(r"\bra\b", stdout) is not None

    # Also confirm an ANSWER SECTION with at least one record exists.
    answer_lines = _parse_dig_answer_section(stdout)
    has_answer = len(answer_lines) > 0

    # A REFUSED status means recursion was denied.
    refused = "status: REFUSED" in stdout

    if recursion_available and has_answer and not refused:
        print(f"    [+] DNS: {target_ip} allows recursion (open resolver)")
        return True

    print(f"    [+] DNS: {target_ip} does NOT allow recursion")
    return False


# ---------------------------------------------------------------------------
# 6. SRV record enumeration (Active Directory awareness)
# ---------------------------------------------------------------------------

def enum_srv_records(
    target_ip: str,
    domain: str,
    prefixes: Optional[List[str]] = None,
) -> List[dict]:
    """
    Enumerate common SRV records (Active Directory / SIP / etc.) for `domain`.

    Probes well-known SRV prefixes (see DEFAULT_SRV_PREFIXES) using:
        dig @{target_ip} {prefix}.{domain} SRV

    Returns a list of dicts, one per resolved SRV record:

        {
            "query": "_ldap._tcp.example.com",
            "priority": "100",
            "weight": "389",
            "port": "389",
            "target": "dc01.example.com.",
        }

    Note: the field naming above follows the SRV layout
    priority weight port target; values are kept as strings from dig output.

    Returns an empty list on failure.
    """
    if prefixes is None or len(prefixes) == 0:
        prefixes = DEFAULT_SRV_PREFIXES

    if not target_ip or not domain:
        print("    [+] DNS: enum_srv_records — target_ip and domain are required")
        return []

    print(f"    [+] DNS: enumerating {len(prefixes)} SRV records for {domain} via {target_ip}")

    found: List[Dict[str, str]] = []

    for prefix in prefixes:
        prefix = prefix.strip()
        if not prefix:
            continue
        query = f"{prefix}.{domain}"
        cmd = f"dig @{target_ip} {query} SRV"
        try:
            proc = run_command(cmd, timeout=15)
        except Exception as exc:
            print(f"    [+] DNS: SRV {query} failed: {exc}")
            continue

        stdout = proc.get("stdout", "") or ""
        answer_lines = _parse_dig_answer_section(stdout)

        for line in answer_lines:
            parts = line.split()
            if len(parts) < 5:
                continue
            # Expected layout: name ttl class SRV priority weight port target
            try:
                type_idx = next(i for i, p in enumerate(parts) if p.upper() == "SRV")
            except StopIteration:
                continue
            value_parts = parts[type_idx + 1:]
            if len(value_parts) < 4:
                continue
            priority, weight, port, target = value_parts[0], value_parts[1], value_parts[2], value_parts[3]
            found.append({
                "query": query,
                "priority": priority,
                "weight": weight,
                "port": port,
                "target": target,
            })
            print(f"    [+] DNS: SRV {query} -> {target}:{port}")

    print(f"    [+] DNS: SRV enumeration complete — {len(found)} record(s)")
    return found


# ---------------------------------------------------------------------------
# Module entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Quick manual smoke test against localhost / a sample domain.
    import sys

    if len(sys.argv) < 3:
        print("Usage: python dns_enum.py <dns_server_ip> <domain> [subnet]")
        sys.exit(1)

    server = sys.argv[1]
    dom = sys.argv[2]
    net = sys.argv[3] if len(sys.argv) > 3 else None

    print("=== DNS Records ===")
    print(enum_dns_records(server, dom))

    print("\n=== Zone Transfer ===")
    print(zone_transfer(server, dom))

    print("\n=== Recursion ===")
    print(check_dns_recursion(server))

    print("\n=== SRV Records ===")
    print(enum_srv_records(server, dom))

    print("\n=== Subdomain Brute-force ===")
    print(subdomain_bruteforce(server, dom))

    if net:
        print("\n=== Reverse DNS Sweep ===")
        print(reverse_dns_sweep(net))
