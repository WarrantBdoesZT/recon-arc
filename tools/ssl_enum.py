"""
StrikeARC — SSL Certificate Enumeration
=======================================
Extract and analyze SSL/TLS certificates for hostnames, organizations,
and security issues. Critical for cross-host correlation.
"""

import socket
import ssl
from typing import Dict, List, Optional
from datetime import datetime


def extract_cert(host: str, port: int = 443, timeout: int = 5) -> Optional[dict]:
    """Connect via SSL socket and extract full certificate information."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert_bin = ssock.getpeercert(binary_form=True)
                if not cert_bin:
                    return None
                cert_dict = ssock.getpeercert()

        # If getpeercert returned empty (CERT_NONE), try parsing from binary
        if not cert_dict:
            return _parse_der_cert(cert_bin, host, port)

        return _format_cert(cert_dict, host, port)
    except socket.timeout:
        return None
    except ConnectionRefusedError:
        return None
    except Exception:
        return None


def _format_cert(cert: dict, host: str, port: int) -> dict:
    """Format ssl module cert dict into our standard structure."""
    def _get_field(name_tuple, field_type):
        """Extract a field from the certificate subject/issuer."""
        for rdn in name_tuple:
            for key, val in rdn:
                if key == field_type:
                    return val
        return ""

    subject = cert.get("subject", ())
    issuer = cert.get("issuer", ())

    result = {
        "host": host,
        "port": port,
        "subject_cn": _get_field(subject, "commonName"),
        "subject_org": _get_field(subject, "organizationName"),
        "subject_ou": _get_field(subject, "organizationalUnitName"),
        "subject_country": _get_field(subject, "countryName"),
        "subject_state": _get_field(subject, "stateOrProvinceName"),
        "subject_locality": _get_field(subject, "localityName"),
        "subject_email": _get_field(subject, "emailAddress"),
        "issuer_cn": _get_field(issuer, "commonName"),
        "issuer_org": _get_field(issuer, "organizationName"),
        "issuer_ou": _get_field(issuer, "organizationalUnitName"),
        "issuer_country": _get_field(issuer, "countryName"),
        "san_list": [],
        "serial_number": str(cert.get("serialNumber", "")),
        "version": cert.get("version", ""),
        "not_before": cert.get("notBefore", ""),
        "not_after": cert.get("notAfter", ""),
        "has_expired": False,
        "is_wildcard": False,
        "is_self_signed": False,
        "signature_algorithm": "",
    }

    # Extract Subject Alternative Names
    san_list = []
    for san_type, san_val in cert.get("subjectAltName", []):
        if san_type == "DNS":
            san_list.append(san_val)
    result["san_list"] = san_list

    # Check wildcard
    cn = result["subject_cn"]
    if cn and cn.startswith("*."):
        result["has_wildcard"] = True

    # Check self-signed
    if (result["subject_cn"] == result["issuer_cn"] and
            result["subject_org"] == result["issuer_org"]):
        result["is_self_signed"] = True

    # Check expiry
    try:
        if cert.get("notAfter"):
            expiry = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
            result["has_expired"] = expiry < datetime.now()
    except (ValueError, TypeError):
        pass

    return result


def _parse_der_cert(cert_bin: bytes, host: str, port: int) -> Optional[dict]:
    """Fallback: parse DER cert when CERT_NONE mode returns empty dict.
    Uses ssl.DER_cert_to_PEM_cert + basic string parsing."""
    try:
        import ssl as _ssl
        pem = _ssl.DER_cert_to_PEM_cert(cert_bin)

        result = {
            "host": host, "port": port,
            "subject_cn": "", "subject_org": "", "subject_ou": "",
            "subject_country": "", "subject_state": "", "subject_locality": "",
            "subject_email": "",
            "issuer_cn": "", "issuer_org": "", "issuer_ou": "",
            "issuer_country": "",
            "san_list": [], "serial_number": "",
            "version": "", "not_before": "", "not_after": "",
            "has_expired": False, "is_wildcard": False,
            "is_self_signed": False, "signature_algorithm": "",
            "raw_pem": pem[:500],  # Keep first 500 chars for debug
        }

        # Try using cryptography library if available
        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            cert_obj = x509.load_der_x509_certificate(cert_bin, default_backend())

            for attr in cert_obj.subject:
                oid_name = attr.oid._name
                if oid_name == "commonName":
                    result["subject_cn"] = attr.value
                elif oid_name == "organizationName":
                    result["subject_org"] = attr.value
                elif oid_name == "organizationalUnitName":
                    result["subject_ou"] = attr.value
                elif oid_name == "countryName":
                    result["subject_country"] = attr.value
                elif oid_name == "emailAddress":
                    result["subject_email"] = attr.value

            for attr in cert_obj.issuer:
                oid_name = attr.oid._name
                if oid_name == "commonName":
                    result["issuer_cn"] = attr.value
                elif oid_name == "organizationName":
                    result["issuer_org"] = attr.value
                elif oid_name == "organizationalUnitName":
                    result["issuer_ou"] = attr.value

            try:
                san_ext = cert_obj.extensions.get_extension_for_class(
                    x509.SubjectAlternativeName
                )
                result["san_list"] = san_ext.value.get_values_for_type(
                    x509.DNSName
                )
            except x509.ExtensionNotFound:
                pass

            result["serial_number"] = str(cert_obj.serial_number)
            result["not_before"] = cert_obj.not_valid_before.isoformat()
            result["not_after"] = cert_obj.not_valid_after.isoformat()
            result["has_expired"] = cert_obj.not_valid_after < datetime.utcnow()
            result["signature_algorithm"] = cert_obj.signature_algorithm_oid._name

            cn = result["subject_cn"]
            if cn and cn.startswith("*"):
                result["has_wildcard"] = True
            if result["subject_cn"] == result["issuer_cn"]:
                result["is_self_signed"] = True

        except ImportError:
            pass  # cryptography not available

        return result
    except Exception:
        return None


def analyze_cert_security(cert_info: dict) -> List[str]:
    """Check for security weaknesses in a certificate."""
    findings = []

    if cert_info.get("is_self_signed"):
        findings.append("Self-signed certificate — may indicate internal PKI or test environment")

    if cert_info.get("has_wildcard"):
        findings.append(f"Wildcard certificate ({cert_info['subject_cn']}) — broad scope")

    if cert_info.get("has_expired"):
        findings.append("Certificate has EXPIRED")

    sig = cert_info.get("signature_algorithm", "").lower()
    if "md5" in sig:
        findings.append("Weak signature algorithm: MD5")
    if "sha1" in sig:
        findings.append("Weak signature algorithm: SHA1")

    # Check for soon-to-expire
    try:
        if cert_info.get("not_after"):
            for fmt in ("%b %d %H:%M:%S %Y %Z", "%Y-%m-%dT%H:%M:%S"):
                try:
                    expiry = datetime.strptime(
                        cert_info["not_after"].split("+")[0].strip(), fmt
                    )
                    days_left = (expiry - datetime.now()).days
                    if 0 < days_left < 30:
                        findings.append(f"Certificate expires in {days_left} days")
                    break
                except ValueError:
                    continue
    except Exception:
        pass

    return findings


def correlate_certs(cert_results: Dict[str, dict]) -> List[str]:
    """Given {host: cert_info}, find shared orgs/issuers/CN patterns."""
    findings = []

    # Group by organization
    org_hosts = {}
    for host, cert in cert_results.items():
        for field in ("subject_org", "issuer_org", "subject_ou"):
            val = cert.get(field, "")
            if val and val.lower() not in ("", "unknown", "none"):
                key = f"{field}={val}"
                org_hosts.setdefault(key, []).append(host)

    for key, hosts in org_hosts.items():
        unique = sorted(set(hosts))
        if len(unique) > 1:
            findings.append(
                f"Shared {key}: hosts {', '.join(unique)} — same organization/infrastructure"
            )

    # Check for CA relationships
    ca_hosts = {}
    for host, cert in cert_results.items():
        issuer = cert.get("issuer_cn", "")
        if issuer and "ca" in issuer.lower():
            ca_hosts.setdefault(issuer, []).append(host)

    for ca, hosts in ca_hosts.items():
        unique = sorted(set(hosts))
        if len(unique) > 1:
            findings.append(
                f"Shared CA '{ca}': hosts {', '.join(unique)} share the same certificate authority"
            )

    return findings


def generate_cert_findings(cert_info: dict, host: str, port: int) -> List[str]:
    """Format cert info as report findings list."""
    findings = []

    cn = cert_info.get("subject_cn", "unknown")
    org = cert_info.get("subject_org", "?")
    ou = cert_info.get("subject_ou", "?")
    issuer = cert_info.get("issuer_cn", "?")

    findings.append(
        f"[CERT] {host}:{port}: CN={cn}, ORG={org}, OU={ou}, ISSUER={issuer}"
    )

    sans = cert_info.get("san_list", [])
    if sans:
        findings.append(f"[CERT] {host}:{port}: SANs={', '.join(sans[:10])}")

    if cert_info.get("is_self_signed"):
        findings.append(f"[CERT] {host}:{port}: SELF-SIGNED certificate")

    if cert_info.get("has_wildcard"):
        findings.append(f"[CERT] {host}:{port}: WILDCARD cert ({cn})")

    if cert_info.get("has_expired"):
        findings.append(f"[CERT] {host}:{port}: EXPIRED certificate")

    # Security issues
    sec_issues = analyze_cert_security(cert_info)
    for issue in sec_issues:
        findings.append(f"[CERT] {host}:{port}: {issue}")

    return findings
