"""
ReconARC — Default Credential Testing
======================================
SAFE testing of KNOWN default credentials against discovered services.

This module tests only manufacturer-published default credentials (3-5 per
service).  It is NOT a brute-force tool and does not accept wordlists.

Safety features:
  - curl --max-time limits HTTP request duration (default 10 s)
  - ssh ConnectTimeout limits connection attempts
  - smbclient wrapped with timeout
  - All errors handled gracefully — never crashes the scan
  - Only well-known defaults are tested

Usage:
    from tools.cred_test import (
        test_http_auth,
        test_form_login,
        test_smb_login,
        test_ssh_login,
        test_splunk_login,
        run_cred_scan,
        DEFAULT_CREDS,
    )
"""

import re
import shlex
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import requests

from utils import http_get, http_post, run_command


# ── Default Credentials Database ──────────────────────────────────────
# Only well-known manufacturer defaults — 3-5 entries per service type.
# This is for *verification*, NOT brute force.

DEFAULT_CREDS: Dict[str, List[Tuple[str, str]]] = {
    'ssh': [
        ('root', 'root'),
        ('root', 'toor'),
        ('admin', 'admin'),
        ('pi', 'raspberry'),
        ('ubuntu', 'ubuntu'),
    ],
    'smb': [
        ('guest', ''),
        ('Administrator', ''),
        ('admin', 'admin'),
        ('administrator', 'password'),
    ],
    'http_basic': [
        ('admin', 'admin'),
        ('admin', 'password'),
        ('admin', 'admin123'),
        ('root', 'root'),
        ('admin', ''),
    ],
    'splunk': [
        ('admin', 'changeme'),   # Splunk < 9.0 factory default
        ('admin', 'admin'),
        ('admin', 'password'),
    ],
    'tomcat': [
        ('tomcat', 'tomcat'),
        ('admin', 'admin'),
        ('manager', 'manager'),
        ('role1', 'role1'),
    ],
    'jenkins': [
        ('admin', 'admin'),
        ('admin', 'password'),
    ],
}


# ── Service → Credential-Category Matching ────────────────────────────

# Maps the nmap *service* string (lower-cased) to a DEFAULT_CREDS key.
_SERVICE_MATCHERS = {
    'ssh':           'ssh',
    'microsoft-ds':  'smb',
    'netbios-ssn':   'smb',
    'smb':           'smb',
}

# Ports that imply a credential category when the service string is generic.
_PORT_MATCHERS = {
    22:    'ssh',
    139:   'smb',
    445:   'smb',
    8000:  'http_basic',
    8001:  'http_basic',
    8080:  'http_basic',
    8081:  'http_basic',
    8443:  'http_basic',
    10000: 'http_basic',   # Webmin
}

# Banner keywords → specialised web-app credential category.
_BANNER_KEYWORDS = {
    'splunk':  'splunk',
    'tomcat':  'tomcat',
    'jenkins': 'jenkins',
}


def _match_cred_category(service_info: dict) -> str:
    """Determine which DEFAULT_CREDS category applies to a service.

    Returns the category key (e.g. ``'ssh'``, ``'splunk'``) or ``''`` when
    no default credentials are defined for this service.
    """
    service = (service_info.get('service') or '').lower()
    port = service_info.get('port', 0)
    banner = (service_info.get('banner') or '') + ' ' + (service_info.get('version') or '')
    banner_lower = banner.lower()

    # 1. Banner-keyword match takes priority (most specific)
    for keyword, category in _BANNER_KEYWORDS.items():
        if keyword in banner_lower:
            return category

    # 2. Service-name match
    if service in _SERVICE_MATCHERS:
        return _SERVICE_MATCHERS[service]

    # 3. SSH / SMB direct service check
    if service == 'ssh' or port == 22:
        return 'ssh'
    if port in (139, 445):
        return 'smb'

    # 4. HTTP/HTTPS — only test basic auth if port suggests a web panel
    if service in ('http', 'https') or port in (80, 443, 8000, 8001, 8080, 8081, 8443, 10000):
        return _PORT_MATCHERS.get(port, 'http_basic')

    # 5. Port-based fallback
    if port in _PORT_MATCHERS:
        return _PORT_MATCHERS[port]

    return ''


# ── HTTP Basic / NTLM Auth Testing ────────────────────────────────────

def test_http_auth(
    url: str,
    username: str,
    password: str,
    auth_type: str = 'basic',
) -> Tuple[bool, str]:
    """Test HTTP Basic or NTLM authentication against *url*.

    Uses ``requests`` with a 10-second timeout for safety.

    Args:
        url:      Full URL (including scheme) of the protected resource.
        username: Username to test.
        password: Password to test.
        auth_type: ``'basic'`` (default) or ``'ntlm'``.

    Returns:
        ``(success, detail)`` — *detail* includes the HTTP status code.
    """
    # Build auth object
    auth: Optional[requests.auth.HTTPBasicAuth]
    auth_lower = auth_type.lower()
    if auth_lower == 'ntlm':
        try:
            from requests_ntlm import HttpNtlmAuth
            auth = HttpNtlmAuth(username, password)
        except ImportError:
            return (
                False,
                'NTLM auth requires requests-ntlm (pip install requests-ntlm)',
            )
    else:
        auth = requests.auth.HTTPBasicAuth(username, password)

    try:
        resp = requests.get(
            url,
            auth=auth,
            timeout=10,
            verify=False,
            allow_redirects=True,
        )
    except requests.exceptions.Timeout:
        return (False, 'HTTP request timed out after 10s')
    except requests.exceptions.ConnectionError as exc:
        return (False, f'HTTP connection failed: {exc}')
    except Exception as exc:
        return (False, f'HTTP request error: {exc}')

    code = resp.status_code

    if code == 401:
        return (False, f'HTTP 401 — credentials rejected ({auth_type})')
    if code == 403:
        return (False, f'HTTP 403 — forbidden (creds may be valid but access denied)')
    if 200 <= code < 400:
        return (True, f'HTTP {code} — authentication successful ({auth_type})')
    if code == 404:
        return (False, f'HTTP 404 — auth endpoint not found')
    return (False, f'HTTP {code} — unexpected response')


# ── Form-Based Login Testing ──────────────────────────────────────────

def test_form_login(
    url: str,
    username_field: str,
    password_field: str,
    username: str,
    password: str,
    success_indicator: str,
    failure_indicator: str,
) -> Tuple[bool, str]:
    """Test form-based login via HTTP POST.

    Sends a POST with the given field names and checks the response body
    for *success_indicator* or *failure_indicator* strings.

    Uses ``requests`` (via ``utils.http_post``) with a 10-second timeout.

    Args:
        url:               Login form action URL.
        username_field:    HTML name attribute of the username input.
        password_field:    HTML name attribute of the password input.
        username:          Username to test.
        password:          Password to test.
        success_indicator: Substring present in the response on success.
        failure_indicator: Substring present in the response on failure.

    Returns:
        ``(success, detail)``.
    """
    form_data = {
        username_field: username,
        password_field: password,
    }

    headers = {
        'User-Agent': 'Mozilla/5.0 (ReconARC cred-test)',
        'Content-Type': 'application/x-www-form-urlencoded',
    }

    try:
        resp = http_post(
            url,
            data=form_data,
            timeout=10,
            headers=headers,
        )
    except Exception as exc:
        return (False, f'HTTP POST error: {exc}')

    if resp is None:
        return (False, 'No HTTP response — login endpoint unreachable')

    body = resp.text
    if not body:
        return (False, f'Empty response (HTTP {resp.status_code})')

    body_lower = body.lower()

    # Check failure indicator first (more specific)
    if failure_indicator and failure_indicator.lower() in body_lower:
        return (False, f'Login failed — failure indicator "{failure_indicator}" found')

    # Check success indicator
    if success_indicator and success_indicator.lower() in body_lower:
        return (True, f'Login successful — success indicator "{success_indicator}" found')

    # Ambiguous response
    body_snippet = body[:200].replace('\n', ' ').strip()
    return (False, f'Inconclusive — neither indicator matched (HTTP {resp.status_code}). Response: {body_snippet}...')


# ── SMB Login Testing ─────────────────────────────────────────────────

def test_smb_login(
    target: str,
    username: str,
    password: str,
) -> Tuple[bool, str]:
    """Test SMB authentication via ``smbclient``.

    Attempts to list shares on the target.  Wrapped with ``timeout`` for
    safety.

    Args:
        target:   Target IP or hostname.
        username: Username to test (use ``''`` for guest/null session).
        password: Password to test.

    Returns:
        ``(success, detail)``.
    """
    # smbclient uses user%password format; empty password = null session
    user_pass = f'{username}%{password}' if password else f'{username}%'

    cmd = (
        f'timeout 15 smbclient -L //{shlex.quote(target)} '
        f'-U {shlex.quote(user_pass)} '
        f'--option="client min protocol=SMB2" '
        f'-N 2>&1'
    )

    try:
        result = run_command(cmd, timeout=20)
    except Exception as exc:
        return (False, f'smbclient execution error: {exc}')

    if result.get('returncode') == -1 and 'BLOCKED' in (result.get('stderr') or ''):
        return (False, 'Blocked by safety filter')

    combined = f"{result.get('stdout', '')}\n{result.get('stderr', '')}"

    # smbclient exit codes: 0 = success
    rc = result.get('returncode', -1)

    if rc == 124:
        return (False, 'smbclient timed out')

    # Check for common auth-failure strings
    auth_fail_patterns = [
        'NT_STATUS_LOGON_FAILURE',
        'NT_STATUS_ACCESS_DENIED',
        'LOGON_FAILURE',
        'session setup failed',
        'NT_STATUS_INVALID_PARAMETER',
    ]
    combined_upper = combined.upper()
    for pattern in auth_fail_patterns:
        if pattern.upper() in combined_upper:
            return (False, f'SMB auth failed — {pattern}')

    # Success indicators: share listings
    if 'Share name' in combined or 'Disk' in combined or 'IPC' in combined:
        return (True, 'SMB login successful — shares enumerated')

    # Anonymous/guest access sometimes returns without shares
    if rc == 0 and 'NT_STATUS' not in combined_upper:
        return (True, 'SMB login successful (exit 0, no error)')

    snippet = combined[:200].replace('\n', ' ').strip()
    return (False, f'SMB auth inconclusive (rc={rc}): {snippet}...')


# ── SSH Login Testing ─────────────────────────────────────────────────

def test_ssh_login(
    target: str,
    username: str,
    password: str,
    timeout: int = 5,
) -> Tuple[bool, str]:
    """Test SSH password authentication via the ``ssh`` command.

    Uses ``sshpass`` to supply the password non-interactively and
    ``ConnectTimeout`` to limit connection time.  All host-key checks are
    disabled for testing.

    .. note::
       The safety filter in ``utils.is_safe_command`` blocks ``sshpass``
       by default.  If the operator has not whitelisted it, this function
       will return ``(False, ...)`` with a clear message rather than
       attempting a dangerous fallback.

    Args:
        target:   Target IP or hostname.
        username: Username to test.
        password: Password to test.
        timeout:  SSH ConnectTimeout in seconds (default 5).

    Returns:
        ``(success, detail)``.
    """
    user_host = f'{username}@{target}'

    cmd = (
        f'sshpass -p {shlex.quote(password)} '
        f'ssh -o ConnectTimeout={timeout} '
        f'-o StrictHostKeyChecking=no '
        f'-o UserKnownHostsFile=/dev/null '
        f'-o PreferredAuthentications=password '
        f'-o PubkeyAuthentication=no '
        f'-o LogLevel=ERROR '
        f'{shlex.quote(user_host)} '
        f'"echo CRED_TEST_OK" 2>&1'
    )

    try:
        result = run_command(cmd, timeout=timeout + 10)
    except Exception as exc:
        return (False, f'ssh execution error: {exc}')

    # Safety filter blocks sshpass — handle gracefully
    stderr = result.get('stderr', '')
    if result.get('returncode') == -1 and 'BLOCKED' in stderr:
        return (
            False,
            'Blocked by safety filter — sshpass is restricted. '
            'Whitelist sshpass in utils.is_safe_command to enable SSH cred testing.',
        )

    combined = f"{result.get('stdout', '')}\n{stderr}"
    rc = result.get('returncode', -1)

    if rc == 124:
        return (False, f'SSH connection timed out after {timeout}s')

    combined_lower = combined.lower()

    # Success
    if 'CRED_TEST_OK' in combined:
        return (True, 'SSH login successful')

    # Common failure patterns
    if 'permission denied' in combined_lower:
        return (False, 'SSH auth failed — permission denied (wrong credentials)')
    if 'connection refused' in combined_lower:
        return (False, 'SSH connection refused')
    if 'connection timed out' in combined_lower or 'timed out' in combined_lower:
        return (False, f'SSH connection timed out after {timeout}s')
    if 'no route to host' in combined_lower:
        return (False, 'SSH no route to host')
    if 'connection reset' in combined_lower:
        return (False, 'SSH connection reset by peer')

    snippet = combined[:200].replace('\n', ' ').strip()
    return (False, f'SSH auth inconclusive (rc={rc}): {snippet}...')


# ── Splunk Login Testing (cval flow) ──────────────────────────────────

def test_splunk_login(
    url: str,
    username: str,
    password: str,
) -> Tuple[bool, str]:
    """Test Splunk login via the web-UI ``cval`` CSRF-token flow.

    Splunk's login page embeds a CSRF token named ``cval``.  This function:
      1. GETs the login page to extract the ``cval`` token.
      2. POSTs credentials with the token to the login endpoint.

    Uses ``requests`` (via ``utils.http_get``/``http_post``) with timeouts.

    Args:
        url:      Base Splunk URL (e.g. ``https://host:8000``).
        username: Username to test (default Splunk admin is ``admin``).
        password: Password to test.

    Returns:
        ``(success, detail)``.
    """
    # Normalise URL — strip trailing slash
    base_url = url.rstrip('/')
    login_url = f'{base_url}/en-US/account/login'

    # ── Step 1: Fetch login page, extract cval ──
    try:
        login_page = http_get(login_url, timeout=10)
    except Exception as exc:
        return (False, f'Splunk page fetch error: {exc}')

    if login_page is None:
        return (False, 'No response — Splunk login page unreachable')

    page_html = login_page.text
    if not page_html:
        return (False, 'Empty response — Splunk login page unreachable')

    # Extract cval CSRF token
    cval_match = re.search(r'name=["\']?cval["\']?\s+value=["\']([^"\']+)["\']', page_html)
    if not cval_match:
        # Some Splunk versions / SSO configs may not expose cval.
        # Fall back to REST API auth endpoint.
        return _splunk_rest_login(base_url, username, password)

    cval = cval_match.group(1)

    # ── Step 2: POST credentials with cval ──
    post_data = {
        'cval': cval,
        'username': username,
        'password': password,
        'set_tz': 'UTC',
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (ReconARC cred-test)',
        'Content-Type': 'application/x-www-form-urlencoded',
    }

    try:
        resp = http_post(
            login_url, data=post_data, timeout=10, headers=headers,
        )
    except Exception as exc:
        return (False, f'Splunk POST error: {exc}')

    if resp is None:
        return (False, 'No HTTP response from Splunk login POST')

    code = resp.status_code

    # On success Splunk redirects to /en-US/app/launcher/ (302 → 200)
    final_url = resp.url.lower()
    if code in (200, 302) and ('launcher' in final_url or '/app/' in final_url):
        return (True, f'Splunk login successful (HTTP {code}, landed on {resp.url})')

    if code == 200 and 'account/login' not in final_url:
        # Followed redirect successfully — likely logged in
        return (True, f'Splunk login successful (HTTP {code})')

    if code == 401:
        return (False, 'Splunk login failed — HTTP 401 (wrong credentials)')
    if code == 403:
        return (False, 'Splunk login failed — HTTP 403 (forbidden)')

    return (False, f'Splunk login inconclusive — HTTP {code} (final URL: {resp.url})')


def _splunk_rest_login(base_url: str, username: str, password: str) -> Tuple[bool, str]:
    """Fallback: test Splunk credentials via the REST API auth endpoint.

    POSTs to ``/services/auth/login`` — returns a session key on success.
    Uses ``requests`` (via ``utils.http_post``).
    """
    # Determine if we should use the management port (8089) for REST
    parsed = urlparse(base_url)
    rest_url = f'{base_url.rstrip("/")}/services/auth/login'
    if parsed.port == 8000:
        # Web port — try management port for REST
        rest_url = f'{parsed.scheme}://{parsed.hostname}:8089/services/auth/login'

    post_data = {'username': username, 'password': password}

    try:
        resp = http_post(rest_url, data=post_data, timeout=10)
    except Exception as exc:
        return (False, f'Splunk REST error: {exc}')

    if resp is None:
        return (False, 'Splunk REST endpoint unreachable')

    code = resp.status_code
    if code == 200:
        return (True, f'Splunk REST login successful (HTTP {code})')
    if code == 401:
        return (False, f'Splunk REST login failed — HTTP 401 (wrong credentials)')
    return (False, f'Splunk REST login — HTTP {code}')


# ── Credential Scan Orchestrator ──────────────────────────────────────

def run_cred_scan(
    host_ip: str,
    services: List[dict],
) -> List[dict]:
    """Test known default credentials against discovered services.

    Iterates over *services*, matches each against :data:`DEFAULT_CREDS`,
    and runs the appropriate test function.  Only manufacturer-published
    defaults are tested — this is NOT brute force.

    Args:
        host_ip:  Target host IP address.
        services: List of ``ServiceInfo`` dicts.  Each must contain at
                  least ``port`` and ``service``; ``banner`` and
                  ``version`` improve matching.

    Returns:
        List of result dicts::

            {
                'target':   str,    # host_ip:port or URL
                'service':  str,    # service name
                'username': str,
                'password': str,
                'success':  bool,
                'detail':   str,    # human-readable result
            }
    """
    results: List[dict] = []

    if not services:
        return results

    print(f'    [+] CRED: scanning {len(services)} services on {host_ip} for default creds')

    for svc in services:
        port = svc.get('port', 0)
        service_name = svc.get('service', 'unknown')
        banner = svc.get('banner', '')
        version = svc.get('version', '')

        # Determine credential category
        category = _match_cred_category(svc)
        if not category:
            continue

        creds = DEFAULT_CREDS.get(category, [])
        if not creds:
            continue

        print(f'    [+] CRED: testing {category} defaults on {service_name}:{port}')

        for username, password in creds:
            cred_label = f'{username}:{password if password else "(blank)"}'
            result_dict = {
                'target': '',
                'service': service_name,
                'username': username,
                'password': password,
                'success': False,
                'detail': '',
            }

            # ── Dispatch to the correct test function ──

            if category == 'ssh':
                result_dict['target'] = f'{host_ip}:{port}'
                success, detail = test_ssh_login(
                    host_ip, username, password, timeout=5,
                )

            elif category == 'smb':
                result_dict['target'] = f'{host_ip}:{port}'
                success, detail = test_smb_login(host_ip, username, password)

            elif category == 'splunk':
                scheme = 'https' if port in (8000, 8089, 8443) else 'http'
                splunk_url = f'{scheme}://{host_ip}:{port}'
                result_dict['target'] = splunk_url
                success, detail = test_splunk_login(
                    splunk_url, username, password,
                )

            elif category == 'tomcat':
                # Tomcat Manager uses HTTP Basic auth
                scheme = 'https' if port in (8443, 443) else 'http'
                tomcat_url = f'{scheme}://{host_ip}:{port}/manager/html'
                result_dict['target'] = tomcat_url
                success, detail = test_http_auth(
                    tomcat_url, username, password, auth_type='basic',
                )

            elif category == 'jenkins':
                scheme = 'https' if port in (8443, 443) else 'http'
                jenkins_url = f'{scheme}://{host_ip}:{port}/j_acegi_security_check'
                result_dict['target'] = jenkins_url
                success, detail = test_form_login(
                    url=f'{scheme}://{host_ip}:{port}/j_acegi_security_check',
                    username_field='j_username',
                    password_field='j_password',
                    username=username,
                    password=password,
                    success_indicator='dashboard',
                    failure_indicator='loginError',
                )

            elif category == 'http_basic':
                scheme = 'https' if port in (443, 8443) else 'http'
                http_url = f'{scheme}://{host_ip}:{port}/'
                result_dict['target'] = http_url
                success, detail = test_http_auth(
                    http_url, username, password, auth_type='basic',
                )

            else:
                continue

            result_dict['success'] = success
            result_dict['detail'] = detail
            results.append(result_dict)

            status = 'VALID' if success else 'failed'
            print(f'        [{status}] {category} {cred_label} — {detail}')

            # Stop testing this service after first success
            if success:
                print(f'    [+] CRED: valid credentials found for {service_name}:{port}')
                break

    # Summary
    valid = [r for r in results if r['success']]
    print(
        f'    [+] CRED: {len(valid)}/{len(results)} credential tests succeeded '
        f'({len(valid)} valid default cred{"s" if len(valid) != 1 else ""} found)'
    )

    return results


# ── CLI ────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    import json
    import sys

    if len(sys.argv) < 3:
        print('Usage: python cred_test.py <host_ip> <services_json>')
        print('  services_json: JSON array of ServiceInfo dicts')
        sys.exit(1)

    _host = sys.argv[1]
    _services = json.loads(sys.argv[2])
    _results = run_cred_scan(_host, _services)
    print(json.dumps(_results, indent=2))
