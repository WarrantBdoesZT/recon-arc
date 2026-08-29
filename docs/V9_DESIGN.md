# StrikeARC v9 — Executor Rearchitecture

**Status:** Design (2026-08-29)
**Predecessor:** v8.4.0 @ `32e4f8e`
**Trigger:** Runs 15–19 post-mortem — 100% of real flags came from
deterministic sensors; 0% from LLM attack paths despite the LLM
identifying the winning chain (Support Center SQLi → admin:admin →
ticket upload → webshell) in every run.

## 1. Problem statement

The v8 executor treats exploitation as "LLM writes curl/hydra strings →
run them → grep output". This produces:

- **Phantom sessions** (run 19): hydra *ran* → `success: true` → webshell
  session with empty `transport_config` and no shell behind it. Privesc /
  flag-hunt then churn against unresolvable hosts.
- **Interactive-protocol failures** (run 16): sqlmap dispatched
  UNAUTHENTICATED because the curl login's cookie jar was never chained;
  fixed by a special-case hand-patch (v8.3.4) that only works for this
  exact lab shape.
- **No last-mile loop** (every run): once creds + shell exist, no code
  path does `whoami` → hunt-through-transport → privesc → hunt-again.
  All runs die at minute ~8 holding valid foothold material.
- **LLM strategy churn**: fresh vector IDs each analyze pass defeated
  id-memoization (fixed v8.4.0), but LLM still spends calls re-deriving
  the same plan.

## 2. Design principles

1. **A foothold is only real when verified.** No session exists until a
   nonce command returns through the channel. `hydra exit 0` is not a
   foothold.
2. **Mechanics are code, strategy is LLM.** HTTP sessions, uploads,
   injection, and shell I/O are deterministic Python primitives. The LLM
   picks *which* playbook runs next — it never writes raw commands.
3. **Playbooks come from the vault.** The 1,683 command blocks /
   1,099 technique tags are encoded as explicit step-chains (§4), not
   free-form suggestions.
4. **Nothing is deleted.** Enum, sensors, state, saves, stall logic, and
   the LangGraph flow stay. v9 replaces the executor core only.

## 3. Primitives layer (`tools/primitives.py`)

Each primitive is a pure function returning a typed result. All network
I/O uses `requests` with timeout; failures raise `PrimitiveError` —
no silent HTTP-200 "success".

```python
@dataclass
class HTTPSession:
    base: str                  # http://ip[:port]
    cookies: dict
    def get(self, path, **kw) -> Response
    def post(self, path, data, **kw) -> Response

def http_login(url, fields, success_marker, fail_marker=None) -> HTTPSession | None
def upload_file(sess, path, field, content, name) -> str | None      # returns URL
def exec_webshell(url, param, cmd, timeout=15) -> str | None          # nonce-verified
def sqli_test(base, path, params) -> bool
def sqli_dump(base, path, params, session: HTTPSession | None) -> list[dict]
def ssh_connect(ip, user, password, port=22) -> SSHCredTransport | None
def spray_creds(ip, service, cred_pairs) -> list[dict]               # validated only
```

Rules:
- `exec_webshell` verification: send `echo strikearc_<nonce8>`; if the
  nonce doesn't round-trip, the shell is dead → `None`.
- `http_login` requires an explicit `success_marker` (e.g. body no longer
  contains `login.php`, or contains an admin panel marker). Status 200
  alone is failure.
- Every primitive logs to the run log with a stable tag
  (`[PRIM:<name>]`) for post-run diffing across runs.

## 4. Playbooks (`tools/playbooks.py`)

Declared chains over primitives with explicit success criteria:

```python
@dataclass
class Playbook:
    name: str
    triggers: list[str]        # matched against vector_type / evidence keywords
    steps: list[Step]          # ordered; each Step = primitive call + success test
    vault_ref: str             # e.g. "HTB SQL Injection Fundamentals"
```

Initial set (each maps to a real vault module):

| Playbook | Chain | Vault ref |
|---|---|---|
| `web_app_shell` | http_login → upload → exec_webshell(nonce) → hunt(privesc loop) | File Upload / Command Injection |
| `sqli_chain` | http_login → sqli_test → sqli_dump(authenticated) → mine HTB{} + creds | SQL Injection Fundamentals |
| `cred_ssh` | spray → ssh_connect → hunt → privesc hunt | Password Attacks 06/07 |
| `dns_txt` | (existing AXFR sensor) | DNS Enumeration |
| `ftp_retr` | (existing FTP retry sensor) | FTP Protocol |

Playbook step failures abort the chain and emit a structured
`PlaybookResult` into state (`playbook_runs`) so the LLM planner and
memoization see what fired, what failed, and at which step.

Playbooks are idempotent: `(playbook, target_key)` pairs memoized like
v8.4.0's `(technique, target)` pairs.

## 5. Session model (verified only)

```python
Session = {
  "id": "sess_...",
  "host_ip": <ip extracted via regex from target, never split(":")>,
  "transport": WebshellTransport | SSHCredTransport,   # built eagerly
  "verified": true,        # set only after nonce round-trip
  "transport_config": {...}  # url/param or user/pass/port
}
```

- `_create_session` is replaced: it no longer infers from LLM result
  dicts; sessions are created ONLY by playbook steps that already hold a
  verified transport.
- `_get_transport_for_host` keeps its alive-gate (and now receives clean
  host IPs).

## 6. Sessions → playbook loop

Scope priority order (replaces attack-path dispatch):
1. Deterministic sensors (DNS TXT, FTP, etc.)
2. Playbooks with satisfied triggers
3. LLM planner (only when 1+2 are exhausted; picks next playbook /
   target, or requests deeper enum)
4. Stall/memoization logic unchanged

## 7. Migration & compatibility

- `nodes/exploit_nodes.py::exploit_node` keeps its interface; internally
  dispatches to playbooks instead of `_dispatch_attack_path`.
- Old vectors of type `attack_path` are converted to playbook triggers
  by keyword mapping (`sqli` → `sqli_chain`, `upload`/`rce` →
  `web_app_shell`, etc.); unmapped vectors fall back to the v8 executor
  path (kept for one version as a safety net).
- Saves: `playbook_runs` is a new state key (declared in ReconState).

## 8. Acceptance test

The current lab (10.129.229.147) holds the bar:
1. Support Center chain produces a **verified** webshell session.
2. Flag hunt through transport finds a flag in webroot/user dirs.
3. No phantom sessions in the save (all sessions `verified: true` with
  non-empty transport_config).
4. Deterministic flags (DNS TXT, FTP) still land.
5. LLM call count ≤ run 19's (21 calls).

## 9. Risks

- **Over-fitting to this lab** (the v8.3.4 mistake): acceptance criteria
  are lab-independent (verified foothold, authenticated dump, round-trip
  nonce), not "capture the webshell flag".
- **Playbook coverage**: initial 5 won't cover everything; unmapped
  vectors keep the v8 fallback so capability never regresses.
- **LLM role reduction**: planner prompt needs updating to choose among
  playbooks — smaller prompt, fewer calls.
- **requests/bs4 availability**: bs4 already present (searchsploit
  mirror used it); requests is stdlib-adjacent and in the venv.
