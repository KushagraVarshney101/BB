# Module C — Real-World Chaining: P5 → P2/P1

A P5 (path disclosure, dir listing, verbose error, exposed `.git`) is bounty-worthless on
its own. Its value is as a **map**: it tells you where to look for the thing that pays. This
module is the "if you see X, immediately check for Y" table, each row drawn from public
paid reports.

Mindset: an info leak is a *lead*, never a report. Do not submit the P5. Submit what it led to.

---

## The escalation table

### If you see: verbose stack trace / error page (path disclosure)
**Immediately check for Y:**
- Full **framework + version** in the trace → search the disclosed corpus and CVE DB for a
  known RCE/auth-bypass for that exact version. `grep -rl "<framework> <version>" corpus/reports/`.
- **Absolute filesystem paths** → feed them to any LFI/path-traversal param you found
  (`?file=`, `?template=`, `?download=`). The trace hands you valid target paths.
- **SQL fragments in the error** → confirmed injection point; the error *is* the oracle for
  error-based SQLi.
- **Internal hostnames / IPs** → SSRF target list (see below).

**The Tool:** trigger errors deliberately — send a string to an int param, an array to a
scalar (`?id[]=1`), a malformed JSON body, an oversized value.

**The Bounty Mindset:** Version + public CVE = you skip the hard part; the report is
"known RCE, here's the repro." Path + LFI = **arbitrary file read (P2/P1)**.

---

### If you see: directory listing enabled
**Immediately check for Y — the backup/secret files that listing exposes:**
```bash
# Fuzz the listed dir (and siblings) for the classics:
ffuf -u https://target/path/FUZZ -w wordlist.txt \
  -w <(printf '%s\n' .env .git/config .git/HEAD backup.zip db.sql dump.sql \
       config.php.bak index.php~ .DS_Store credentials.json id_rsa .htpasswd \
       app.js.map wp-config.php.save web.config.bak)
```
Then, per hit:
- `.git/` present → `git-dumper https://target/.git ./loot` → full source + often secrets
  in history (`git log -p | grep -iE 'password|secret|key'`).
- `.env` / `config.*.bak` → live credentials, DB strings, API keys.
- `*.sql` / `*.zip` backup → dump = PII / creds.
- `*.js.map` → recovers original source, revealing hidden endpoints (feed to Module A).
- `.DS_Store` → `python ds_store_exp.py` to enumerate more hidden filenames.

**The Bounty Mindset:** Dir listing alone is P5. Dir listing → `.git` → source with a
hardcoded prod secret is a **P1**. This is the single most reliable P5→P1 ladder in bounty
history.

---

### If you see: exposed `.git`, `.svn`, or a source map
**Y:** recover source, then run **Module A** on it (IDOR, mass assignment, hardcoded
secrets), and grep history for secrets:
```bash
git-dumper https://target/.git ./src && cd src
git log --all -p | grep -iE 'password=|secret|api[_-]?key|token|BEGIN (RSA|OPENSSH)'
grep -rnE 'AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_\-]{35}' .
```
**Bounty Mindset:** Exposed source turns a black-box target into white-box — every other
module gets easier. Credentials in git history = **immediate P1**.

---

### If you see: an unlisted / internal API endpoint (from JS, source map, or error)
**Y:**
- Test it with **no auth** and with a *low-priv* token (broken access control / IDOR — Module A).
- Check it for **mass assignment** (send extra privileged fields).
- If it takes a URL/host param → **SSRF** (below).

**Bounty Mindset:** Endpoints the program forgot to document are the ones they forgot to
protect. Undocumented + missing authz = **P1 with no compensating control to argue about**.

---

### If you see: a URL / host / redirect parameter (`url=`, `next=`, `callback=`, `webhook=`, `image=`, `dest=`)
**Y — SSRF and open redirect, in that order of value:**
```bash
# SSRF probes (use a collaborator/interactsh + cloud metadata)
?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
?url=http://metadata.google.internal/computeMetadata/v1/    # needs Metadata-Flavor header
?url=http://[::ffff:169.254.169.254]/                        # IPv6-mapped bypass
?url=http://burpcollab.net/                                  # blind confirm
# If a filter blocks localhost, try NAT64 / decimal / DNS-rebind (see FINDING_gitlab_ssrf_nat64.md)
```
- Reflected back / follows redirect only → open redirect (P4), chain into OAuth token theft.
- Fetches server-side → **SSRF**; escalate to cloud metadata creds (**P1**) or internal
  service access.

**Bounty Mindset:** `url=` param → cloud metadata → IAM creds is the archetypal **P1 SSRF**.
This workspace already has a NAT64 bypass finding on file — reuse that playbook when a naive
localhost filter is present.

---

### If you see: user-controlled content reflected without encoding, or a filename/upload
**Y:**
- Reflected input → probe stored/DOM XSS in the *authenticated* area (self-XSS is P5; XSS in
  another user's context is P3–P2).
- File upload → try `.svg` (XSS), `.html`, double extension, content-type mismatch, path in
  filename (`../`), and check where it's served (same-origin + rendered = XSS/RCE surface).

**Bounty Mindset:** XSS in an admin/other-user context = **session theft / account takeover**.
The chain is reflected-P5 → stored-in-victim-context-P2.

---

### If you see: JWT / session token in the response or JS
**Y:** decode it (`jwt.io` offline), then test:
- `alg:none` accepted?  weak/`HS256`-with-public-key confusion?  (`grep` corpus for the lib).
- Does it embed a `role`/`userId` you can tamper (Module A mass-assignment mindset)?
- Long/no expiry + no rotation on logout = session fixation angle.

**Bounty Mindset:** A forgeable token = **auth bypass / account takeover, P1**.

---

## How to run a chain end-to-end (worked shape)

1. **Recon P5** — spider, catch a verbose error or dir listing.
2. **Map** — extract versions, paths, hostnames, hidden endpoints from the leak.
3. **Pivot** — pick the highest-EV Y from the table above for what the leak exposed.
4. **Prove** — reproduce against a real instance (use the local labs where the target is
   self-hostable: GitLab/Matomo/Next.js).
5. **Write the impact, lead with the P-you-reached**, and reference the P5 only as the
   discovery step. Triagers reward demonstrated impact, not the breadcrumb.

> House rule from this workspace: read the program's **policy exclusions before** you invest
> in a chain — some programs explicitly N/A dir listing, `.git`, SSRF-to-metadata, or
> self-XSS. Confirm the *endpoint* of your chain is in-scope and payable first.
