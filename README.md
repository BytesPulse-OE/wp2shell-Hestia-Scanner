# wp2shell-hestia-scanner

Read-only WordPress security scanner for **HestiaCP** servers.
Detects compromise indicators from the **wp2shell** exploit chain
(CVE-2026-63030 + CVE-2026-60137) across all hosted sites,
sends per-client email reports, and performs deep file analysis
with optional AI evaluation via the Claude API.

> **Safe versions:** WordPress 6.8.6 / 6.9.5 / 7.0.2 or newer.
> These scripts never modify anything — read-only throughout.

---

## What is wp2shell?

wp2shell is a pre-authentication remote code execution chain in WordPress core,
disclosed on 17 July 2026. A single anonymous HTTP request against a default
installation (no plugins, no special configuration) is enough to create a
rogue administrator account and execute arbitrary code on the server.

The chain combines:
- **CVE-2026-60137** — SQL injection in the `author__not_in` parameter of `WP_Query`
- **CVE-2026-63030** — Route confusion in the REST API `/wp-json/batch/v1` endpoint

Compromised sites typically show a rogue admin with login prefix `wp2_` and
email `@wp2shell.invalid`. The patch was included in WordPress 6.8.6, 6.9.5,
and 7.0.2 (released 17 July 2026).

More information: <https://wp2shell.com>

---

## Repository contents

| File | Purpose |
|------|---------|
| `wp2shell-scan.sh` | Fast IoC scanner — checks all WP installs server-wide, outputs a colour-coded report to stdout and `/root/` |
| `wp2shell-report-per-user.sh` | Full scanner — per-user email reports, core file diff, PHP/JS/htaccess/image analysis, optional AI evaluation |

---

## Requirements

- Linux server running **HestiaCP**
- **bash** 4.0+
- **[WP-CLI](https://wp-cli.org/)** installed globally as `wp`
- `root` access (both scripts must run as root)
- `sendmail` (for `wp2shell-report-per-user.sh` email sending)
- `python3` (for JSON handling in AI calls)
- `curl` (for AI evaluation, optional)
- `unzip`, `file`, `strings` (recommended, for archive/binary analysis)

### Install WP-CLI (if not present)

```bash
curl -O https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar
chmod +x wp-cli.phar
sudo mv wp-cli.phar /usr/local/bin/wp
wp --info
```

---

## Quick start

### 1. wp2shell-scan.sh — fast server-wide IoC scan

Checks every WordPress install on the server for the most direct
wp2shell indicators: rogue admin accounts, orphaned usermeta, poisoned
`oembed_cache`, vulnerable WordPress versions, core checksum failures,
PHP files in `uploads/`, and webshell signatures.

```bash
sudo bash wp2shell-scan.sh
```

Output is written to stdout (colour-coded) and automatically saved to
`/root/wp2shell-report-YYYYMMDD-HHMMSS.txt`.

---

### 2. wp2shell-report-per-user.sh — full scan with email reports

The main scanner. For every HestiaCP user it:

1. Finds all WordPress installs under `/home/<user>/web/`
2. Checks WordPress version, rogue admins, orphaned usermeta, PHP in uploads, core checksums
3. Downloads the exact clean WordPress core for each site's version and locale, then runs a **line-by-line diff** — showing what changed, what was added, and evaluating each file
4. Scans `wp-content` for PHP/JS/HTML/htaccess/image malicious patterns
5. Sends a report email to the `CONTACT` address stored in HestiaCP for that user

#### First run (always start with DRY_RUN=1)

```bash
sudo bash wp2shell-report-per-user.sh
```

On startup the script asks two interactive questions:

```
+------------------------------------------------------+
|           AI EVALUATION (Claude API)                |
+------------------------------------------------------+
  Use AI evaluation for ambiguous files? [y/N]

+------------------------------------------------------+
|           SAVE REPORT                               |
+------------------------------------------------------+
  Save a full report file for later review? [y/N]
```

With `DRY_RUN=1` (the default) **no emails are sent** — the full email
body is printed to stdout so you can review it before it reaches clients.

#### Send real emails

Open the script and change:

```bash
DRY_RUN=1   →   DRY_RUN=0
```

Then run again. Emails are sent via `sendmail` to the HestiaCP `CONTACT`
address of each user.

#### Send only when issues are found

```bash
SEND_ONLY_IF_ISSUES=0   →   SEND_ONLY_IF_ISSUES=1
```

---

## Configuration

All settings are at the top of each script.

### wp2shell-scan.sh

| Variable | Default | Description |
|----------|---------|-------------|
| `WEB_ROOT` | `/home` | Root path for HestiaCP users |
| `DAYS_MODIFIED` | `30` | Flag PHP files modified within this many days |
| `WP` | `wp` | Path to WP-CLI binary |

### wp2shell-report-per-user.sh

| Variable | Default | Description |
|----------|---------|-------------|
| `DRY_RUN` | `1` | `1` = preview only, `0` = send emails |
| `SEND_ONLY_IF_ISSUES` | `0` | `1` = skip email if site is clean |
| `MAIL_FROM` | `security@<hostname>` | Envelope sender address |
| `MAIL_SUBJECT` | `[wp2shell] Security scan report -- %DOMAINS%` | Email subject (`%DOMAINS%` is replaced automatically) |
| `CORE_CACHE` | `/root/wp2shell-cores` | Directory for cached clean WP cores (reused across scans) |
| `ANTHROPIC_API_KEY` | *(empty)* | Claude API key for AI evaluation (optional) |

---

## AI evaluation (optional)

When an ambiguous diff or extra file cannot be classified by pattern
matching alone, the scanner can send it to the **Claude API**
(`claude-sonnet-4-6`) for a security verdict: `DANGER`, `SUSPICIOUS`,
`REVIEW`, or `OK`, with a one-sentence explanation.

AI evaluation is used **only** in the grey zone — when patterns are
inconclusive. Clear-cut cases (e.g. `eval(base64_decode(...))` in added
lines → `DANGER`) are classified instantly without any API call.

### Option A — set key in the script

Open `wp2shell-report-per-user.sh` and replace:

```bash
ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY:-}"
```

with:

```bash
ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY:-sk-ant-api03-...}"
```

### Option B — export before running

```bash
export ANTHROPIC_API_KEY='sk-ant-api03-...'
sudo -E bash wp2shell-report-per-user.sh
```

API keys are available at <https://console.anthropic.com> (separate from
claude.ai subscriptions — pay-as-you-go credits required).

### Option C — analyse in the browser (no API key needed)

If you don't have an Anthropic API key, paste the scan output into the
**[wp2shell Report Analyzer](https://claude.ai)** Claude artifact — it
performs the same AI evaluation directly in the browser using the
Claude API on your behalf.

---

## What the scanner checks

### Database / user checks
- WordPress version vs. safe versions (6.8.6 / 6.9.5 / 7.0.2+)
- Admin accounts with `wp2_` prefix or `@wp2shell.invalid` email
- Administrators created after the disclosure date (15 July 2026)
- Gaps in user ID sequence (deleted rogue admin traces)
- Orphaned `wp_usermeta` rows (remnants of deleted users)
- Poisoned `oembed_cache` and `customize_changeset` rows (exploit mechanism)

### Core file integrity
- `wp core verify-checksums` against official WordPress.org checksums
- Line-by-line `diff -U5` against a freshly downloaded clean core for the exact version and locale of each site
- Files modified (changed vs. clean core) shown with full unified diff
- Extra files (not present in clean core) shown with content and metadata

### File analysis (`wp-content` + root)
- **PHP** — pattern scan for `eval(`, `base64_decode(`, `gzinflate(`, `shell_exec(`, `php://input`, `create_function(`, `preg_replace` with `/e` modifier, and more
- **PHP in uploads/** — any `.php` file here is flagged as high severity
- **Extra PHP extensions** — `.php7`, `.phtml`, `.phar`, `.php5`, `.shtml`
- **JS / HTML** — `eval(atob(...))`, `document.write(unescape(...))`, obfuscated `String.fromCharCode(...)`, external `src=` pointing to unknown domains
- **.htaccess** — `AddType application/x-httpd-php` (execute non-PHP as PHP), `auto_prepend_file`, `auto_append_file`, `RewriteRule` pointing to external URLs or uploads; distinguishes malicious from protective (`php_flag engine off`)
- **Polyglot images** — `<?php` literal inside `.jpg`, `.png`, `.gif`, `.ico`, `.webp` files
- **Exposed backups** — `wp-config.php.bak`, `wp-config.old`, `*.sql`, `database.sql` in web-accessible paths
- **Archives in document root** — `.zip`, `.gz`, `.tar` files that should not be publicly accessible

---

## Output format

### wp2shell-scan.sh

Colour-coded terminal output using `[!]` (red), `[?]` (yellow), `[ok]` (green).
Automatically saved to `/root/wp2shell-report-YYYYMMDD-HHMMSS.txt`.

### wp2shell-report-per-user.sh

For each changed or extra core file:

```
┌─ MODIFIED: wp-includes/load.php
│  [!] Assessment (patterns): [DANGER] -- executable/obfuscated pattern found in added lines
│
│  ORIGINAL: /root/wp2shell-cores/7.0.2-el/wp-includes/load.php
│  SITE:     /home/user/web/example.gr/public_html/wp-includes/load.php
│  @@ -212,5 +212,6 @@
│  -      $loaded = true;
│  +      $loaded = true;
│  +      eval(base64_decode('...'));
└──────────────────────────────────────
```

Lines prefixed `-` are from the **clean core**, lines prefixed `+` are from the **live site**.

---

## Notes

- **This scanner never modifies anything.** It is safe to run on production servers.
- Updating WordPress to a patched version closes the vulnerability but does **not** clean an already-compromised site. If indicators are found, treat the site as compromised and restore from a clean backup.
- The `CORE_CACHE` directory (`/root/wp2shell-cores/`) stores downloaded clean cores and is reused across scans — delete it to force a fresh download.
- Premium and custom plugins do not have official checksums and cannot be verified automatically — review recently modified files manually.

---

## License

MIT

---

## Credits

Developed by **[BytesPulse](https://bytespulse.gr)** in response to the wp2shell
disclosure (July 2026).
CVE information: <https://wp2shell.com>
