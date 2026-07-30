<div align="center">

# 🛡️ wp2shell-Hestia-Scanner

<p>
  <a href="#english">🇬🇧 English</a>
  &nbsp;&nbsp;|&nbsp;&nbsp;
  <a href="#greek">🇬🇷 Ελληνικά</a>
</p>

![Bash](https://img.shields.io/badge/bash-4.0%2B-green?logo=gnubash)
![Platform](https://img.shields.io/badge/platform-HestiaCP-blue)
![License](https://img.shields.io/badge/license-GPL--3.0-orange)
![CVE](https://img.shields.io/badge/CVE-2026--63030%20%7C%202026--60137-red)

**Read-only WordPress security scanner for HestiaCP servers.**  
Detects wp2shell compromise indicators across all hosted sites — with per-client email reports, core file diff, SHA256 webshell detection, risk scoring, and optional AI evaluation.

> ⚠️ **Safe versions:** WordPress **6.8.6 / 6.9.5 / 7.0.2** or newer.  
> These scripts **never modify anything** — read-only throughout.

</div>

---

<a name="english"></a>

# 🇬🇧 English

## What is wp2shell?

wp2shell is a pre-authentication remote code execution (RCE) chain in WordPress core, disclosed on **17 July 2026**. A single anonymous HTTP request against a default installation is enough to create a rogue administrator and execute arbitrary code on the server.

The chain combines:
- **CVE-2026-60137** — SQL injection in the `author__not_in` parameter of `WP_Query`
- **CVE-2026-63030** — Route confusion in the REST API `/wp-json/batch/v1` endpoint

Compromised sites show a rogue admin with login prefix `wp2_` and email `@wp2shell.invalid`.

More information: <https://wp2shell.com>

---

## Repository contents

| File | Purpose |
|------|---------|
| `wp2shell-scan.sh` | Fast server-wide IoC scanner — colour-coded terminal output, risk score per site, auto-saved report to `/root/` |
| `wp2shell-report-per-user.sh` | Full scanner — per-HestiaCP-user email reports, core file diff, SHA256 webshell detection, AI evaluation, risk scoring |
| `known_shells.sha256` | Known webshell hash database (SHA256) — fetched automatically at runtime |

---

## What the scanner checks

### Database / User checks
| Check | Severity |
|-------|----------|
| WordPress version vs. safe versions | HIGH / OK |
| Accounts with `wp2_` prefix or `@wp2shell.invalid` email | CRITICAL |
| Administrators created after disclosure (15/07/2026) | MEDIUM |
| Gaps in user-ID sequence (deleted rogue admin traces) | MEDIUM |
| Orphaned `wp_usermeta` rows | MEDIUM |
| Poisoned `oembed_cache` / `customize_changeset` rows | CRITICAL |
| Tampered WP options (`upload_path`, `auto_prepend_file`, `siteurl`) | CRITICAL / HIGH |

### Core file integrity
| Check | Severity |
|-------|----------|
| `wp core verify-checksums` vs. wp.org | HIGH |
| Line-by-line `diff -U5` against clean downloaded core | CRITICAL / HIGH / OK |
| Extra files not present in clean core (content + metadata shown) | CRITICAL / HIGH |

### File analysis
| Check | Severity |
|-------|----------|
| PHP in `uploads/` | CRITICAL |
| Extra PHP extensions (`.php7` `.phtml` `.phar` `.php5`) | HIGH |
| **SHA256 match against known webshell database** (WSO, FilesMan, b374k, p0wny…) | CRITICAL |
| PHP modified after `SINCE_DATE` **AND** matching suspicious patterns — with matching line shown inline | CRITICAL / HIGH |
| PHP with suspicious patterns but NOT recently modified | LOW |
| JS/HTML modified after `SINCE_DATE` AND matching obfuscation patterns | MEDIUM |
| **External C2/exfiltration URLs** (pastebin, ngrok, Discord webhooks, bit.ly…) | CRITICAL |
| `.htaccess` dangerous directives (`AddType`, `auto_prepend_file`, external `RewriteRule`) | HIGH |
| `.htaccess` modified after `SINCE_DATE` | MEDIUM |
| Polyglot images with PHP payload (`<?php` in `.jpg`/`.png`…) | CRITICAL |
| Exposed backup/config files (`wp-config.php.bak`, `*.sql`…) | MEDIUM |

### Persistence
| Check | Severity |
|-------|----------|
| User crontab entries with `curl`/`wget`/`php`/`base64` | HIGH |
| System cron files referencing the site path | MEDIUM |

### Risk Score
Each site receives a **0–100 risk score** with a breakdown of every contributing finding:

```
  +------------------------------------------+
  |  RISK SCORE: 96/100  COMPROMISED         |
  +------------------------------------------+
  +40  wp2shell fingerprint account
  +30  PHP file(s) inside uploads/
  +20  Vulnerable WordPress version
  +6   Core checksum failure
```

| Score | Label |
|-------|-------|
| 0–20 | Probably Clean |
| 21–40 | Low Risk |
| 41–60 | Medium Risk |
| 61–80 | High Risk |
| 81+ | **COMPROMISED** |

---

## Requirements

- Linux server running **HestiaCP**
- **bash** 4.0+
- **[WP-CLI](https://wp-cli.org/)** installed globally as `wp`
- `root` access
- `sendmail` (for email reports)
- `python3` (for AI evaluation JSON handling)
- `curl`, `sha256sum`, `file`, `strings`, `unzip`

### Install WP-CLI (if missing)
```bash
curl -O https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar
chmod +x wp-cli.phar && sudo mv wp-cli.phar /usr/local/bin/wp
```

---

## One-liner install & run

### Fast IoC scan
```bash
curl -fsSL https://raw.githubusercontent.com/BytesPulse-OE/wp2shell-Hestia-Scanner/main/wp2shell-scan.sh | sudo bash
```

### Full scan with per-client email reports
```bash
curl -fsSL https://raw.githubusercontent.com/BytesPulse-OE/wp2shell-Hestia-Scanner/main/wp2shell-report-per-user.sh \
  -o wp2shell-report-per-user.sh && sudo bash wp2shell-report-per-user.sh
```

> **Note:** The full scanner asks interactive questions at startup (AI evaluation, save report, date threshold). Downloading first then running ensures the prompts work correctly.

---

## Usage

### wp2shell-scan.sh — fast server-wide scan

```bash
sudo bash wp2shell-scan.sh
```

Finds all WordPress installs under `/home/*/web/*/public_html/`, runs all checks, prints colour-coded output to terminal, and saves a full report to `/root/wp2shell-report-YYYYMMDD-HHMMSS.txt`.

At startup it asks for an optional custom date threshold (default: `2026-07-15`).

### wp2shell-report-per-user.sh — full scan with email reports

```bash
sudo bash wp2shell-report-per-user.sh
```

At startup, three questions:

```
[AI EVALUATION]   Use AI evaluation for ambiguous files? [y/N]
[SAVE REPORT]     Save a full report file for later review? [y/N]
[DATE THRESHOLD]  Use a different date? Leave blank to keep default [YYYY-MM-DD]:
```

**Always start with `DRY_RUN=1`** (the default) — emails are previewed on screen, nothing is sent. Change to `DRY_RUN=0` only after confirming the output looks correct.

---

## Configuration

### wp2shell-scan.sh

| Variable | Default | Description |
|----------|---------|-------------|
| `WEB_ROOT` | `/home` | HestiaCP web root |
| `SINCE_DATE` | `2026-07-15` | "Recently modified" threshold |
| `WP` | `wp` | Path to WP-CLI |

### wp2shell-report-per-user.sh

| Variable | Default | Description |
|----------|---------|-------------|
| `DRY_RUN` | `1` | `1` = preview only, `0` = send emails |
| `SEND_ONLY_IF_ISSUES` | `0` | `1` = skip email if site is clean |
| `SINCE_DATE` | `2026-07-15` | "Recently modified" threshold |
| `MAIL_FROM` | `security@<hostname>` | Envelope sender |
| `CORE_CACHE` | `/root/wp2shell-cores` | Clean core cache directory |
| `ANTHROPIC_API_KEY` | *(empty)* | Claude API key for AI evaluation |

---

## AI Evaluation (optional)

For ambiguous diffs that patterns alone cannot classify, the scanner sends the diff to the **Claude API** (`claude-sonnet-4-6`) and returns a verdict: `DANGER`, `SUSPICIOUS`, `REVIEW`, or `OK` with a one-sentence explanation. AI is used **only** in the grey zone — clear cases are classified instantly without any API call.

Set your key in the script or export before running:
```bash
export ANTHROPIC_API_KEY='sk-ant-api03-...'
sudo -E bash wp2shell-report-per-user.sh
```

API keys: <https://console.anthropic.com> — separate from claude.ai subscriptions.

### No API key? Use the browser analyzer

Paste your scan output into the **wp2shell Report Analyzer** artifact on Claude.ai — it performs the same AI evaluation directly in the browser without requiring your own key.

---

## Output format

### Severity levels

| Label | Color | Meaning |
|-------|-------|---------|
| `[CRITICAL]` | 🔴 Bold red | Active compromise indicator — act immediately |
| `[HIGH]` | 🔴 Red | Strong indicator — review urgently |
| `[MEDIUM]` | 🟡 Yellow | Suspicious — investigate |
| `[LOW]` | 🔵 Blue | Low priority — likely false positive |
| `[INFO]` | ⚫ Grey | Informational |
| `[OK]` | 🟢 Green | Clean / expected |

### Core diff example

```
┌─ MODIFIED: wp-includes/load.php
│  [CRITICAL] Assessment (patterns): executable/obfuscated pattern in added lines
│             +20  Core file modified with dangerous pattern
│
│  ORIGINAL: /root/wp2shell-cores/7.0.2-el/wp-includes/load.php
│  SITE:     /home/user/web/example.gr/public_html/wp-includes/load.php
│  @@ -212,5 +212,6 @@
│  -      $loaded = true;
│  +      $loaded = true;
│  +      eval(base64_decode('aGVsbG8='));
└──────────────────────────────────────
```

---

## Notes

- The scanner **never modifies** anything. Safe to run on live production servers.
- Updating WordPress to a patched version closes the vulnerability but **does not clean** an already-compromised site. If indicators are found, restore from a clean backup.
- The `CORE_CACHE` directory (`/root/wp2shell-cores/`) is reused across scans. Delete it to force a fresh download.
- The `known_shells.sha256` hash database is refreshed automatically once per day.

---

## License

GPL-3.0 — see [LICENSE](LICENSE)

---

## Credits

Developed by **[BytesPulse](https://bytespulse.gr)** in response to the wp2shell disclosure (July 2026).  
CVE information: <https://wp2shell.com>

---
---

<a name="greek"></a>

# 🇬🇷 Ελληνικά

## Τι είναι το wp2shell;

Το wp2shell είναι μια αλυσίδα εκμετάλλευσης απομακρυσμένης εκτέλεσης κώδικα (RCE) στον πυρήνα του WordPress, που αποκαλύφθηκε στις **17 Ιουλίου 2026**. Ένα μόνο ανώνυμο HTTP αίτημα σε μια προεπιλεγμένη εγκατάσταση αρκεί για τη δημιουργία διαχειριστή και την εκτέλεση αυθαίρετου κώδικα στον server.

Η αλυσίδα συνδυάζει:
- **CVE-2026-60137** — SQL injection στην παράμετρο `author__not_in` του `WP_Query`
- **CVE-2026-63030** — Route confusion στο REST API `/wp-json/batch/v1`

Τα παραβιασμένα sites εμφανίζουν λογαριασμό διαχειριστή με πρόθεμα `wp2_` και email `@wp2shell.invalid`.

Περισσότερες πληροφορίες: <https://wp2shell.com>

---

## Περιεχόμενα

| Αρχείο | Σκοπός |
|--------|--------|
| `wp2shell-scan.sh` | Γρήγορος σαρωτής IoC — έγχρωμη έξοδος στο terminal, risk score ανά site, αυτόματη αποθήκευση report στο `/root/` |
| `wp2shell-report-per-user.sh` | Πλήρης σαρωτής — email αναφορές ανά HestiaCP user, diff πυρήνα, SHA256 ανίχνευση webshells, AI αξιολόγηση, risk score |
| `known_shells.sha256` | Βάση δεδομένων SHA256 γνωστών webshells — κατεβαίνει αυτόματα κατά την εκτέλεση |

---

## Τι ελέγχει

### Βάση δεδομένων / Χρήστες
| Έλεγχος | Σοβαρότητα |
|---------|-----------|
| Έκδοση WordPress vs. ασφαλείς εκδόσεις | HIGH / OK |
| Λογαριασμοί με πρόθεμα `wp2_` ή email `@wp2shell.invalid` | CRITICAL |
| Διαχειριστές που δημιουργήθηκαν μετά την αποκάλυψη (15/07/2026) | MEDIUM |
| Κενά στην ακολουθία user-ID (ίχνη διαγραμμένου rogue admin) | MEDIUM |
| Orphaned `wp_usermeta` rows | MEDIUM |
| Δηλητηριασμένα `oembed_cache` / `customize_changeset` rows | CRITICAL |
| Αλλοιωμένες WP επιλογές (`upload_path`, `auto_prepend_file`, `siteurl`) | CRITICAL / HIGH |

### Ακεραιότητα αρχείων πυρήνα
| Έλεγχος | Σοβαρότητα |
|---------|-----------|
| `wp core verify-checksums` vs. wp.org | HIGH |
| Γραμμή-γραμμή `diff -U5` έναντι καθαρού πυρήνα | CRITICAL / HIGH / OK |
| Επιπλέον αρχεία που δεν υπάρχουν στον καθαρό πυρήνα | CRITICAL / HIGH |

### Ανάλυση αρχείων
| Έλεγχος | Σοβαρότητα |
|---------|-----------|
| PHP αρχεία στο `uploads/` | CRITICAL |
| Επιπλέον PHP extensions (`.php7` `.phtml` `.phar` `.php5`) | HIGH |
| **SHA256 αντιστοίχιση με γνωστά webshells** (WSO, FilesMan, b374k, p0wny…) | CRITICAL |
| PHP που τροποποιήθηκε μετά το `SINCE_DATE` **ΚΑΙ** περιέχει ύποπτο pattern — με την ακριβή γραμμή | CRITICAL / HIGH |
| PHP με ύποπτα patterns που ΔΕΝ τροποποιήθηκε πρόσφατα | LOW |
| JS/HTML τροποποιημένα μετά το `SINCE_DATE` με obfuscation patterns | MEDIUM |
| **Εξωτερικές C2/εξαγωγή δεδομένων URLs** (pastebin, ngrok, Discord webhooks, bit.ly…) | CRITICAL |
| Επικίνδυνα directives σε `.htaccess` | HIGH |
| `.htaccess` τροποποιημένο μετά το `SINCE_DATE` | MEDIUM |
| Polyglot εικόνες με PHP payload | CRITICAL |
| Εκτεθειμένα backup/config αρχεία | MEDIUM |

### Persistence
| Έλεγχος | Σοβαρότητα |
|---------|-----------|
| Crontab χρήστη με `curl`/`wget`/`php`/`base64` | HIGH |
| System cron αρχεία που αναφέρουν το path του site | MEDIUM |

### Risk Score
Κάθε site λαμβάνει **βαθμολογία 0–100** με ανάλυση κάθε ευρήματος:

```
  +------------------------------------------+
  |  RISK SCORE: 96/100  COMPROMISED         |
  +------------------------------------------+
  +40  wp2shell fingerprint account
  +30  PHP file(s) inside uploads/
  +20  Vulnerable WordPress version
  +6   Core checksum failure
```

| Βαθμολογία | Κατηγορία |
|-----------|-----------|
| 0–20 | Probably Clean |
| 21–40 | Low Risk |
| 41–60 | Medium Risk |
| 61–80 | High Risk |
| 81+ | **COMPROMISED** |

---

## Απαιτήσεις

- Linux server με **HestiaCP**
- **bash** 4.0+
- **[WP-CLI](https://wp-cli.org/)** εγκατεστημένο ως `wp`
- Πρόσβαση `root`
- `sendmail` (για αποστολή email)
- `python3` (για AI αξιολόγηση)
- `curl`, `sha256sum`, `file`, `strings`, `unzip`

### Εγκατάσταση WP-CLI (αν λείπει)
```bash
curl -O https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar
chmod +x wp-cli.phar && sudo mv wp-cli.phar /usr/local/bin/wp
```

---

## Εγκατάσταση με μία εντολή

### Γρήγορος σαρωτής IoC
```bash
curl -fsSL https://raw.githubusercontent.com/BytesPulse-OE/wp2shell-Hestia-Scanner/main/wp2shell-scan.sh | sudo bash
```

### Πλήρης σαρωτής με email αναφορές
```bash
curl -fsSL https://raw.githubusercontent.com/BytesPulse-OE/wp2shell-Hestia-Scanner/main/wp2shell-report-per-user.sh \
  -o wp2shell-report-per-user.sh && sudo bash wp2shell-report-per-user.sh
```

---

## Χρήση

### wp2shell-scan.sh

```bash
sudo bash wp2shell-scan.sh
```

Βρίσκει αυτόματα όλα τα WordPress installs κάτω από `/home/*/web/*/public_html/`, εκτελεί όλους τους ελέγχους, τυπώνει έγχρωμη έξοδο στο terminal και αποθηκεύει πλήρες report στο `/root/`.

### wp2shell-report-per-user.sh

```bash
sudo bash wp2shell-report-per-user.sh
```

Κατά την εκκίνηση ρωτά τρία πράγματα:

```
[AI EVALUATION]   Χρήση AI αξιολόγησης για αμφίβολα αρχεία; [y/N]
[SAVE REPORT]     Αποθήκευση πλήρους report σε αρχείο; [y/N]
[DATE THRESHOLD]  Διαφορετική ημερομηνία; Αφήστε κενό για default [YYYY-MM-DD]:
```

**Ξεκινήστε πάντα με `DRY_RUN=1`** (default) — τα emails εμφανίζονται στην οθόνη, δεν στέλνονται. Αλλάξτε σε `DRY_RUN=0` μόνο αφού επιβεβαιώσετε ότι η έξοδος είναι σωστή.

---

## Ρυθμίσεις

### wp2shell-scan.sh

| Μεταβλητή | Default | Περιγραφή |
|-----------|---------|-----------|
| `WEB_ROOT` | `/home` | Root φάκελος HestiaCP |
| `SINCE_DATE` | `2026-07-15` | Κατώφλι "πρόσφατα τροποποιημένων" |
| `WP` | `wp` | Διαδρομή WP-CLI |

### wp2shell-report-per-user.sh

| Μεταβλητή | Default | Περιγραφή |
|-----------|---------|-----------|
| `DRY_RUN` | `1` | `1` = μόνο preview, `0` = αποστολή emails |
| `SEND_ONLY_IF_ISSUES` | `0` | `1` = email μόνο αν βρεθεί κάτι |
| `SINCE_DATE` | `2026-07-15` | Κατώφλι "πρόσφατα τροποποιημένων" |
| `MAIL_FROM` | `security@<hostname>` | Sender email |
| `CORE_CACHE` | `/root/wp2shell-cores` | Cache καθαρών πυρήνων |
| `ANTHROPIC_API_KEY` | *(κενό)* | Claude API key για AI αξιολόγηση |

---

## AI Αξιολόγηση (προαιρετική)

Για αμφίβολα diffs που τα patterns δεν μπορούν να ταξινομήσουν, ο σαρωτής στέλνει το diff στο **Claude API** (`claude-sonnet-4-6`) και επιστρέφει ετυμηγορία: `DANGER`, `SUSPICIOUS`, `REVIEW`, ή `OK` με μία πρόταση εξήγηση. Το AI χρησιμοποιείται **μόνο** στη γκρίζα ζώνη.

```bash
export ANTHROPIC_API_KEY='sk-ant-api03-...'
sudo -E bash wp2shell-report-per-user.sh
```

API keys: <https://console.anthropic.com> — ξεχωριστό από τη συνδρομή claude.ai.

### Χωρίς API key; Χρησιμοποιήστε τον browser analyzer

Κάντε paste το output του scan στο **wp2shell Report Analyzer** artifact στο Claude.ai — εκτελεί την ίδια AI αξιολόγηση απευθείας στον browser.

---

## Σημειώσεις

- Ο σαρωτής **δεν τροποποιεί τίποτα**. Ασφαλής εκτέλεση σε live production servers.
- Η ενημέρωση του WordPress στην patched έκδοση κλείνει την ευπάθεια αλλά **δεν καθαρίζει** ένα ήδη παραβιασμένο site. Αν βρεθούν indicators, επαναφέρετε από καθαρό backup.
- Ο φάκελος `CORE_CACHE` (`/root/wp2shell-cores/`) επαναχρησιμοποιείται μεταξύ scans. Διαγράψτε τον για αναγκαστική επαναλήψη.
- Η βάση `known_shells.sha256` ανανεώνεται αυτόματα μία φορά ανά 24 ώρες.

---

## Άδεια

GPL-3.0 — δείτε [LICENSE](LICENSE)

---

## Credits

Αναπτύχθηκε από την **[BytesPulse](https://bytespulse.gr)** σε απόκριση της αποκάλυψης wp2shell (Ιούλιος 2026).  
Πληροφορίες CVE: <https://wp2shell.com>
