#!/usr/bin/env bash
#
# wp2shell-report-per-user.sh
# Read-only wp2shell scanner per HestiaCP user + core diff + email report.
#
# - Never modifies anything on sites (read-only throughout).
# - For each user: scans their WP sites, diffs against clean core,
#   checks PHP/JS/HTML/htaccess/images for malicious signatures & new files,
#   and sends a findings email to the HestiaCP CONTACT address of each user.
#
# Usage:  sudo bash wp2shell-report-per-user.sh
#
# WARNING: start with DRY_RUN=1 (default) to preview emails on screen
#          BEFORE sending them to real clients.
# ---------------------------------------------------------------------------

set -uo pipefail

# --- Settings ---------------------------------------------------------------
HESTIA="/usr/local/hestia"
USERS_DIR="$HESTIA/data/users"
CORE_CACHE="/root/wp2shell-cores"        # cache clean cores per version+locale
DAYS_MODIFIED=30
WP="wp"

DRY_RUN=1                                # 1 = preview only, 0 = send emails
SEND_ONLY_IF_ISSUES=0                    # 1 = email only if issues found
MAIL_FROM="security@$(hostname -f 2>/dev/null || hostname)"
MAIL_SUBJECT="[wp2shell] Security scan report -- %DOMAINS%"
SENDMAIL="/usr/sbin/sendmail"

# Set your Anthropic API key here, or export it before running:
#   export ANTHROPIC_API_KEY='sk-ant-...' && sudo -E bash wp2shell-report-per-user.sh
ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY:-}"
# ---------------------------------------------------------------------------

[ "$(id -u)" -eq 0 ] || { echo "Run as root (sudo)."; exit 1; }
command -v "$WP" >/dev/null 2>&1 || { echo "wp-cli not found."; exit 1; }
mkdir -p "$CORE_CACHE"

echo ""
echo "+------------------------------------------------------+"
echo "|        wp2shell Security Scanner -- BytesPulse      |"
echo "+------------------------------------------------------+"
echo ""

# --- Q1: AI evaluation ---
USE_AI=0
echo "+------------------------------------------------------+"
echo "|           AI EVALUATION (Claude API)                |"
echo "+------------------------------------------------------+"
if [ -z "$ANTHROPIC_API_KEY" ]; then
  echo "|  No API key set. To enable AI evaluation set       |"
  echo "|  ANTHROPIC_API_KEY in the settings block above,   |"
  echo "|  or: export ANTHROPIC_API_KEY='sk-ant-...'        |"
  echo "|       sudo -E bash $0"
  echo "+------------------------------------------------------+"
  echo "  -> AI evaluation unavailable (no API key)."
else
  echo "|  API key is set. AI sends ambiguous diffs/files    |"
  echo "|  to Claude API -- only when patterns are           |"
  echo "|  inconclusive (grey zone).                         |"
  echo "+------------------------------------------------------+"
  read -r -p "  Use AI evaluation for ambiguous files? [y/N] " ai_choice </dev/tty
  case "${ai_choice,,}" in
    y|yes) USE_AI=1; echo "  -> AI evaluation ENABLED." ;;
    *)     USE_AI=0; echo "  -> AI evaluation DISABLED -- patterns only." ;;
  esac
fi
echo ""

# --- Q2: Save report ---
REPORT_FILE=""
echo "+------------------------------------------------------+"
echo "|           SAVE REPORT                               |"
echo "+------------------------------------------------------+"
read -r -p "  Save a full report file for later review? [y/N] " save_choice </dev/tty
case "${save_choice,,}" in
  y|yes)
    REPORT_FILE="/root/wp2shell-report-$(date +%Y%m%d-%H%M%S).txt"
    echo "  -> Report: $REPORT_FILE"
    {
      echo "=================================================================="
      echo " wp2shell Security Report -- BytesPulse"
      echo " Server:  $(hostname -f 2>/dev/null || hostname)"
      echo " Date:    $(date '+%Y-%m-%d %H:%M:%S')"
      echo " AI:      $([ "$USE_AI" -eq 1 ] && echo 'ENABLED' || echo 'DISABLED')"
      echo "=================================================================="
    } > "$REPORT_FILE"
    ;;
  *)
    REPORT_FILE=""
    echo "  -> Report will not be saved."
    ;;
esac
echo ""

# Global: dangerous PHP patterns -- used by scan_site AND scan_files
DANGER_PATTERNS='eval\s*\(|base64_decode\s*\(|gzinflate\s*\(|gzuncompress\s*\(|gzdecode\s*\(|assert\s*\(|shell_exec\s*\(|passthru\s*\(|proc_open\s*\(|popen\s*\(|pcntl_exec\s*\(|php://input|create_function\s*\(|preg_replace.*\/e[^a-z]|move_uploaded_file\s*\(|str_rot13\s*\('

# Run wp-cli as site owner (no plugins/themes for speed & safety)
run_wp() { local owner="$1" path="$2"; shift 2; sudo -u "$owner" -- "$WP" --path="$path" --skip-plugins --skip-themes "$@" 2>/dev/null; }

# Download (once) clean core for version+locale to cache, as root
ensure_clean_core() {
  local ver="$1" loc="$2" dir="$CORE_CACHE/${ver}-${loc}"
  if [ ! -f "$dir/wp-load.php" ]; then
    mkdir -p "$dir"
    "$WP" core download --allow-root --version="$ver" --locale="$loc" \
          --path="$dir" --skip-content --force >/dev/null 2>&1 \
      || "$WP" core download --allow-root --version="$ver" \
              --path="$dir" --skip-content --force >/dev/null 2>&1
  fi
  echo "$dir"
}

# ---------------------------------------------------------------------------
# scan_files: checks PHP/JS/HTML/htaccess/images for malicious content.
# Called from scan_site -- prints to stdout, returns 1 if anything found.
# ---------------------------------------------------------------------------
scan_files() {
  local WPP="$1" issues=0
  local CONTENT="$WPP/wp-content"

  echo "  -- File scan (PHP/JS/HTML/.htaccess/images) --"

  # A) EXTRA PHP EXTENSIONS -- files Apache/Nginx executes as PHP
  #    (.php7 .phtml .phar .php5 .shtml) -- never belong in a normal WP site
  local xphp
  xphp="$(find "$WPP" -type f \( \
            -name '*.php7' -o -name '*.phtml' -o -name '*.phar' \
            -o -name '*.php5' -o -name '*.shtml' \
          \) 2>/dev/null)"
  if [ -n "$xphp" ]; then
    echo "  [!] Files with executable PHP extensions (.php7/.phtml/.phar/.php5/.shtml):"
    echo "$xphp" | sed 's/^/       /'
    issues=1
  fi

  # B) PHP SIGNATURES -- eval/assert/base64/shell etc.
  #    Search entire site (plugins, themes, uploads, root).
  #    Exclude wp-includes & wp-admin -- covered by core diff/checksums.
  local php_sig
  php_sig="$(grep -RIlE --include='*.php' "$DANGER_PATTERNS" \
      "$CONTENT" "$WPP"/*.php 2>/dev/null \
    | grep -vE '/(wp-includes|wp-admin)/' \
    | head -60)"
  if [ -n "$php_sig" ]; then
    echo "  [?] PHP with suspicious patterns (check context -- possible false positives):"
    echo "$php_sig" | sed 's/^/       /'
    # Separate uploads/ hits -- PHP never belongs there
    local php_sig_up
    php_sig_up="$(echo "$php_sig" | grep '/uploads/')"
    if [ -n "$php_sig_up" ]; then
      echo "  [!] Among those, inside uploads/ (DEFINITELY suspicious):"
      echo "$php_sig_up" | sed 's/^/       /'
      issues=1
    fi
  fi

  # C) .HTACCESS -- dangerous directives (distinguishes protective vs malicious)
  local htaccess_files
  mapfile -t htaccess_files < <(find "$WPP" -name '.htaccess' -type f 2>/dev/null)
  for hta in "${htaccess_files[@]}"; do
    # DANGER: AddType (executes other extensions as PHP), auto_prepend/append (inject),
    #           RewriteRule pointing to uploads or external URL
    local hta_danger
    hta_danger="$(grep -inE \
      'AddType\s+application/x-httpd-php|auto_prepend_file|auto_append_file|php_value\s+auto_prepend|RewriteRule.*uploads.*\.(php|phtml|phar)|RewriteRule.*http[s]?://' \
      "$hta" 2>/dev/null)"
    if [ -n "$hta_danger" ]; then
      echo "  [!] DANGEROUS directives in ${hta#$WPP/}:"
      echo "$hta_danger" | sed 's/^/       >> /'
      issues=1
    fi

    # PROTECTIVE (OK): php_flag engine off -- blocks PHP execution, set by plugins
    local hta_protective
    hta_protective="$(grep -inE 'php_flag\s+engine\s+off' "$hta" 2>/dev/null)"
    if [ -n "$hta_protective" ]; then
      echo "  [ok] Protective directive in ${hta#$WPP/} (php_flag engine off -- normal, set by plugins like Sucuri/WPForms)"
    fi

    # INFORMATIONAL: other php_flag/php_value entries that are not engine off
    local hta_phpflag
    hta_phpflag="$(grep -inE 'php_flag|php_value' "$hta" 2>/dev/null \
                  | grep -ivE 'php_flag\s+engine\s+off')"
    if [ -n "$hta_phpflag" ]; then
      echo "  [?] php_flag/php_value in ${hta#$WPP/} (check context):"
      echo "$hta_phpflag" | sed 's/^/       /'
    fi
  done

  # D) JS/HTML -- malicious JavaScript signatures
  #    eval(atob(...)) / document.write(unescape(...)) / obfuscated hex strings /
  #    external src loading scripts from unknown domains
  local js_sig
  js_sig="$(grep -RIlE --include='*.js' --include='*.html' --include='*.htm' \
      'eval\s*\(\s*atob\s*\(|eval\s*\(\s*unescape\s*\(|document\.write\s*\(\s*unescape|String\.fromCharCode\s*\([0-9,\s]{40,}\)|\\\\x[0-9a-f]{2}\\\\x[0-9a-f]{2}\\\\x[0-9a-f]{2}|fetch\s*\(\s*['"'"'"][^'"'"'"]{0,5}https?://[^/]|src\s*=\s*['"'"'"]https?://(?!ajax\.googleapis|cdnjs\.cloudflare|code\.jquery|cdn\.jsdelivr|fonts\.googleapis|use\.fontawesome)' \
      "$CONTENT" 2>/dev/null | head -40)"
  if [ -n "$js_sig" ]; then
    echo "  [?] JS/HTML with suspicious patterns (obfuscation, external script src):"
    echo "$js_sig" | sed 's/^/       /'
    issues=1
  fi

  # E) NEW/MODIFIED files after 15/07/2026
  #    PHP -- excluding wp-includes & wp-admin (covered by core diff)
  local new_php
  new_php="$(find "$CONTENT" "$WPP"/*.php 2>/dev/null \
              -type f -name '*.php' -newermt '2026-07-15' \
              -printf '%TY-%Tm-%Td %TH:%TM  %p\n' 2>/dev/null | head -40)"
  [ -n "$new_php" ] && {
    echo "  [?] PHP modified after 15/07 (wp-content + root):"
    echo "$new_php" | sed 's/^/       /'
  }

  #    JS/HTML -- new or modified
  local new_js
  new_js="$(find "$CONTENT" -type f \( -name '*.js' -o -name '*.html' -o -name '*.htm' \) \
              -newermt '2026-07-15' \
              -printf '%TY-%Tm-%Td %TH:%TM  %p\n' 2>/dev/null | head -40)"
  [ -n "$new_js" ] && {
    echo "  [?] JS/HTML modified after 15/07:"
    echo "$new_js" | sed 's/^/       /'
  }

  #    .htaccess -- modified
  local new_hta
  new_hta="$(find "$WPP" -name '.htaccess' -newermt '2026-07-15' \
              -printf '%TY-%Tm-%Td %TH:%TM  %p\n' 2>/dev/null)"
  [ -n "$new_hta" ] && {
    echo "  [!] .htaccess modified after 15/07:"
    echo "$new_hta" | sed 's/^/       /'
    issues=1
  }

  # F) IMAGES WITH PHP PAYLOAD -- polyglot files
  #    Search for literal "<?php" inside jpg/png/gif/ico/webp
  local img_php
  img_php="$(grep -RIla --include='*.jpg' --include='*.jpeg' \
               --include='*.png' --include='*.gif' --include='*.ico' \
               --include='*.webp' \
               '<?php' "$CONTENT/uploads" 2>/dev/null | head -20)"
  if [ -n "$img_php" ]; then
    echo "  [!] Images containing PHP code (polyglot payload):"
    echo "$img_php" | sed 's/^/       /'
    issues=1
  fi

  # G) EXPOSED BACKUP/CONFIG files -- web-accessible
  local exposed
  exposed="$(find "$WPP" -maxdepth 2 -type f \( \
               -name 'wp-config.php.bak' -o -name 'wp-config.old' \
               -o -name 'wp-config.php~' -o -name '*.sql' \
               -o -name '*.sql.gz' -o -name 'database.sql' \
             \) 2>/dev/null)"
  if [ -n "$exposed" ]; then
    echo "  [!] Exposed backup/config files (web-accessible!):"
    echo "$exposed" | sed 's/^/       /'
    issues=1
  fi

  return $issues
}

# Scans ONE site and prints findings to stdout.
# Returns 0 if clean, 1 if anything found.
scan_site() {
  local owner="$1" WPP="$2" issues=0
  echo "----------------------------------------------"
  echo "SITE: $WPP"

  local ver; ver="$(run_wp "$owner" "$WPP" core version)"
  if [ -z "$ver" ]; then
    echo "  [?] Could not read version/DB -- skipping."
    return 0
  fi
  echo "  WordPress version: $ver"
  case "$ver" in
    6.8.[6-9]*|6.9.[5-9]*|6.9.[1-9][0-9]*|7.0.[2-9]*|7.[1-9]*|[89].*)
      echo "  [ok] Patched version." ;;
    *)
      echo "  [!] VULNERABLE version -- update to 6.8.6 / 6.9.5 / 7.0.2+"; issues=1 ;;
  esac

  # 1) Account fingerprints
  local bad
  bad="$(run_wp "$owner" "$WPP" user list --fields=ID,user_login,user_email,user_registered,roles --format=csv \
         | grep -Ei 'wp2_[0-9a-f]{6,}|@wp2shell\.invalid')"
  if [ -n "$bad" ]; then
    echo "  [!] wp2shell fingerprint accounts found:"; echo "$bad" | sed 's/^/       /'; issues=1
  fi

  # 2) Admins created after disclosure (15/07/2026)
  local newadm
  newadm="$(run_wp "$owner" "$WPP" user list --role=administrator \
            --fields=ID,user_login,user_email,user_registered --format=csv \
            | awk -F, 'NR>1 && $4>"2026-07-15"{print}')"
  if [ -n "$newadm" ]; then
    echo "  [!] New admins created after disclosure (15/07/2026):"; echo "$newadm" | sed 's/^/       /'; issues=1
  fi

  # 3) Orphaned usermeta / gaps in user-ID sequence
  local orphan
  orphan="$(run_wp "$owner" "$WPP" db query \
    "SELECT COUNT(*) FROM wp_usermeta um LEFT JOIN wp_users u ON um.user_id=u.ID WHERE u.ID IS NULL;" \
    --skip-column-names)"
  [ "${orphan:-0}" -gt 0 ] 2>/dev/null && { echo "  [!] Orphaned usermeta rows: $orphan"; issues=1; }

  # 4) PHP files in uploads
  local phpup
  phpup="$(find "$WPP/wp-content/uploads" -type f -name '*.php' 2>/dev/null)"
  [ -n "$phpup" ] && { echo "  [!] PHP files inside uploads/:"; echo "$phpup" | sed 's/^/       /'; issues=1; }

  # 5) Core checksums (locale-aware, from wp.org)
  local cks
  cks="$(run_wp "$owner" "$WPP" core verify-checksums 2>&1)"
  if echo "$cks" | grep -qi 'Success'; then
    echo "  [ok] Core checksums OK."
  else
    echo "  [!] Core checksums FAILED:"
    echo "$cks" | grep -Ei 'Warning|does not|should not' | sed 's/^/       /'; issues=1
  fi

  # 6) CORE DIFF -- line-by-line with per-file evaluation
  local loc clean
  loc="$(run_wp "$owner" "$WPP" eval 'echo get_locale();')"; loc="${loc:-en_US}"
  clean="$(ensure_clean_core "$ver" "$loc")"

  if [ ! -f "$clean/wp-load.php" ]; then
    echo "  [?] Could not download clean core for diff (version/locale)."
  else
    # List files that differ (modified) or are extra (not in clean core)
    local changed_files extra_files
    mapfile -t changed_files < <(
      diff -rq "$clean" "$WPP" \
        --exclude=wp-content --exclude=wp-config.php \
        --exclude=readme.html --exclude=license.txt 2>/dev/null \
      | grep -vE 'Only in .*/wp-content' \
      | grep '^Files '  \
      | sed "s|Files $clean/\(.*\) and .*|\1|"
    )
    mapfile -t extra_files < <(
      diff -rq "$clean" "$WPP" \
        --exclude=wp-content --exclude=wp-config.php \
        --exclude=readme.html --exclude=license.txt 2>/dev/null \
      | grep -vE 'Only in .*/wp-content' \
      | grep "^Only in $WPP" \
      | while IFS= read -r line; do
          # Format: "Only in /path/to/dir: filename"
          # Extract directory and filename separately
          dir="${line#Only in }";  dir="${dir%%: *}"
          file="${line##*: }"
          # Relative path from WPP root (strip WPP prefix + trailing slash)
          rel_dir="${dir#$WPP}"; rel_dir="${rel_dir#/}"
          if [ -z "$rel_dir" ]; then
            echo "$file"           # file directly in root
          else
            echo "$rel_dir/$file"  # file in subdirectory
          fi
        done
    )

    if [ "${#changed_files[@]}" -eq 0 ] && [ "${#extra_files[@]}" -eq 0 ]; then
      echo "  [ok] Core diff clean -- no modified or extra files."
    else
      echo "  -- Core diff: ${#changed_files[@]} modified, ${#extra_files[@]} extra files --"

      # --- Modified core files: diff -U5 + evaluation -----------------------
      for rel in "${changed_files[@]}"; do
        local orig="$clean/$rel" site_file="$WPP/$rel"
        echo ""
        echo "  ┌─ MODIFIED: $rel"

        # Generate unified diff (5 lines of context)
        local udiff
        udiff="$(diff -U5 "$orig" "$site_file" 2>/dev/null)"

        # Extract only changed lines (+/-) for evaluation
        local added removed
        added="$(echo "$udiff"   | grep '^+' | grep -v '^+++')"
        removed="$(echo "$udiff" | grep '^-' | grep -v '^---')"

        # --- Step 1: Pattern evaluation --------------------------------------
        local verdict=""
        local pattern_matched=0

        # DANGEROUS patterns in ADDED lines (uses global DANGER_PATTERNS)
        if echo "$added" | grep -qiE "$DANGER_PATTERNS"; then
          verdict="DANGER"
          pattern_matched=1
          echo "  │  [!] Assessment (patterns): [DANGER] -- executable/obfuscated pattern found in added lines"
        fi

        # SAFE: only whitespace/comment/version string changes
        if [ "$pattern_matched" -eq 0 ]; then
          local non_trivial
          non_trivial="$(echo "$added" | grep -v '^+[[:space:]]*$' \
                                       | grep -v '^+[[:space:]]*//' \
                                       | grep -v '^+[[:space:]]*/\*' \
                                       | grep -v '^+[[:space:]]*\*' \
                                       | grep -vE '^\+\$wp_version\s*=' \
                                       | grep -vE '^\+\$required_php_version\s*=')"
          if [ -z "$non_trivial" ]; then
            verdict="OK"
            pattern_matched=1
            echo "  │  [ok] Assessment (patterns): [OK] -- only whitespace/comment/version changes"
          fi
        fi

        # --- Step 2: AI evaluation (only when patterns are inconclusive) ------
        if [ "$pattern_matched" -eq 0 ] && [ "$USE_AI" -eq 1 ] && command -v curl >/dev/null 2>&1; then
          echo "  │  [...] Assessment (AI) -- sending diff to Claude API..."
          local ai_prompt ai_response ai_verdict ai_reason
          ai_prompt="You are a WordPress security analyst. Review the following unified diff of a WordPress core file. Respond ONLY with JSON, no other text: {\"verdict\": \"DANGER\" or \"SUSPICIOUS\" or \"OK\", \"reason\": \"one sentence in English\"}. \n\nFile: $rel\nDiff:\n$udiff"
          ai_response="$(curl -sf --max-time 15 --connect-timeout 5 \
            -X POST "https://api.anthropic.com/v1/messages" \
            -H "Content-Type: application/json" \
            -H "anthropic-version: 2023-06-01" \
            -H "x-api-key: ${ANTHROPIC_API_KEY:-}" \
            -d "$(printf '%s' "{\"model\":\"claude-sonnet-4-6\",\"max_tokens\":200,\"messages\":[{\"role\":\"user\",\"content\":$(printf '%s' "$ai_prompt" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')}]}")" \
            2>/dev/null \
            | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d["content"][0]["text"])' 2>/dev/null \
            | python3 -c 'import sys,json; d=json.loads(sys.stdin.read()); print(d["verdict"]+"|||"+d["reason"])' 2>/dev/null)"

          if [ -n "$ai_response" ]; then
            ai_verdict="${ai_response%%|||*}"
            ai_reason="${ai_response##*|||}"
            echo "  │  [AI] Assessment: [$ai_verdict] -- $ai_reason"
            verdict="$ai_verdict"
          else
            echo "  │  [?] Assessment (AI): [FAILED] -- no response, check manually"
            verdict="REVIEW"
          fi
        elif [ "$pattern_matched" -eq 0 ]; then
          echo "  │  [?] Assessment (AI): [SKIPPED] -- AI disabled, check manually"
          verdict="REVIEW"
        fi

        # If DANGER or SUSPICIOUS → flag for the email
        case "$verdict" in DANGER|SUSPICIOUS|REVIEW) issues=1 ;; esac

        # Print diff with prefix for readability
        echo "  │"
        echo "  │  ORIGINAL: $clean/$rel";
        echo "  │  SITE:     $site_file"
        echo "$udiff" | head -80 | sed \
          -e 's/^-/  │  - /' \
          -e 's/^+/  │  + /' \
          -e 's/^@/  │  @ /' \
          -e 's/^[^│]/  │    &/'
        local total_lines; total_lines="$(echo "$udiff" | wc -l)"
        [ "$total_lines" -gt 80 ] && echo "  │  ... ($(( total_lines - 80 )) more lines -- run: diff -U5 \"$clean/$rel\" \"$site_file\")"
        echo "  └──────────────────────────────────────"
      done

      # --- Extra files (not part of clean core) ------------------------------
      for rel in "${extra_files[@]}"; do
        local extra_file="$WPP/$rel"
        echo ""
        echo "  ┌─ EXTRA: $rel"

        # File metadata
        if [ -e "$extra_file" ]; then
          local fsize fdate ftype
          fsize="$(du -sh "$extra_file" 2>/dev/null | cut -f1)"
          fdate="$(stat -c '%y' "$extra_file" 2>/dev/null | cut -d'.' -f1)"
          if [ -d "$extra_file" ]; then
            ftype="DIRECTORY"
          else
            ftype="$(file -b "$extra_file" 2>/dev/null | cut -c1-60)"
          fi
          echo "  │  Size: $fsize  |  Last modified: $fdate"
          echo "  │  Type:  $ftype"
        else
          echo "  │  [!] File not found (deleted between scan and analysis)"
          echo "  └──────────────────────────────────────"
          continue
        fi

        # Directories -- listing only, no content analysis
        if [ -d "$extra_file" ]; then
          echo "  │  Directory listing:"
          ls -la "$extra_file" 2>/dev/null | head -20 | sed 's/^/  │    /'
          echo "  │  [?] Assessment: [DIRECTORY] -- check contents manually"
          echo "  └──────────────────────────────────────"
          continue
        fi

        local ext="${extra_file##*.}"; ext="${ext,,}"

        # ZIP / archives -- contents without extraction
        if [[ "$ext" == "zip" || "$ext" == "gz" || "$ext" == "tar" ]]; then
          echo "  │"
          echo "  │  Archive listing:"
          if command -v unzip >/dev/null 2>&1 && [ "$ext" == "zip" ]; then
            unzip -l "$extra_file" 2>/dev/null | head -30 | sed 's/^/  │    /'
          else
            echo "  │    (unzip not found -- install to enable listing)"
          fi
          echo "  │  [!] Assessment: [REVIEW] -- archive in document root, possible backup with credentials"
          issues=1
          echo "  └──────────────────────────────────────"
          continue
        fi

        # HTML -- show content, no PHP analysis
        if [[ "$ext" == "html" || "$ext" == "htm" ]]; then
          echo "  │"
          echo "  │  Content:"
          cat "$extra_file" 2>/dev/null | head -20 | sed 's/^/  │    /'
          # Google verification files -- known safe pattern
          if grep -qiE 'google-site-verification|google\.com/webmasters' "$extra_file" 2>/dev/null; then
            echo "  │  [ok] Assessment: [OK] -- Google Search Console verification file"
          else
            echo "  │  [?] Assessment: [REVIEW] -- HTML file outside WP structure"
            issues=1
          fi
          echo "  └──────────────────────────────────────"
          continue
        fi

        # PHP / executable files -- full analysis
        # Avoid null bytes: check if binary before reading into variable
        local extra_content=""
        if file "$extra_file" 2>/dev/null | grep -qE 'text|ASCII|UTF'; then
          extra_content="$(head -100 "$extra_file" 2>/dev/null)"
        else
          # Binary file -- extract printable strings only for pattern check
          extra_content="$(strings "$extra_file" 2>/dev/null | head -100)"
          echo "  │  [i] Binary file -- analysing via strings(1)"
        fi

        if echo "$extra_content" | grep -qiE "$DANGER_PATTERNS"; then
          echo "  │  [!] Assessment (patterns): [DANGER] -- executable/obfuscated pattern detected"
          # Show exactly which lines are suspicious
          echo "  │  Suspicious lines:"
          grep -nEi "$DANGER_PATTERNS" "$extra_file" 2>/dev/null | head -10 | sed 's/^/  │    >> /'
          issues=1
        elif echo "$extra_content" | grep -qiE '<\?php'; then
          # PHP without immediately suspicious patterns -> AI
          if [ "$USE_AI" -eq 1 ] && command -v curl >/dev/null 2>&1; then
            echo "  │  [...] Assessment (AI) -- PHP file outside core, waiting for verdict..."
            local ex_prompt ex_resp ex_v ex_r
            ex_prompt="You are a WordPress security analyst. Review this PHP file found in the WordPress directory but NOT part of the official core. Respond ONLY with JSON, no other text: {\"verdict\": \"DANGER\" or \"SUSPICIOUS\" or \"OK\", \"reason\": \"one sentence in English\"}.\n\nFile: $rel\nContent (first 100 lines):\n$extra_content"
            ex_resp="$(curl -sf --max-time 15 --connect-timeout 5 \
              -X POST "https://api.anthropic.com/v1/messages" \
              -H "Content-Type: application/json" \
              -H "anthropic-version: 2023-06-01" \
              -H "x-api-key: ${ANTHROPIC_API_KEY:-}" \
              -d "$(printf '%s' "{\"model\":\"claude-sonnet-4-6\",\"max_tokens\":200,\"messages\":[{\"role\":\"user\",\"content\":$(printf '%s' "$ex_prompt" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')}]}")" \
              2>/dev/null \
              | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d["content"][0]["text"])' 2>/dev/null \
              | python3 -c 'import sys,json; d=json.loads(sys.stdin.read()); print(d["verdict"]+"|||"+d["reason"])' 2>/dev/null)"
            if [ -n "$ex_resp" ]; then
              ex_v="${ex_resp%%|||*}"; ex_r="${ex_resp##*|||}"
              echo "  │  [AI] Assessment: [$ex_v] -- $ex_r"
              case "$ex_v" in DANGER|SUSPICIOUS) issues=1 ;; esac
            else
              echo "  │  [?] Assessment (AI): [FAILED] -- check manually"
              issues=1
            fi
          else
            echo "  │  [?] Assessment: [REVIEW] -- PHP outside core, AI disabled"
            issues=1
          fi
        else
          echo "  │  [ok] Assessment (patterns): [OK] -- no PHP or suspicious code"
        fi

        # Print file content
        echo "  │"
        echo "  │  Content (first 40 lines):"
        head -40 "$extra_file" 2>/dev/null | sed 's/^/  │    /'
        local ex_lines; ex_lines="$(wc -l < "$extra_file" 2>/dev/null)"
        [ "${ex_lines:-0}" -gt 40 ] && echo "  │  ... ($(( ex_lines - 40 )) more lines -- path: $extra_file)"
        echo "  └──────────────────────────────────────"
      done
    fi
  fi

  # 7) Recently modified core PHP (newer than 15/07/2026)
  local rec
  rec="$(find "$WPP/wp-admin" "$WPP/wp-includes" -name '*.php' -newermt '2026-07-15' 2>/dev/null \
         -printf '%TY-%Tm-%Td %TH:%TM  %p\n' | head -30)"
  [ -n "$rec" ] && { echo "  [?] Core PHP modified after 15/07/2026:"; echo "$rec" | sed 's/^/       /'; }

  # 8) Extended file scan: PHP/JS/HTML/htaccess/images/backups
  scan_files "$WPP" || issues=1

  return $issues
}

# --- Main loop: per user ----------------------------------------------------
mapfile -t USERS < <(ls -1 "$USERS_DIR" 2>/dev/null)

for user in "${USERS[@]}"; do
  conf="$USERS_DIR/$user/user.conf"
  [ -f "$conf" ] || continue

  # Client email from Hestia CONTACT field
  contact="$(grep -oP "CONTACT='\K[^']+" "$conf")"

  # WP installs for this user
  mapfile -t SITES < <(find "/home/$user/web" -maxdepth 4 -name wp-load.php -type f 2>/dev/null \
                       | xargs -r -n1 dirname | sort -u)
  [ "${#SITES[@]}" -eq 0 ] && continue

  echo "===================================================================="
  echo "USER: $user  ->  $contact  (${#SITES[@]} WP sites)"

  body_file="$(mktemp)"
  domains=""
  user_issues=0

  {
    echo "wp2shell security scan"
    echo "User: $user"
    echo "Server: $(hostname)"
    echo "Date: $(date '+%Y-%m-%d %H:%M')"
    echo
  } >> "$body_file"

  for WPP in "${SITES[@]}"; do
    dom="$(basename "$(dirname "$(dirname "$WPP")")")"   # /home/u/web/<domain>/public_html
    domains="${domains:+$domains, }$dom"
    if scan_site "$user" "$WPP" >> "$body_file"; then :; else user_issues=1; fi
    echo >> "$body_file"
  done

  {
    echo "----------------------------------------------"
    if [ "$user_issues" -eq 1 ]; then
      echo "SUMMARY: potential indicators found -- review required."
    else
      echo "SUMMARY: no direct wp2shell indicators found."
    fi
    echo
    echo "More info: https://wp2shell.com"
    echo "-- BytesPulse security scan (automated)"
  } >> "$body_file"

  # Send or preview
  if [ "$SEND_ONLY_IF_ISSUES" -eq 1 ] && [ "$user_issues" -eq 0 ]; then
    echo "  (clean -- email not sent, SEND_ONLY_IF_ISSUES=1)"
    rm -f "$body_file"; continue
  fi
  if [ -z "$contact" ]; then
    echo "  [?] No CONTACT email found for $user -- skipping send."
    rm -f "$body_file"; continue
  fi

  subject="${MAIL_SUBJECT/\%DOMAINS\%/$domains}"

  if [ "$DRY_RUN" -eq 1 ]; then
    echo "  --- DRY_RUN: email NOT sent. Preview: ---"
    echo "  To: $contact"
    echo "  Subject: $subject"
    echo "  ----------------------------------------------------"
    sed 's/^/  | /' "$body_file"
  else
    {
      echo "From: $MAIL_FROM"
      echo "To: $contact"
      echo "Subject: $subject"
      echo "Content-Type: text/plain; charset=UTF-8"
      echo
      cat "$body_file"
    } | "$SENDMAIL" -t -f "$MAIL_FROM"
    echo "  [sent] -> $contact"
  fi

  # Append to full report file (if requested)
  if [ -n "$REPORT_FILE" ]; then
    {
      echo ""
      echo "=================================================================="
      echo " USER: $user   |   $contact"
      echo "=================================================================="
      cat "$body_file"
    } >> "$REPORT_FILE"
  fi

  rm -f "$body_file"
done

echo "===================================================================="
echo "Done. DRY_RUN=$DRY_RUN (1=preview only, 0=send)."

if [ -n "$REPORT_FILE" ]; then
  {
    echo ""
    echo "=================================================================="
    echo " Scan completed -- $(date '+%Y-%m-%d %H:%M:%S')"
    echo " DRY_RUN=$DRY_RUN | AI=$([ "$USE_AI" -eq 1 ] && echo 'ENABLED' || echo 'DISABLED')"
    echo "=================================================================="
  } >> "$REPORT_FILE"
  echo ""
  echo "  Report saved: $REPORT_FILE"
  echo "  View:         less -R \"$REPORT_FILE\""
  echo "  Filter [!]:   grep '\[!\|DANGER' \"$REPORT_FILE\""
fi
