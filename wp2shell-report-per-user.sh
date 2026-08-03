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
# Date threshold for "recently modified" checks (wp2shell disclosure date).
# Change to narrow or widen the window. Format: YYYY-MM-DD
SINCE_DATE="2026-07-15"
WP="wp"

SEND_ONLY_IF_ISSUES=0                    # 1 = email only if issues found
MAIL_FROM="security@$(hostname -f 2>/dev/null || hostname)"
MAIL_SUBJECT="[wp2shell] Security scan report -- %DOMAINS%"
SENDMAIL="/usr/sbin/sendmail"


# ---------------------------------------------------------------------------

[ "$(id -u)" -eq 0 ] || { echo "Run as root (sudo)."; exit 1; }
command -v "$WP" >/dev/null 2>&1 || { echo "wp-cli not found."; exit 1; }
mkdir -p "$CORE_CACHE"

# Severity colors
RED=$'\e[31m'; RED_BOLD=$'\e[1;31m'; YEL=$'\e[33m'
BLU=$'\e[34m'; GRN=$'\e[32m'; GRY=$'\e[90m'; RST=$'\e[0m'

# ---------------------------------------------------------------------------
# Unified output system -- same structure for terminal, email, and report.
# Terminal gets colors, email/report get plain text.
#
# Usage:
#   finding_start CRITICAL "Title of finding"
#   finding_file  "path/to/file.php"
#   finding_line  "Line 42: eval(base64_decode(...))"
#   finding_end
#
# Each finding renders as:
#   [CRITICAL] Title of finding
#              File: path/to/file.php
#              > Line 42: eval(base64_decode(...))
# ---------------------------------------------------------------------------
SITE_FINDINGS=""          # accumulates plain-text findings for email
_FINDING_SEV=""           # current finding severity label
_FINDING_TITLE=""         # current finding title
_FINDING_LINES=""         # current finding detail lines

# Severity color map (terminal only)
_sev_color() {
  case "$1" in
    CRITICAL) printf '%s' "$RED_BOLD" ;;
    HIGH)     printf '%s' "$RED"      ;;
    MEDIUM)   printf '%s' "$YEL"      ;;
    LOW)      printf '%s' "$BLU"      ;;
    INFO)     printf '%s' "$GRY"      ;;
    OK)       printf '%s' "$GRN"      ;;
    *)        printf '%s' "$RST"      ;;
  esac
}

finding_start() {
  _FINDING_SEV="$1"
  _FINDING_TITLE="$2"
  _FINDING_LINES=""
}

finding_file() {
  _FINDING_LINES="${_FINDING_LINES}             File: $1\n"
}

finding_line() {
  # Strip non-printable/binary chars, truncate to 120 chars
  local line; line="$(printf '%s' "$1" | tr -cd '[:print:]' | cut -c1-120)"
  [ -n "$line" ] && _FINDING_LINES="${_FINDING_LINES}               > $line\n"
}

finding_end() {
  local col; col="$(_sev_color "$_FINDING_SEV")"
  local label; label="$(printf '%-10s' "[$_FINDING_SEV]")"

  # Terminal output (with color)
  printf '%s%s%s %s\n' "$col" "$label" "$RST" "$_FINDING_TITLE"
  [ -n "$_FINDING_LINES" ] && printf '%b' "$_FINDING_LINES"

  # Accumulate plain text for email (no color codes)
  SITE_FINDINGS="${SITE_FINDINGS}  $label $_FINDING_TITLE\n"
  [ -n "$_FINDING_LINES" ] && SITE_FINDINGS="${SITE_FINDINGS}${_FINDING_LINES}"
  SITE_FINDINGS="${SITE_FINDINGS}\n"

  _FINDING_SEV=""; _FINDING_TITLE=""; _FINDING_LINES=""
}

finding_ok() {
  # Single-line OK message (no file/detail needed)
  printf '%s%-10s%s %s\n' "$GRN" "[OK]" "$RST" "$1"
}

finding_info() {
  printf '%s%-10s%s %s\n' "$GRY" "[INFO]" "$RST" "$1"
}

echo ""
echo "+------------------------------------------------------+"
echo "|        wp2shell Security Scanner -- BytesPulse      |"
echo "+------------------------------------------------------+"
echo ""

# --- Q1: Send emails ---
DRY_RUN=1
echo "+------------------------------------------------------+"
echo "|           EMAIL REPORTS                             |"
echo "+------------------------------------------------------+"
echo "  Emails are sent to the CONTACT address stored in    "
echo "  HestiaCP for each user.                             "
echo ""
read -r -p "  Send real emails to clients? [y/N] " email_choice </dev/tty
case "${email_choice,,}" in
  y|yes)
    DRY_RUN=0
    echo "  -> Emails WILL be sent."
    ;;
  *)
    DRY_RUN=1
    echo "  -> DRY RUN -- emails will be previewed only."
    ;;
esac
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
      echo "=================================================================="
    } > "$REPORT_FILE"
    ;;
  *)
    REPORT_FILE=""
    echo "  -> Report will not be saved."
    ;;
esac
echo ""

# --- Q3: Date threshold ---
echo "+------------------------------------------------------+"
echo "|           DATE THRESHOLD                            |"
echo "+------------------------------------------------------+"
echo "  Default: $SINCE_DATE (wp2shell disclosure date)"
read -r -p "  Use a different date? Leave blank to keep default [YYYY-MM-DD]: " date_choice </dev/tty
if [[ "$date_choice" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
  SINCE_DATE="$date_choice"
  echo "  -> Using custom date: $SINCE_DATE"
else
  echo "  -> Using default: $SINCE_DATE"
fi
echo ""

# TIER 1 -- almost always malicious regardless of context
DANGER_HIGH='eval\s*\(\s*\$_|eval\s*\(\s*base64_decode\s*\(|eval\s*\(\s*gz|eval\s*\(\s*str_rot13|assert\s*\(\s*\$_|shell_exec\s*\(|passthru\s*\(|proc_open\s*\(|popen\s*\(|pcntl_exec\s*\(|create_function\s*\(|move_uploaded_file\s*\(\s*\$_|php://input'

# TIER 2 -- only suspicious when combined with user input on same line
DANGER_WITH_INPUT='(eval|assert|base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13)\s*\(.*\$_(POST|GET|REQUEST|COOKIE|SERVER|FILES)'

# TIER 3 -- broad scan, used only for low-priority informational check
DANGER_PATTERNS='eval\s*\(|base64_decode\s*\(|gzinflate\s*\(|gzuncompress\s*\(|gzdecode\s*\(|assert\s*\(|shell_exec\s*\(|passthru\s*\(|proc_open\s*\(|popen\s*\(|pcntl_exec\s*\(|php://input|create_function\s*\(|preg_replace.*\/e[^a-z]|move_uploaded_file\s*\(|str_rot13\s*\('

# External C2 / exfiltration domains to flag inside PHP/JS/HTML
C2_PATTERNS='pastebin\.com/raw|gist\.github\.com/raw|raw\.githubusercontent\.com/|t\.me/|discord(app)?\.com/api/webhooks|ngrok\.io|ngrok-free\.app|tinyurl\.com|bit\.ly/[a-zA-Z0-9]|cdn\.discordapp\.com'

# Known webshell SHA256 hashes (subset of most common shells)
# Source: https://github.com/Neo23x0/signature-base + manual curation
KNOWN_SHELLS_FILE="/root/wp2shell-known-shells.sha256"

# Download/refresh known shells hash list (once per day)
fetch_known_shells() {
  local url="https://raw.githubusercontent.com/BytesPulse-OE/wp2shell-Hestia-Scanner/main/known_shells.sha256"
  local age=99999
  [ -f "$KNOWN_SHELLS_FILE" ] && age=$(( $(date +%s) - $(stat -c %Y "$KNOWN_SHELLS_FILE") ))
  if [ ! -f "$KNOWN_SHELLS_FILE" ] || [ "$age" -gt 86400 ]; then
    echo "  Fetching known webshell hash database..."
    curl -sf --max-time 10 --connect-timeout 5 "$url" -o "$KNOWN_SHELLS_FILE" 2>/dev/null \
      || echo "  [INFO] Could not fetch hash DB -- SHA256 check skipped."
  fi
}
fetch_known_shells

# Check a single file against known shell hashes
# Returns: shell name if matched, empty string otherwise
check_known_shell() {
  local f="$1"
  [ -f "$KNOWN_SHELLS_FILE" ] || return
  local hash; hash="$(sha256sum "$f" 2>/dev/null | cut -d' ' -f1)"
  [ -z "$hash" ] && return
  grep -i "^$hash" "$KNOWN_SHELLS_FILE" 2>/dev/null | head -1 | awk '{print $2}'
}

# ---------------------------------------------------------------------------
# Risk scoring -- accumulate points per site, print summary at end of scan_site
# Usage: score_add <points> <reason>
# Call score_reset at start of each site, score_report at end.
# ---------------------------------------------------------------------------
SITE_SCORE=0
SITE_SCORE_LOG=""

score_reset() {
  SITE_SCORE=0
  SITE_SCORE_LOG=""
  SITE_FINDINGS=""
}

score_add() {
  local pts="$1" reason="$2"
  SITE_SCORE=$(( SITE_SCORE + pts ))
  [ "$SITE_SCORE" -gt 100 ] && SITE_SCORE=100
  SITE_SCORE_LOG="${SITE_SCORE_LOG}  $(printf '%+d' "$pts")  $reason\n"
}

score_report() {
  local label color
  if   [ "$SITE_SCORE" -ge 81 ]; then label="COMPROMISED";    color="$RED_BOLD"
  elif [ "$SITE_SCORE" -ge 61 ]; then label="HIGH RISK";      color="$RED"
  elif [ "$SITE_SCORE" -ge 41 ]; then label="MEDIUM RISK";    color="$YEL"
  elif [ "$SITE_SCORE" -ge 21 ]; then label="LOW RISK";       color="$BLU"
  else                                 label="PROBABLY CLEAN"; color="$GRN"
  fi
  echo ""
  echo "  +------------------------------------------+"
  printf "  |  RISK SCORE: %s%-6s%s  %-17s  |\n" "$color" "$SITE_SCORE/100" "$RST" "$label"
  echo "  +------------------------------------------+"
  if [ -n "$SITE_SCORE_LOG" ]; then
    printf '%b' "$SITE_SCORE_LOG" | while IFS= read -r line; do
      [ -n "$line" ] && echo "  $line"
    done
  fi
  echo ""
}

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

  # A) EXTRA PHP EXTENSIONS -- files Apache/Nginx executes as PHP
  #    (.php7 .phtml .phar .php5 .shtml) -- never belong in a normal WP site
  local xphp
  xphp="$(find "$WPP" -type f \( \
            -name '*.php7' -o -name '*.phtml' -o -name '*.phar' \
            -o -name '*.php5' -o -name '*.shtml' \
          \) 2>/dev/null)"
  if [ -n "$xphp" ]; then
    finding_start HIGH "Extra PHP-executable extension found (.php7/.phtml/.phar/.php5)"
    while IFS= read -r f; do finding_file "${f#$WPP/}"; done <<< "$xphp"
    finding_end
    score_add 10 "Executable non-.php extension file(s)"; issues=1
  fi

  # A2) SHA256 -- known webshell hash match (zero false positives)
  if [ -f "$KNOWN_SHELLS_FILE" ]; then
    while IFS= read -r f; do
      local shell_name; shell_name="$(check_known_shell "$f")"
      if [ -n "$shell_name" ]; then
        finding_start CRITICAL "Known webshell -- SHA256 hash match"
        finding_file "${f#$WPP/}"
        finding_line "Identified as: $shell_name"
        finding_end
        score_add 25 "Known webshell: $shell_name"; issues=1
      fi
    done < <(find "$WPP" -type f -name '*.php' 2>/dev/null)
  fi

  # B) PHP -- recently modified AND containing dangerous patterns (tiered)
  #    TIER 1: always suspicious (eval($_POST, shell_exec, etc.)
  #    TIER 2: suspicious only with user input on same line
  #    Both exclude comments to reduce false positives.
  local php_combined php_hit_count=0
  mapfile -t php_combined < <(
    find "$CONTENT" "$WPP"/*.php 2>/dev/null \
      -type f -name '*.php' -newermt "$SINCE_DATE" 2>/dev/null \
    | grep -vE '/(wp-includes|wp-admin)/' \
    | while IFS= read -r f; do
        # Tier 1 + Tier 2, skip comment lines
        hits="$(grep -nEi "$DANGER_HIGH|$DANGER_WITH_INPUT" "$f" 2>/dev/null \
          | grep -vE '^\s*[0-9]+:\s*[/*#]|//[^$]*$' | head -3)"
        [ -n "$hits" ] && printf '%s\n%s\n---\n' "$f" "$hits"
      done
  )
  if [ ${#php_combined[@]} -gt 0 ]; then
    local cur_file=""
    for line in "${php_combined[@]}"; do
      if [ "$line" = "---" ]; then
        [ -n "$cur_file" ] && finding_end
        cur_file=""
      elif [ -z "$cur_file" ]; then
        cur_file="$line"
        php_hit_count=$(( php_hit_count + 1 ))
        if echo "$cur_file" | grep -q '/uploads/'; then
          finding_start CRITICAL "PHP in uploads/ with dangerous pattern"
        else
          finding_start HIGH "PHP modified after $SINCE_DATE with dangerous pattern"
        fi
        finding_file "${cur_file#$WPP/}"
        issues=1
        # Diminishing returns: first 3 files score, rest don't
        if [ "$php_hit_count" -le 3 ]; then
          score_add 15 "PHP modified after $SINCE_DATE + dangerous pattern"
        fi
      else
        finding_line "$line"
      fi
    done
  fi

  # B2) TIER 3 broad patterns NOT recently modified -- informational only
  local php_old_sig
  php_old_sig="$(grep -RIlE --include='*.php' "$DANGER_PATTERNS" \
      "$CONTENT" "$WPP"/*.php 2>/dev/null \
    | grep -vE '/(wp-includes|wp-admin)/' \
    | while IFS= read -r f; do
        find "$f" -newermt "$SINCE_DATE" 2>/dev/null | grep -q . && continue
        echo "$f"
      done \
    | head -30)"
  if [ -n "$php_old_sig" ]; then
    finding_start LOW "PHP with broad patterns -- NOT recently modified (likely false positives)"
    while IFS= read -r f; do [ -n "$f" ] && finding_file "${f#$WPP/}"; done <<< "$php_old_sig"
    finding_end
  fi

  # C) .HTACCESS -- dangerous directives (distinguishes protective vs malicious)
  local htaccess_files
  mapfile -t htaccess_files < <(find "$WPP" -name '.htaccess' -type f 2>/dev/null)
  for hta in "${htaccess_files[@]}"; do
    local hta_danger
    hta_danger="$(grep -inE \
      'AddType\s+application/x-httpd-php|auto_prepend_file|auto_append_file|php_value\s+auto_prepend|RewriteRule.*uploads.*\.(php|phtml|phar)|RewriteRule.*http[s]?://' \
      "$hta" 2>/dev/null)"
    if [ -n "$hta_danger" ]; then
      finding_start HIGH "Dangerous .htaccess directive"
      finding_file "${hta#$WPP/}"
      while IFS= read -r line; do finding_line "$line"; done <<< "$hta_danger"
      finding_end
      score_add 10 "Dangerous .htaccess: ${hta#$WPP/}"; issues=1
    fi

    local hta_protective
    hta_protective="$(grep -inE 'php_flag\s+engine\s+off' "$hta" 2>/dev/null)"
    [ -n "$hta_protective" ] && finding_ok "Protective directive in ${hta#$WPP/} (php_flag engine off)"

    local hta_phpflag
    hta_phpflag="$(grep -inE 'php_flag|php_value' "$hta" 2>/dev/null \
                  | grep -ivE 'php_flag\s+engine\s+off')"
    if [ -n "$hta_phpflag" ]; then
      finding_start LOW "php_flag/php_value directive -- check context"
      finding_file "${hta#$WPP/}"
      while IFS= read -r line; do finding_line "$line"; done <<< "$hta_phpflag"
      finding_end
    fi
  done

  # D) JS/HTML -- recently modified AND matching malicious patterns (combined)
  local js_combined
  js_combined="$(
    find "$CONTENT" -type f \( -name '*.js' -o -name '*.html' -o -name '*.htm' \) \
      -newermt "$SINCE_DATE" 2>/dev/null \
    | while IFS= read -r f; do
        hits="$(grep -nEi \
          'eval\s*\(\s*atob\s*\(|eval\s*\(\s*unescape\s*\(|document\.write\s*\(\s*unescape|String\.fromCharCode\s*\([0-9,\s]{40,}\)' \
          "$f" 2>/dev/null | head -2)"
        [ -n "$hits" ] && echo "$f" && echo "$hits" | sed 's/^/       >> /'
      done | head -60
  )"
  if [ -n "$js_combined" ]; then
    finding_start MEDIUM "JS/HTML modified after $SINCE_DATE with obfuscation pattern"
    while IFS= read -r line; do [ -n "$line" ] && finding_line "$line"; done <<< "$js_combined"
    finding_end
    score_add 10 "JS/HTML obfuscation pattern in recently modified file"; issues=1
  fi

  # D2) External C2 / exfiltration URLs inside PHP, JS, HTML
  # Exclude lines that are pure comments (@see, //, #, *)
  local c2_hits
  c2_hits="$(grep -RInE --include='*.php' --include='*.js' --include='*.html' --include='*.htm' \
    "$C2_PATTERNS" "$WPP" 2>/dev/null \
    | grep -vE '@see\s+https?://|[[:space:]]*//' \
    | grep -vE '^\S+:[0-9]+:\s*(\/\/|\*|#)' \
    | cut -c1-120 \
    | head -10)"
  if [ -n "$c2_hits" ]; then
    finding_start CRITICAL "External C2/exfiltration URL in source files"
    while IFS= read -r line; do [ -n "$line" ] && finding_line "$line"; done <<< "$c2_hits"
    finding_end
    score_add 15 "External C2/exfiltration URL"; issues=1
  fi

  # E) .htaccess modified after SINCE_DATE
  local new_hta
  new_hta="$(find "$WPP" -name '.htaccess' -newermt "$SINCE_DATE" \
              -printf '%TY-%Tm-%Td %TH:%TM  %p\n' 2>/dev/null)"
  if [ -n "$new_hta" ]; then
    finding_start MEDIUM ".htaccess modified after $SINCE_DATE"
    while IFS= read -r line; do [ -n "$line" ] && finding_line "$line"; done <<< "$new_hta"
    finding_end
    score_add 5 ".htaccess modified after $SINCE_DATE"; issues=1
  fi

  # F) IMAGES WITH PHP PAYLOAD -- polyglot files
  local img_php
  img_php="$(grep -RIla --include='*.jpg' --include='*.jpeg' \
               --include='*.png' --include='*.gif' --include='*.ico' \
               --include='*.webp' \
               '<?php' "$CONTENT/uploads" 2>/dev/null | head -20)"
  if [ -n "$img_php" ]; then
    finding_start CRITICAL "Image file containing PHP code (polyglot payload)"
    while IFS= read -r f; do finding_file "${f#$WPP/}"; done <<< "$img_php"
    finding_end
    score_add 25 "Polyglot image with PHP payload"; issues=1
  fi

  # G) EXPOSED BACKUP/CONFIG files -- web-accessible
  local exposed
  exposed="$(find "$WPP" -maxdepth 2 -type f \( \
               -name 'wp-config.php.bak' -o -name 'wp-config.old' \
               -o -name 'wp-config.php~' -o -name '*.sql' \
               -o -name '*.sql.gz' -o -name 'database.sql' \
             \) 2>/dev/null)"
  if [ -n "$exposed" ]; then
    finding_start MEDIUM "Exposed backup/config file -- web-accessible"
    while IFS= read -r f; do finding_file "${f#$WPP/}"; done <<< "$exposed"
    finding_end
    score_add 5 "Exposed backup/config file(s)"; issues=1
  fi

  return $issues
}

# Scans ONE site and prints findings to stdout.
# Returns 0 if clean, 1 if anything found.
scan_site() {
  local owner="$1" WPP="$2" issues=0
  score_reset

  echo ""
  echo "======================================================================"
  echo "  SITE: $WPP"
  echo "======================================================================"

  local ver; ver="$(run_wp "$owner" "$WPP" core version)"
  if [ -z "$ver" ]; then
    finding_info "Could not read WordPress version / DB -- skipping site."
    return 0
  fi
  finding_info "WordPress $ver"

  case "$ver" in
    6.8.[6-9]*|6.9.[5-9]*|6.9.[1-9][0-9]*|7.0.[2-9]*|7.[1-9]*|[89].*)
      finding_ok "Patched version" ;;
    *)
      finding_start HIGH "Vulnerable WordPress version -- update immediately"
      finding_line "Installed: $ver"
      finding_line "Safe versions: 6.8.6 / 6.9.5 / 7.0.2 or newer"
      finding_end
      score_add 20 "Vulnerable WordPress version ($ver)"; issues=1 ;;
  esac

  # 1) Account fingerprints
  local bad
  bad="$(run_wp "$owner" "$WPP" user list \
    --fields=ID,user_login,user_email,user_registered,roles --format=csv 2>/dev/null \
    | grep -Ei 'wp2_[0-9a-f]{6,}|@wp2shell\.invalid')"
  if [ -n "$bad" ]; then
    finding_start CRITICAL "wp2shell fingerprint account found"
    while IFS= read -r line; do [ -n "$line" ] && finding_line "$line"; done <<< "$bad"
    finding_end
    score_add 40 "wp2shell fingerprint account"; issues=1
  else
    finding_ok "No wp2shell fingerprint accounts"
  fi

  # 2) New admins post-disclosure
  local newadm
  newadm="$(run_wp "$owner" "$WPP" user list --role=administrator \
            --fields=ID,user_login,user_email,user_registered --format=csv 2>/dev/null \
            | awk -F, 'NR>1 && $4>"2026-07-15"{print}')"
  if [ -n "$newadm" ]; then
    finding_start MEDIUM "Administrator created after disclosure date (15/07/2026)"
    while IFS= read -r line; do [ -n "$line" ] && finding_line "$line"; done <<< "$newadm"
    finding_end
    score_add 10 "New admin after disclosure"; issues=1
  fi

  # 3) Orphaned usermeta
  local orphan
  orphan="$(run_wp "$owner" "$WPP" db query \
    "SELECT COUNT(*) FROM wp_usermeta um LEFT JOIN wp_users u ON um.user_id=u.ID WHERE u.ID IS NULL;" \
    --skip-column-names)"
  if [ "${orphan:-0}" -gt 0 ] 2>/dev/null; then
    finding_start MEDIUM "Orphaned usermeta rows -- traces of deleted rogue user"
    finding_line "$orphan rows in wp_usermeta with no matching user"
    finding_end
    score_add 5 "Orphaned usermeta ($orphan rows)"; issues=1
  fi

  # 4) PHP files in uploads
  local phpup
  phpup="$(find "$WPP/wp-content/uploads" -type f -name '*.php' 2>/dev/null)"
  if [ -n "$phpup" ]; then
    finding_start CRITICAL "PHP file(s) inside uploads/ -- must not exist here"
    while IFS= read -r f; do finding_file "${f#$WPP/}"; done <<< "$phpup"
    finding_end
    score_add 30 "PHP file(s) inside uploads/"; issues=1
  else
    finding_ok "No PHP files in uploads/"
  fi

  # 5) Core checksums
  local cks
  cks="$(run_wp "$owner" "$WPP" core verify-checksums 2>&1)"
  if echo "$cks" | grep -qi 'Success'; then
    finding_ok "Core checksums OK"
  else
    finding_start HIGH "Core checksum failure -- modified or extra core files"
    while IFS= read -r line; do
      finding_line "$line"
    done < <(echo "$cks" | grep -Ei 'Warning|does not|should not')
    finding_end
    score_add 5 "Core checksum failure"; issues=1
  fi


  # 6) CORE DIFF -- line-by-line with per-file evaluation
  local loc clean
  loc="$(run_wp "$owner" "$WPP" eval 'echo get_locale();')"; loc="${loc:-en_US}"
  clean="$(ensure_clean_core "$ver" "$loc")"

  if [ ! -f "$clean/wp-load.php" ]; then
    finding_info "Could not download clean core for diff (version/locale) -- skipping diff."
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
      finding_ok "Core diff clean -- no modified or extra files"
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

        # DANGEROUS patterns in ADDED lines -- use TIER 1 (high confidence only)
        if echo "$added" | grep -qiE "$DANGER_HIGH"; then
          verdict="DANGER"
          pattern_matched=1
          finding_start CRITICAL "Core file modified with dangerous pattern"
          finding_file "$rel"
          finding_line "Changed lines contain: eval / base64_decode / shell_exec or similar"
          finding_end
          score_add 20 "Core file modified with dangerous pattern: $rel"
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
            finding_ok "Core file change: whitespace/comment/version only"
          fi
        fi

        # --- Step 2: inconclusive -- flag for manual review -------------------
        if [ "$pattern_matched" -eq 0 ]; then
          finding_start MEDIUM "Core file changed -- inconclusive, review manually"
          finding_file "$rel"
          finding_end
          verdict="REVIEW"
        fi

        # If DANGER or SUSPICIOUS or REVIEW -- flag for the email
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
          finding_info "Extra file not found (deleted between scan and analysis)"
          echo "  └──────────────────────────────────────"
          continue
        fi

        # Directories -- listing only, no content analysis
        if [ -d "$extra_file" ]; then
          echo "  │  Directory listing:"
          ls -la "$extra_file" 2>/dev/null | head -20 | sed 's/^/  │    /'
          finding_start MEDIUM "Extra directory outside WordPress core -- check contents manually"
          finding_file "$rel"
          finding_end
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
          finding_start MEDIUM "Archive file in document root -- possible backup with credentials"
          finding_file "$rel"
          finding_end
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
            finding_ok "Google Search Console verification file -- OK"
          else
            finding_start MEDIUM "HTML file outside WordPress structure -- review"
            finding_file "$rel"
            finding_end
            issues=1
          fi
          echo "  └──────────────────────────────────────"
          continue
        fi

        # PHP / executable files -- full analysis
        # Avoid null bytes: check if binary before reading into variable
        local extra_content="" is_binary=0
        if file "$extra_file" 2>/dev/null | grep -qE 'text|ASCII|UTF'; then
          extra_content="$(head -100 "$extra_file" 2>/dev/null)"
        else
          # Binary file -- use strings only for internal pattern check, never display raw content
          extra_content="$(strings "$extra_file" 2>/dev/null | head -100)"
          is_binary=1
        fi

        if echo "$extra_content" | grep -qiE "$DANGER_PATTERNS"; then
          finding_start CRITICAL "Extra file with dangerous pattern"
          finding_file "$rel"
          # Only show matching lines if text file -- binary lines are already sanitized by finding_line()
          if [ "$is_binary" -eq 0 ]; then
            while IFS= read -r line; do finding_line "$line"; done < \
              <(grep -nEi "$DANGER_PATTERNS" "$extra_file" 2>/dev/null | head -5 | cut -c1-120)
          else
            finding_line "[binary file -- dangerous pattern detected via strings analysis]"
          fi
          finding_end
          score_add 15 "Extra PHP file with dangerous pattern: $rel"; issues=1
        elif echo "$extra_content" | grep -qiE '<\?php'; then
          finding_start MEDIUM "Extra PHP file outside WordPress core -- review manually"
          finding_file "$rel"
          finding_end
          score_add 5 "Extra PHP file outside core: $rel"; issues=1
        else
          finding_ok "Extra file: no PHP or suspicious code"
        fi

        # Print file content -- text files only, truncated and sanitized
        echo "  │"
        if [ "$is_binary" -eq 1 ]; then
          echo "  │  [binary file -- content not displayed]"
        else
          echo "  │  Content (first 20 lines):"
          head -20 "$extra_file" 2>/dev/null \
            | tr -cd '[:print:]\n' \
            | sed 's/^/  │    /'
          local ex_lines; ex_lines="$(wc -l < "$extra_file" 2>/dev/null)"
          [ "${ex_lines:-0}" -gt 20 ] && echo "  │  ... ($(( ex_lines - 20 )) more lines -- path: $extra_file)"
        fi
        echo "  └──────────────────────────────────────"
      done
    fi
  fi

  # 7) Recently modified core PHP (newer than 15/07/2026)
  local rec
  rec="$(find "$WPP/wp-admin" "$WPP/wp-includes" -name '*.php' -newermt '2026-07-15' 2>/dev/null \
         -printf '%TY-%Tm-%Td %TH:%TM  %p\n' | head -30)"
  if [ -n "$rec" ]; then
    finding_start MEDIUM "Core PHP files modified after 15/07/2026 -- verify these are from WordPress update"
    while IFS= read -r line; do [ -n "$line" ] && finding_line "$line"; done <<< "$rec"
    finding_end
  fi

  # 8) WP Options -- check for tampered critical options
  echo "  -- WP Options check --"
  local opt_siteurl opt_home opt_upload opt_prepend
  opt_siteurl="$(run_wp "$owner" "$WPP" option get siteurl 2>/dev/null)"
  opt_home="$(run_wp "$owner" "$WPP" option get home 2>/dev/null)"
  opt_upload="$(run_wp "$owner" "$WPP" option get upload_path 2>/dev/null)"
  opt_prepend="$(run_wp "$owner" "$WPP" option get auto_prepend_file 2>/dev/null)"

  # Flag upload_path if set outside wp-content/uploads
  if [ -n "$opt_upload" ] && ! echo "$opt_upload" | grep -qE 'wp-content/uploads|^$'; then
    finding_start HIGH "WP option upload_path redirected outside wp-content/uploads"
    finding_line "upload_path = $opt_upload"
    finding_end
    score_add 15 "upload_path tampered"; issues=1
  fi
  if [ -n "$opt_prepend" ]; then
    finding_start CRITICAL "auto_prepend_file set in WP options -- injects PHP into every request"
    finding_line "auto_prepend_file = $opt_prepend"
    finding_end
    score_add 25 "auto_prepend_file in wp_options"; issues=1
  fi
  # Flag siteurl/home pointing to unexpected external domain
  # HestiaCP path: /home/<user>/web/<domain>/public_html
  # Strip /public_html to get the domain directory
  local expected_domain; expected_domain="$(basename "$(dirname "$WPP")")"
  # Strip protocol from siteurl before comparing (https://example.com -> example.com)
  local siteurl_domain; siteurl_domain="$(echo "$opt_siteurl" | sed 's|https\?://||' | cut -d'/' -f1)"
  if [ -n "$siteurl_domain" ] && ! echo "$siteurl_domain" | grep -qi "$expected_domain"; then
    finding_start HIGH "siteurl does not match site directory"
    finding_line "siteurl:  $opt_siteurl"
    finding_line "Expected: $expected_domain"
    finding_end
    score_add 10 "siteurl mismatch"; issues=1
  else
    finding_ok "WP options look clean"
  fi

  # 9) Cron persistence -- system crontabs for this site's owner
  echo "  -- Cron persistence check --"
  local cron_hits
  cron_hits="$(crontab -u "$owner" -l 2>/dev/null \
    | grep -vE '^\s*#|^\s*$' \
    | grep -iE 'curl|wget|php|python|bash|sh |/tmp|/dev/shm|base64')"
  if [ -n "$cron_hits" ]; then
    finding_start HIGH "Suspicious cron entries for user $owner"
    while IFS= read -r line; do [ -n "$line" ] && finding_line "$line"; done <<< "$cron_hits"
    finding_end
    score_add 10 "Suspicious cron entry for $owner"; issues=1
  else
    finding_ok "No suspicious cron entries for $owner"
  fi

  # Also check /etc/cron.d for entries referencing this site's webroot
  local syscron
  syscron="$(grep -rlE "$WPP|/home/$owner" /etc/cron.d /etc/cron.daily \
               /etc/cron.hourly /etc/cron.weekly 2>/dev/null)"
  if [ -n "$syscron" ]; then
    finding_start MEDIUM "System cron file references this site path"
    while IFS= read -r f; do finding_file "$f"; done <<< "$syscron"
    finding_end
    score_add 5 "System cron referencing site path"
  fi

  # 10) Extended file scan: PHP/JS/HTML/htaccess/images/backups
  scan_files "$WPP" || issues=1

  # Risk score report for this site
  score_report

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
  label=""

  {
    echo "=================================================================="
    echo " wp2shell Security Scan Report"
    echo " Server:     $(hostname)"
    echo " Date:       $(date '+%Y-%m-%d %H:%M')"
    echo " Since date: $SINCE_DATE"
    echo " User:       $user"
    echo "=================================================================="
    echo ""
    echo " Severity:"
    echo "   [CRITICAL] Active compromise -- act immediately"
    echo "   [HIGH]     Strong indicator -- review urgently"
    echo "   [MEDIUM]   Suspicious -- investigate"
    echo "   [LOW]      Low priority -- likely false positive"
    echo "   [OK]       Clean"
    echo ""
  } >> "$body_file"

  for WPP in "${SITES[@]}"; do
    dom="$(basename "$(dirname "$WPP")")"
    domains="${domains:+$domains, }$dom"

    # Run scan on terminal (verbose)
    scan_site "$user" "$WPP" 2>/dev/null || user_issues=1

    # Build structured email section from SITE_SCORE_LOG and issues
    {
      echo "------------------------------------------------------------------"
      echo " SITE: $dom"
      echo " Path: $WPP"
      echo ""

      # Risk score
      label=""
      if   [ "$SITE_SCORE" -ge 81 ]; then label="COMPROMISED"
      elif [ "$SITE_SCORE" -ge 61 ]; then label="HIGH RISK"
      elif [ "$SITE_SCORE" -ge 41 ]; then label="MEDIUM RISK"
      elif [ "$SITE_SCORE" -ge 21 ]; then label="LOW RISK"
      else                                 label="PROBABLY CLEAN"
      fi
      echo " Risk Score: $SITE_SCORE/100 -- $label"
      echo ""

      # Findings breakdown
      if [ -n "$SITE_FINDINGS" ]; then
        echo " Findings:"
        printf '%b' "$SITE_FINDINGS"
      else
        echo " No significant findings."
      fi
      echo ""

      # Action line
      if [ "$SITE_SCORE" -ge 61 ]; then
        echo " ACTION REQUIRED: Log in to your server and run wp2shell-scan.sh"
        echo " for full technical details, or contact your hosting provider."
      elif [ "$SITE_SCORE" -ge 21 ]; then
        echo " RECOMMENDED: Review the findings above. Contact support if unsure."
      else
        echo " No action required at this time."
      fi
      echo ""
    } >> "$body_file"
  done

  {
    echo "=================================================================="
    if [ "$user_issues" -eq 1 ]; then
      echo " SUMMARY: Issues found -- review required."
    else
      echo " SUMMARY: No direct wp2shell indicators found."
    fi
    echo ""
    echo " More info:  https://wp2shell.com"
    echo " Powered by: BytesPulse (https://bytespulse.gr)"
    echo "=================================================================="
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
    echo "  --- DRY RUN: email NOT sent. Preview: ---"
    echo "  To:      $contact"
    echo "  Subject: $subject"
    echo "  ----------------------------------------"
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
    echo " DRY_RUN=$DRY_RUN"
    echo "=================================================================="
  } >> "$REPORT_FILE"
  echo ""
  echo "  Report saved: $REPORT_FILE"
  echo "  View:         less \"$REPORT_FILE\""
  echo "  Filter:       grep 'CRITICAL\|HIGH' \"$REPORT_FILE\""
fi
