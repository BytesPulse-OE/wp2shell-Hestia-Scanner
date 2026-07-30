#!/usr/bin/env bash
#
# wp2shell-scan.sh -- Read-only wp2shell compromise scanner
# CVE-2026-63030 (REST batch route confusion) + CVE-2026-60137 (author__not_in SQLi)
#
# Scans ALL WordPress installs on a HestiaCP server.
# Read-only -- never modifies anything (users, DB rows, files).
#
# Usage:  sudo bash wp2shell-scan.sh
#
# Safe versions: 6.8.6 / 6.9.5 / 7.0.2 or newer
# ---------------------------------------------------------------------------

set -uo pipefail

# --- Settings ---------------------------------------------------------------
WEB_ROOT="/home"
REPORT="/root/wp2shell-report-$(date +%Y%m%d-%H%M%S).txt"
SINCE_DATE="2026-07-15"          # date threshold -- format YYYY-MM-DD
WP="wp"                          # path to wp-cli binary
KNOWN_SHELLS_FILE="/root/wp2shell-known-shells.sha256"
# ---------------------------------------------------------------------------

# Colors
RED=$'\e[31m'; RED_BOLD=$'\e[1;31m'; YEL=$'\e[33m'
BLU=$'\e[34m'; GRN=$'\e[32m'; GRY=$'\e[90m'; CYA=$'\e[36m'; RST=$'\e[0m'

FOUND_ANY=0

# Severity log helpers
log()      { echo "$@" | tee -a "$REPORT"; }
hdr()      { log ""; log "${CYA}=== $* ===${RST}"; }
critical() { FOUND_ANY=1; log "${RED_BOLD}[CRITICAL] $*${RST}"; }
high()     { FOUND_ANY=1; log "${RED}[HIGH]     $*${RST}"; }
medium()   { FOUND_ANY=1; log "${YEL}[MEDIUM]   $*${RST}"; }
low()      { log "${BLU}[LOW]      $*${RST}"; }
info()     { log "${GRY}[INFO]     $*${RST}"; }
ok()       { log "${GRN}[OK]       $*${RST}"; }

# Global patterns
DANGER_PATTERNS='eval\s*\(|base64_decode\s*\(|gzinflate\s*\(|gzuncompress\s*\(|gzdecode\s*\(|assert\s*\(|shell_exec\s*\(|passthru\s*\(|proc_open\s*\(|popen\s*\(|pcntl_exec\s*\(|php://input|create_function\s*\(|preg_replace.*\/e[^a-z]|move_uploaded_file\s*\(|str_rot13\s*\('
C2_PATTERNS='pastebin\.com/raw|gist\.github\.com/raw|raw\.githubusercontent\.com|t\.me/|discord(app)?\.com/api/webhooks|ngrok\.io|ngrok-free\.app|tinyurl\.com|bit\.ly/[a-zA-Z0-9]|cdn\.discordapp\.com'

# ---------------------------------------------------------------------------
# Risk score (per site, reset each iteration)
# ---------------------------------------------------------------------------
SITE_SCORE=0
SITE_SCORE_LOG=""

score_reset() { SITE_SCORE=0; SITE_SCORE_LOG=""; }

score_add() {
  local pts="$1" reason="$2"
  SITE_SCORE=$(( SITE_SCORE + pts ))
  SITE_SCORE_LOG="${SITE_SCORE_LOG}$(printf '  %+d  %s\n' "$pts" "$reason")"$'\n'
}

score_report() {
  local label color
  if   [ "$SITE_SCORE" -ge 81 ]; then label="COMPROMISED";   color="$RED_BOLD"
  elif [ "$SITE_SCORE" -ge 61 ]; then label="HIGH RISK";     color="$RED"
  elif [ "$SITE_SCORE" -ge 41 ]; then label="MEDIUM RISK";   color="$YEL"
  elif [ "$SITE_SCORE" -ge 21 ]; then label="LOW RISK";      color="$BLU"
  else                                 label="PROBABLY CLEAN"; color="$GRN"
  fi
  log ""
  log "${CYA}  +------------------------------------------+"
  log "$(printf "  |  RISK SCORE: %s%-6s%s  %-17s  ${CYA}|" "$color" "$SITE_SCORE/100" "$RST" "$label")"
  log "${CYA}  +------------------------------------------+${RST}"
  if [ -n "$SITE_SCORE_LOG" ]; then
    printf '%s' "$SITE_SCORE_LOG" | while IFS= read -r line; do
      [ -n "$line" ] && log "  $line"
    done
  fi
  log ""
}

# ---------------------------------------------------------------------------
# Known shell SHA256 check
# ---------------------------------------------------------------------------
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

check_known_shell() {
  local f="$1"
  [ -f "$KNOWN_SHELLS_FILE" ] || return
  local hash; hash="$(sha256sum "$f" 2>/dev/null | cut -d' ' -f1)"
  [ -z "$hash" ] && return
  grep -i "^$hash" "$KNOWN_SHELLS_FILE" 2>/dev/null | head -1 | awk '{print $2}'
}

# ---------------------------------------------------------------------------
# Startup checks
# ---------------------------------------------------------------------------
[ "$(id -u)" -eq 0 ] || { echo "Run as root (sudo)."; exit 1; }

command -v "$WP" >/dev/null 2>&1 || {
  echo "wp-cli not found. Install it first:"
  echo "  curl -O https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar"
  echo "  chmod +x wp-cli.phar && sudo mv wp-cli.phar /usr/local/bin/wp"
  exit 1
}

echo ""
echo "+------------------------------------------------------+"
echo "|        wp2shell Security Scanner -- BytesPulse      |"
echo "+------------------------------------------------------+"
echo ""
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

fetch_known_shells

log "wp2shell scan -- $(date)"
log "Server:     $(hostname)"
log "Since date: $SINCE_DATE"
log "Report:     $REPORT"
log ""
log "Severity legend:"
log "  [CRITICAL] Active compromise indicator -- act immediately"
log "  [HIGH]     Strong indicator -- review urgently"
log "  [MEDIUM]   Suspicious -- investigate"
log "  [LOW]      Low priority -- likely false positive, verify manually"
log "  [INFO]     Informational"
log "  [OK]       Clean / expected"

run_wp() { local owner="$1" path="$2"; shift 2; sudo -u "$owner" -- "$WP" --path="$path" --skip-plugins --skip-themes "$@" 2>/dev/null; }

mapfile -t WP_PATHS < <(find "$WEB_ROOT" -maxdepth 6 -name wp-load.php -type f 2>/dev/null | xargs -r -n1 dirname | sort -u)
log ""
log "Found ${#WP_PATHS[@]} WordPress installs."

for WPP in "${WP_PATHS[@]}"; do
  owner="$(stat -c '%U' "$WPP")"
  score_reset
  hdr "SITE: $WPP  (owner: $owner)"

  # --- 1) Core version -------------------------------------------------------
  ver="$(run_wp "$owner" "$WPP" core version 2>/dev/null)"
  if [ -z "$ver" ]; then
    info "Could not read version/DB -- skipping."
    continue
  fi
  case "$ver" in
    6.8.[6-9]*|6.9.[5-9]*|6.9.[1-9][0-9]*|7.0.[2-9]*|7.[1-9]*|[89].*)
      ok "WordPress $ver -- patched" ;;
    *)
      high "WordPress $ver -- VULNERABLE! Update to 6.8.6 / 6.9.5 / 7.0.2+"
      score_add 20 "Vulnerable WordPress version ($ver)" ;;
  esac

  # --- 2) wp2shell fingerprint accounts --------------------------------------
  bad_users="$(run_wp "$owner" "$WPP" user list \
    --fields=ID,user_login,user_email,user_registered,roles --format=csv 2>/dev/null \
    | grep -Ei 'wp2_[0-9a-f]{6,}|@wp2shell\.invalid')"
  if [ -n "$bad_users" ]; then
    critical "wp2shell fingerprint accounts found:"
    echo "$bad_users" | sed 's/^/       /' | tee -a "$REPORT"
    score_add 40 "wp2shell fingerprint account (wp2_/@wp2shell.invalid)"
  else
    ok "No accounts with wp2_ / @wp2shell.invalid"
  fi

  # --- 3) New admins post-disclosure -----------------------------------------
  admins="$(run_wp "$owner" "$WPP" user list --role=administrator \
            --fields=ID,user_login,user_email,user_registered --format=csv 2>/dev/null)"
  info "Administrator list:"
  echo "$admins" | tee -a "$REPORT"
  echo "$admins" | awk -F, 'NR>1 && $4>"2026-07-15"{print}' | while IFS= read -r line; do
    [ -n "$line" ] && {
      FOUND_ANY=1
      log "${YEL}[MEDIUM]   Admin created after disclosure date: $line${RST}"
      score_add 10 "New admin created after disclosure: $line"
    }
  done

  # --- 4) Orphaned usermeta / user-ID gaps -----------------------------------
  gaps="$(run_wp "$owner" "$WPP" db query \
    "SELECT (t1.ID+1) AS gap_start FROM wp_users t1 LEFT JOIN wp_users t2 ON t1.ID+1=t2.ID WHERE t2.ID IS NULL AND t1.ID < (SELECT MAX(ID) FROM wp_users);" \
    --skip-column-names 2>/dev/null)"
  if [ -n "$gaps" ]; then
    medium "Gaps in user-ID sequence (possible deleted rogue admin): $(echo "$gaps" | tr '\n' ' ')"
    score_add 5 "User-ID sequence gaps"
  fi

  orphan="$(run_wp "$owner" "$WPP" db query \
    "SELECT COUNT(*) FROM wp_usermeta um LEFT JOIN wp_users u ON um.user_id=u.ID WHERE u.ID IS NULL;" \
    --skip-column-names 2>/dev/null)"
  if [ "${orphan:-0}" -gt 0 ] 2>/dev/null; then
    medium "Orphaned usermeta rows: $orphan (traces of deleted user)"
    score_add 5 "Orphaned usermeta rows ($orphan)"
  fi

  # --- 5) Poisoned oembed_cache / customize_changeset ------------------------
  susp_oembed="$(run_wp "$owner" "$WPP" db query \
    "SELECT COUNT(*) FROM wp_postmeta WHERE meta_key='_oembed_response' AND (meta_value LIKE '%O:8:\"WP_Post\"%' OR meta_value LIKE '%wp2shell%');" \
    --skip-column-names 2>/dev/null)"
  if [ "${susp_oembed:-0}" -gt 0 ] 2>/dev/null; then
    critical "Suspicious oembed_response rows (object injection): $susp_oembed"
    score_add 20 "Poisoned oembed_cache rows ($susp_oembed)"
  fi

  susp_cs="$(run_wp "$owner" "$WPP" db query \
    "SELECT ID,post_date,post_status FROM wp_posts WHERE post_type='customize_changeset' AND post_date>'2026-07-15';" \
    --skip-column-names 2>/dev/null)"
  if [ -n "$susp_cs" ]; then
    medium "customize_changeset after 15/07/2026 (exploit mechanism): $(echo "$susp_cs" | tr '\n' ' | ')"
    score_add 5 "Suspicious customize_changeset rows"
  fi

  # --- 6) Core file integrity ------------------------------------------------
  cks="$(run_wp "$owner" "$WPP" core verify-checksums 2>&1)"
  if echo "$cks" | grep -qi 'Success'; then
    ok "Core checksums OK"
  else
    high "Core checksums FAILED -- modified/extra core files:"
    echo "$cks" | grep -Ei 'Warning|does not|should not exist' | sed 's/^/       /' | tee -a "$REPORT"
    score_add 5 "Core checksum failure"
  fi

  # --- 7) Plugin integrity ---------------------------------------------------
  pck="$(run_wp "$owner" "$WPP" plugin verify-checksums --all 2>&1 | grep -Ei 'Warning|does not match')"
  if [ -n "$pck" ]; then
    low "Plugin checksum mismatches (premium/custom plugins excluded):"
    echo "$pck" | sed 's/^/       /' | tee -a "$REPORT"
  fi

  # --- 8) PHP files in uploads -----------------------------------------------
  php_in_uploads="$(find "$WPP/wp-content/uploads" -type f -name '*.php' 2>/dev/null)"
  if [ -n "$php_in_uploads" ]; then
    critical "PHP files inside uploads/ (should not exist):"
    echo "$php_in_uploads" | sed 's/^/       /' | tee -a "$REPORT"
    score_add 30 "PHP file(s) inside uploads/"
  fi

  # --- 9) WP Options -- tampered critical options ----------------------------
  hdr "WP Options check"
  opt_upload="$(run_wp "$owner" "$WPP" option get upload_path 2>/dev/null)"
  opt_prepend="$(run_wp "$owner" "$WPP" option get auto_prepend_file 2>/dev/null)"
  opt_siteurl="$(run_wp "$owner" "$WPP" option get siteurl 2>/dev/null)"
  expected_domain="$(basename "$(dirname "$(dirname "$WPP")")")"

  if [ -n "$opt_upload" ] && ! echo "$opt_upload" | grep -qE 'wp-content/uploads|^$'; then
    high "upload_path redirected outside wp-content/uploads: $opt_upload"
    score_add 15 "upload_path tampered: $opt_upload"
  fi
  if [ -n "$opt_prepend" ]; then
    critical "auto_prepend_file set in WP options: $opt_prepend"
    score_add 25 "auto_prepend_file in wp_options"
  fi
  if ! echo "$opt_siteurl" | grep -q "$expected_domain"; then
    high "siteurl does not match site directory: $opt_siteurl"
    score_add 10 "siteurl mismatch"
  fi

  # --- 10) Cron persistence --------------------------------------------------
  hdr "Cron persistence check"
  cron_hits="$(crontab -u "$owner" -l 2>/dev/null \
    | grep -vE '^\s*#|^\s*$' \
    | grep -iE 'curl|wget|php|python|bash|/tmp|/dev/shm|base64')"
  if [ -n "$cron_hits" ]; then
    high "Suspicious cron entries for $owner:"
    echo "$cron_hits" | sed 's/^/       /' | tee -a "$REPORT"
    score_add 10 "Suspicious cron entry for $owner"
  else
    ok "No suspicious cron entries for $owner."
  fi

  syscron="$(grep -rlE "$WPP|/home/$owner" /etc/cron.d /etc/cron.daily \
               /etc/cron.hourly /etc/cron.weekly 2>/dev/null)"
  if [ -n "$syscron" ]; then
    medium "System cron files referencing this site:"
    echo "$syscron" | sed 's/^/       /' | tee -a "$REPORT"
    score_add 5 "System cron referencing site path"
  fi

  # --- 11) SHA256 known webshell check ---------------------------------------
  if [ -f "$KNOWN_SHELLS_FILE" ]; then
    hdr "SHA256 known webshell check"
    find "$WPP" -type f -name '*.php' 2>/dev/null | while IFS= read -r f; do
      shell_name="$(check_known_shell "$f")"
      if [ -n "$shell_name" ]; then
        critical "Known webshell match: $f"
        log "       Shell: $shell_name"
        score_add 25 "Known webshell SHA256 match: $shell_name"
      fi
    done
  fi

  # --- 12) External C2/exfiltration URLs -------------------------------------
  hdr "External C2 URL check"
  c2_hits="$(grep -RInE --include='*.php' --include='*.js' --include='*.html' \
    "$C2_PATTERNS" "$WPP/wp-content" 2>/dev/null | head -20)"
  if [ -n "$c2_hits" ]; then
    critical "External C2/exfiltration URL found:"
    echo "$c2_hits" | sed 's/^/       /' | tee -a "$REPORT"
    score_add 15 "External C2/exfiltration URL in source files"
  else
    ok "No C2/exfiltration URLs found."
  fi

  # --- 13) PHP modified after SINCE_DATE AND matching patterns ---------------
  hdr "PHP file analysis"
  find "$WPP" -type f -name '*.php' -newermt "$SINCE_DATE" 2>/dev/null \
  | grep -vE '/(wp-includes|wp-admin)/' \
  | while IFS= read -r f; do
      hits="$(grep -nEi "$DANGER_PATTERNS" "$f" 2>/dev/null | head -3)"
      if [ -n "$hits" ]; then
        if echo "$f" | grep -q '/uploads/'; then
          log "${RED_BOLD}[CRITICAL] $f  (PHP in uploads/ + suspicious pattern)${RST}"
          score_add 20 "PHP in uploads + suspicious pattern"
        else
          log "${RED}[HIGH]     $f  (modified after $SINCE_DATE + suspicious pattern)${RST}"
          score_add 15 "PHP modified after $SINCE_DATE + suspicious pattern"
        fi
        echo "$hits" | sed 's/^/       >> /' | tee -a "$REPORT"
      fi
    done

  # Low priority: patterns in files NOT recently modified
  grep -RIlE --include='*.php' "$DANGER_PATTERNS" "$WPP" 2>/dev/null \
  | grep -vE '/(wp-includes|wp-admin)/' \
  | while IFS= read -r f; do
      find "$f" -newermt "$SINCE_DATE" 2>/dev/null | grep -q . && continue
      echo "$f"
    done \
  | head -30 \
  | while IFS= read -r f; do
      log "${BLU}[LOW]      $f  (suspicious pattern, not recently modified -- likely false positive)${RST}"
    done

  # --- Risk Score report for this site ---------------------------------------
  score_report

done

# --- Summary ----------------------------------------------------------------
hdr "SUMMARY"
if [ "$FOUND_ANY" -eq 1 ]; then
  log "${RED_BOLD}Indicators found. Review CRITICAL/HIGH entries above and the full report:${RST}"
  log "  $REPORT"
  log "Note: updating WordPress closes the vulnerability but does NOT clean an already-compromised site."
else
  log "${GRN}No direct wp2shell indicators found. Still verify versions and recently modified files.${RST}"
fi
log ""
log "Official checker: https://wp2shell.com  (SearchLight Cyber)"
log "Forensic plugin:  'Compromise Scanner for wp2shell' (wordpress.org)"
