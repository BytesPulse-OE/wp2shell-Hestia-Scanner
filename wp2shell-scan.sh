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

# ---------------------------------------------------------------------------
# Unified finding() output system
# Same structure for terminal (color) and report file (plain text).
#
# Usage:
#   finding_start CRITICAL "Title"
#   finding_file  "path/to/file.php"
#   finding_line  "Line 42: eval(...)"
#   finding_end
# ---------------------------------------------------------------------------
_FINDING_SEV=""
_FINDING_TITLE=""
_FINDING_LINES=""

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
  local line; line="$(printf '%s' "$1" | tr -cd '[:print:]' | cut -c1-120)"
  [ -n "$line" ] && _FINDING_LINES="${_FINDING_LINES}               > $line\n"
}

finding_end() {
  [ "$_FINDING_SEV" = "CRITICAL" ] || [ "$_FINDING_SEV" = "HIGH" ] && FOUND_ANY=1
  local col; col="$(_sev_color "$_FINDING_SEV")"
  local label; label="$(printf '%-10s' "[$_FINDING_SEV]")"
  # Terminal + report file
  { printf '%s%s%s %s\n' "$col" "$label" "$RST" "$_FINDING_TITLE"
    [ -n "$_FINDING_LINES" ] && printf '%b' "$_FINDING_LINES"; } | tee -a "$REPORT"
  _FINDING_SEV=""; _FINDING_TITLE=""; _FINDING_LINES=""
}

finding_ok()   {
  printf '%s%-10s%s %s\n' "$GRN" "[OK]" "$RST" "$1" | tee -a "$REPORT"
}
finding_info() {
  printf '%s%-10s%s %s\n' "$GRY" "[INFO]" "$RST" "$1" | tee -a "$REPORT"
}
hdr() {
  printf '\n%s=== %s ===%s\n' "$CYA" "$*" "$RST" | tee -a "$REPORT"
}

# ---------------------------------------------------------------------------
# Risk score
# ---------------------------------------------------------------------------
SITE_SCORE=0
SITE_SCORE_LOG=""

score_reset() { SITE_SCORE=0; SITE_SCORE_LOG=""; }

score_add() {
  SITE_SCORE=$(( SITE_SCORE + $1 ))
  SITE_SCORE_LOG="${SITE_SCORE_LOG}$(printf '  %+d  %s\n' "$1" "$2")"$'\n'
}

score_report() {
  local label color
  if   [ "$SITE_SCORE" -ge 81 ]; then label="COMPROMISED";    color="$RED_BOLD"
  elif [ "$SITE_SCORE" -ge 61 ]; then label="HIGH RISK";      color="$RED"
  elif [ "$SITE_SCORE" -ge 41 ]; then label="MEDIUM RISK";    color="$YEL"
  elif [ "$SITE_SCORE" -ge 21 ]; then label="LOW RISK";       color="$BLU"
  else                                 label="PROBABLY CLEAN"; color="$GRN"
  fi
  {
    printf '\n%s  +------------------------------------------+%s\n' "$CYA" "$RST"
    printf '  |  RISK SCORE: %s%-6s%s  %-17s  |\n' "$color" "$SITE_SCORE/100" "$RST" "$label"
    printf '%s  +------------------------------------------+%s\n' "$CYA" "$RST"
    if [ -n "$SITE_SCORE_LOG" ]; then
      printf '%s' "$SITE_SCORE_LOG" | while IFS= read -r line; do
        [ -n "$line" ] && printf '  %s\n' "$line"
      done
    fi
    printf '\n'
  } | tee -a "$REPORT"
}

# ---------------------------------------------------------------------------
# Known shell SHA256
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
  [ -f "$KNOWN_SHELLS_FILE" ] || return
  local hash; hash="$(sha256sum "$1" 2>/dev/null | cut -d' ' -f1)"
  [ -z "$hash" ] && return
  grep -i "^$hash" "$KNOWN_SHELLS_FILE" 2>/dev/null | head -1 | awk '{print $2}'
}

# ---------------------------------------------------------------------------
# Startup
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

{
  echo "wp2shell scan -- $(date)"
  echo "Server:     $(hostname)"
  echo "Since date: $SINCE_DATE"
  echo "Report:     $REPORT"
  echo ""
  echo "Severity:"
  echo "  [CRITICAL] Active compromise indicator -- act immediately"
  echo "  [HIGH]     Strong indicator -- review urgently"
  echo "  [MEDIUM]   Suspicious -- investigate"
  echo "  [LOW]      Low priority -- likely false positive"
  echo "  [OK]       Clean / expected"
  echo ""
} | tee -a "$REPORT"

run_wp() { local owner="$1" path="$2"; shift 2
  sudo -u "$owner" -- "$WP" --path="$path" --skip-plugins --skip-themes "$@" 2>/dev/null; }

mapfile -t WP_PATHS < <(find "$WEB_ROOT" -maxdepth 6 -name wp-load.php -type f 2>/dev/null \
  | xargs -r -n1 dirname | sort -u)

printf '\nFound %d WordPress installs.\n' "${#WP_PATHS[@]}" | tee -a "$REPORT"

for WPP in "${WP_PATHS[@]}"; do
  owner="$(stat -c '%U' "$WPP")"
  score_reset

  {
    printf '\n'
    printf '======================================================================\n'
    printf '  SITE: %s  (owner: %s)\n' "$WPP" "$owner"
    printf '======================================================================\n'
  } | tee -a "$REPORT"

  # --- 1) Core version -------------------------------------------------------
  ver="$(run_wp "$owner" "$WPP" core version 2>/dev/null)"
  if [ -z "$ver" ]; then
    finding_info "Could not read version/DB -- skipping."
    continue
  fi

  case "$ver" in
    6.8.[6-9]*|6.9.[5-9]*|6.9.[1-9][0-9]*|7.0.[2-9]*|7.[1-9]*|[89].*)
      finding_ok "WordPress $ver -- patched" ;;
    *)
      finding_start HIGH "Vulnerable WordPress version -- update immediately"
      finding_line "Installed: $ver"
      finding_line "Safe versions: 6.8.6 / 6.9.5 / 7.0.2 or newer"
      finding_end
      score_add 20 "Vulnerable WordPress version ($ver)" ;;
  esac

  # --- 2) wp2shell fingerprint accounts --------------------------------------
  bad_users="$(run_wp "$owner" "$WPP" user list \
    --fields=ID,user_login,user_email,user_registered,roles --format=csv 2>/dev/null \
    | grep -Ei 'wp2_[0-9a-f]{6,}|@wp2shell\.invalid')"
  if [ -n "$bad_users" ]; then
    finding_start CRITICAL "wp2shell fingerprint account found"
    while IFS= read -r line; do [ -n "$line" ] && finding_line "$line"; done <<< "$bad_users"
    finding_end
    score_add 40 "wp2shell fingerprint account (wp2_/@wp2shell.invalid)"
  else
    finding_ok "No accounts with wp2_ / @wp2shell.invalid"
  fi

  # --- 3) New admins post-disclosure -----------------------------------------
  admins="$(run_wp "$owner" "$WPP" user list --role=administrator \
            --fields=ID,user_login,user_email,user_registered --format=csv 2>/dev/null)"
  newadm="$(echo "$admins" | awk -F, 'NR>1 && $4>"2026-07-15"{print}')"
  if [ -n "$newadm" ]; then
    finding_start MEDIUM "Administrator created after disclosure date (15/07/2026)"
    while IFS= read -r line; do [ -n "$line" ] && finding_line "$line"; done <<< "$newadm"
    finding_end
    FOUND_ANY=1; score_add 10 "New admin after disclosure"
  fi

  # --- 4) Orphaned usermeta / user-ID gaps -----------------------------------
  gaps="$(run_wp "$owner" "$WPP" db query \
    "SELECT (t1.ID+1) AS gap_start FROM wp_users t1 LEFT JOIN wp_users t2 ON t1.ID+1=t2.ID WHERE t2.ID IS NULL AND t1.ID < (SELECT MAX(ID) FROM wp_users);" \
    --skip-column-names 2>/dev/null)"
  if [ -n "$gaps" ]; then
    finding_start MEDIUM "Gaps in user-ID sequence -- possible deleted rogue admin"
    finding_line "Missing IDs: $(echo "$gaps" | tr '\n' ' ')"
    finding_end
    score_add 5 "User-ID sequence gaps"
  fi

  orphan="$(run_wp "$owner" "$WPP" db query \
    "SELECT COUNT(*) FROM wp_usermeta um LEFT JOIN wp_users u ON um.user_id=u.ID WHERE u.ID IS NULL;" \
    --skip-column-names 2>/dev/null)"
  if [ "${orphan:-0}" -gt 0 ] 2>/dev/null; then
    finding_start MEDIUM "Orphaned usermeta rows -- traces of deleted rogue user"
    finding_line "$orphan rows in wp_usermeta with no matching user"
    finding_end
    score_add 5 "Orphaned usermeta ($orphan rows)"
  fi

  # --- 5) Poisoned oembed_cache / customize_changeset ------------------------
  susp_oembed="$(run_wp "$owner" "$WPP" db query \
    "SELECT COUNT(*) FROM wp_postmeta WHERE meta_key='_oembed_response' AND (meta_value LIKE '%O:8:\"WP_Post\"%' OR meta_value LIKE '%wp2shell%');" \
    --skip-column-names 2>/dev/null)"
  if [ "${susp_oembed:-0}" -gt 0 ] 2>/dev/null; then
    finding_start CRITICAL "Poisoned oembed_cache rows -- object injection indicator"
    finding_line "$susp_oembed suspicious oembed_response rows in wp_postmeta"
    finding_end
    score_add 20 "Poisoned oembed_cache ($susp_oembed rows)"
  fi

  susp_cs="$(run_wp "$owner" "$WPP" db query \
    "SELECT ID,post_date,post_status FROM wp_posts WHERE post_type='customize_changeset' AND post_date>'2026-07-15';" \
    --skip-column-names 2>/dev/null)"
  if [ -n "$susp_cs" ]; then
    finding_start MEDIUM "customize_changeset entries after 15/07/2026 -- exploit mechanism"
    while IFS= read -r line; do [ -n "$line" ] && finding_line "$line"; done <<< "$susp_cs"
    finding_end
    score_add 5 "Suspicious customize_changeset rows"
  fi

  # --- 6) Core file integrity ------------------------------------------------
  hdr "Core integrity"
  cks="$(run_wp "$owner" "$WPP" core verify-checksums 2>&1)"
  if echo "$cks" | grep -qi 'Success'; then
    finding_ok "Core checksums OK"
  else
    finding_start HIGH "Core checksum failure -- modified or extra core files"
    echo "$cks" | grep -Ei 'Warning|does not|should not exist' | while IFS= read -r line; do
      finding_line "$line"
    done
    finding_end
    score_add 5 "Core checksum failure"
  fi

  # --- 7) Plugin integrity ---------------------------------------------------
  pck="$(run_wp "$owner" "$WPP" plugin verify-checksums --all 2>&1 | grep -Ei 'Warning|does not match')"
  if [ -n "$pck" ]; then
    finding_start LOW "Plugin checksum mismatches (premium/custom plugins not checked)"
    while IFS= read -r line; do [ -n "$line" ] && finding_line "$line"; done <<< "$pck"
    finding_end
  fi

  # --- 8) PHP files in uploads -----------------------------------------------
  hdr "File checks"
  php_in_uploads="$(find "$WPP/wp-content/uploads" -type f -name '*.php' 2>/dev/null)"
  if [ -n "$php_in_uploads" ]; then
    finding_start CRITICAL "PHP file(s) inside uploads/ -- must not exist here"
    while IFS= read -r f; do finding_file "${f#$WPP/}"; done <<< "$php_in_uploads"
    finding_end
    score_add 30 "PHP file(s) inside uploads/"
  else
    finding_ok "No PHP files in uploads/"
  fi

  # --- 9) WP Options ---------------------------------------------------------
  hdr "WP Options"
  opt_upload="$(run_wp "$owner" "$WPP" option get upload_path 2>/dev/null)"
  opt_prepend="$(run_wp "$owner" "$WPP" option get auto_prepend_file 2>/dev/null)"
  opt_siteurl="$(run_wp "$owner" "$WPP" option get siteurl 2>/dev/null)"
  expected_domain="$(basename "$(dirname "$(dirname "$WPP")")")"
  siteurl_domain="$(echo "$opt_siteurl" | sed 's|https\?://||' | cut -d'/' -f1)"

  if [ -n "$opt_upload" ] && ! echo "$opt_upload" | grep -qE 'wp-content/uploads|^$'; then
    finding_start HIGH "upload_path redirected outside wp-content/uploads"
    finding_line "upload_path = $opt_upload"
    finding_end
    score_add 15 "upload_path tampered"
  fi
  if [ -n "$opt_prepend" ]; then
    finding_start CRITICAL "auto_prepend_file set -- injects PHP into every request"
    finding_line "auto_prepend_file = $opt_prepend"
    finding_end
    score_add 25 "auto_prepend_file in wp_options"
  fi
  if [ -n "$siteurl_domain" ] && ! echo "$siteurl_domain" | grep -qi "$expected_domain"; then
    finding_start HIGH "siteurl does not match site directory"
    finding_line "siteurl:  $opt_siteurl"
    finding_line "Expected: $expected_domain"
    finding_end
    score_add 10 "siteurl mismatch"
  else
    finding_ok "WP options look clean"
  fi

  # --- 10) Cron persistence --------------------------------------------------
  hdr "Cron persistence"
  cron_hits="$(crontab -u "$owner" -l 2>/dev/null \
    | grep -vE '^\s*#|^\s*$' \
    | grep -iE 'curl|wget|php|python|bash|/tmp|/dev/shm|base64')"
  if [ -n "$cron_hits" ]; then
    finding_start HIGH "Suspicious cron entries for user $owner"
    while IFS= read -r line; do [ -n "$line" ] && finding_line "$line"; done <<< "$cron_hits"
    finding_end
    score_add 10 "Suspicious cron entry for $owner"
  else
    finding_ok "No suspicious cron entries for $owner"
  fi

  syscron="$(grep -rlE "$WPP|/home/$owner" /etc/cron.d /etc/cron.daily \
               /etc/cron.hourly /etc/cron.weekly 2>/dev/null)"
  if [ -n "$syscron" ]; then
    finding_start MEDIUM "System cron file references this site"
    while IFS= read -r f; do finding_file "$f"; done <<< "$syscron"
    finding_end
    score_add 5 "System cron referencing site"
  fi

  # --- 11) SHA256 known webshell ---------------------------------------------
  if [ -f "$KNOWN_SHELLS_FILE" ]; then
    hdr "SHA256 webshell check"
    find "$WPP" -type f -name '*.php' 2>/dev/null | while IFS= read -r f; do
      shell_name="$(check_known_shell "$f")"
      if [ -n "$shell_name" ]; then
        finding_start CRITICAL "Known webshell -- SHA256 hash match"
        finding_file "${f#$WPP/}"
        finding_line "Identified as: $shell_name"
        finding_end
        score_add 25 "Known webshell: $shell_name"
      fi
    done
  fi

  # --- 12) External C2/exfiltration URLs -------------------------------------
  hdr "External C2 URLs"
  c2_hits="$(grep -RInE --include='*.php' --include='*.js' --include='*.html' \
    'pastebin\.com/raw|gist\.github\.com/raw|raw\.githubusercontent\.com|t\.me/|discord(app)?\.com/api/webhooks|ngrok\.io|ngrok-free\.app|tinyurl\.com|bit\.ly/[a-zA-Z0-9]|cdn\.discordapp\.com' \
    "$WPP/wp-content" 2>/dev/null \
    | grep -vE '@see\s+https?://|^\s*[*#/].*https?://' \
    | cut -c1-120 | head -10)"
  if [ -n "$c2_hits" ]; then
    finding_start CRITICAL "External C2/exfiltration URL in source files"
    while IFS= read -r line; do [ -n "$line" ] && finding_line "$line"; done <<< "$c2_hits"
    finding_end
    score_add 15 "External C2/exfiltration URL"
  else
    finding_ok "No C2/exfiltration URLs found"
  fi

  # --- 13) PHP modified after SINCE_DATE AND matching patterns ---------------
  hdr "PHP pattern analysis"
  find "$WPP" -type f -name '*.php' -newermt "$SINCE_DATE" 2>/dev/null \
  | grep -vE '/(wp-includes|wp-admin)/' \
  | while IFS= read -r f; do
      hits="$(grep -nEi "$DANGER_PATTERNS" "$f" 2>/dev/null | head -3 | cut -c1-120)"
      if [ -n "$hits" ]; then
        if echo "$f" | grep -q '/uploads/'; then
          finding_start CRITICAL "PHP in uploads/ with suspicious pattern"
        else
          finding_start HIGH "PHP modified after $SINCE_DATE with suspicious pattern"
        fi
        finding_file "${f#$WPP/}"
        while IFS= read -r line; do [ -n "$line" ] && finding_line "$line"; done <<< "$hits"
        finding_end
        score_add 15 "PHP modified after $SINCE_DATE + suspicious pattern"
      fi
    done

  # Low priority: patterns NOT recently modified
  grep -RIlE --include='*.php' "$DANGER_PATTERNS" "$WPP" 2>/dev/null \
  | grep -vE '/(wp-includes|wp-admin)/' \
  | while IFS= read -r f; do
      find "$f" -newermt "$SINCE_DATE" 2>/dev/null | grep -q . && continue
      finding_start LOW "Suspicious pattern (not recently modified -- likely false positive)"
      finding_file "${f#$WPP/}"
      finding_end
    done | head -60 | tee -a "$REPORT"

  # --- Risk Score ------------------------------------------------------------
  score_report

done

# --- Summary -----------------------------------------------------------------
{
  printf '\n======================================================================\n'
  printf 'SUMMARY\n'
  printf '======================================================================\n'
  if [ "$FOUND_ANY" -eq 1 ]; then
    printf '%s[!] Indicators found. Review CRITICAL/HIGH entries above.%s\n' "$RED_BOLD" "$RST"
    printf '    Full report: %s\n' "$REPORT"
    printf '    Note: updating WordPress does NOT clean an already-compromised site.\n'
  else
    printf '%s[OK] No direct wp2shell indicators found.%s\n' "$GRN" "$RST"
    printf '     Still verify versions and recently modified files.\n'
  fi
  printf '\nOfficial checker: https://wp2shell.com  (SearchLight Cyber)\n'
} | tee -a "$REPORT"
