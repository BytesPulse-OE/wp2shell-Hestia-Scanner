#!/usr/bin/env bash
#
# wp2shell-scan.sh — Read-only ανιχνευτής παραβίασης για wp2shell
# CVE-2026-63030 (REST batch route confusion) + CVE-2026-60137 (author__not_in SQLi)
#
# Σαρώνει ΟΛΑ τα WordPress installs σε έναν HestiaCP server.
# ΔΕΝ αλλάζει τίποτα — μόνο διαβάζει (users, DB rows, αρχεία) και αναφέρει.
#
# Χρήση:  sudo bash wp2shell-scan.sh
#
# Ασφαλείς εκδόσεις: 6.8.6 / 6.9.5 / 7.0.2 (ή νεότερες)
# ---------------------------------------------------------------------------

set -uo pipefail

# --- Ρυθμίσεις ---------------------------------------------------------------
WEB_ROOT="/home"                 # HestiaCP: /home/<user>/web/<domain>/public_html
REPORT="/root/wp2shell-report-$(date +%Y%m%d-%H%M%S).txt"
DAYS_MODIFIED=30                 # "πρόσφατα τροποποιημένα" αρχεία (ημέρες)
WP="wp"                          # διαδρομή στο wp-cli αν χρειάζεται
# ---------------------------------------------------------------------------

RED=$'\e[31m'; YEL=$'\e[33m'; GRN=$'\e[32m'; CYA=$'\e[36m'; RST=$'\e[0m'
FOUND_ANY=0

log()  { echo "$@" | tee -a "$REPORT"; }
hdr()  { log ""; log "${CYA}=== $* ===${RST}"; }
hit()  { FOUND_ANY=1; log "${RED}[!] $*${RST}"; }
warn() { log "${YEL}[?] $*${RST}"; }
ok()   { log "${GRN}[ok] $*${RST}"; }

need_root() { [ "$(id -u)" -eq 0 ] || { echo "Τρέξε ως root (sudo)."; exit 1; }; }
need_root

command -v "$WP" >/dev/null 2>&1 || {
  echo "Το wp-cli δεν βρέθηκε. Εγκατάστησέ το πρώτα:"
  echo "  curl -O https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar"
  echo "  chmod +x wp-cli.phar && sudo mv wp-cli.phar /usr/local/bin/wp"
  exit 1
}

log "wp2shell scan — $(date)"
log "Server: $(hostname)"
log "Report: $REPORT"

# Εκτελεί wp-cli ως ο owner του site (αποφεύγει προειδοποιήσεις root)
run_wp() { local owner="$1" path="$2"; shift 2; sudo -u "$owner" -- "$WP" --path="$path" --skip-plugins --skip-themes "$@" 2>/dev/null; }

# Βρες όλα τα WordPress installs (ψάχνει wp-load.php)
mapfile -t WP_PATHS < <(find "$WEB_ROOT" -maxdepth 6 -name wp-load.php -type f 2>/dev/null | xargs -r -n1 dirname | sort -u)

log ""
log "Βρέθηκαν ${#WP_PATHS[@]} WordPress installs."

for WPP in "${WP_PATHS[@]}"; do
  owner="$(stat -c '%U' "$WPP")"
  hdr "SITE: $WPP  (owner: $owner)"

  # --- 1) Έκδοση πυρήνα ------------------------------------------------------
  ver="$(run_wp "$owner" "$WPP" core version 2>/dev/null)"
  if [ -z "$ver" ]; then
    warn "Δεν μπόρεσα να διαβάσω έκδοση/DB (ίσως broken install ή λάθος credentials)."
    continue
  fi
  case "$ver" in
    6.8.[6-9]*|6.9.[5-9]*|6.9.[1-9][0-9]*|7.0.[2-9]*|7.[1-9]*|[89].*)
      ok "WordPress $ver — patched" ;;
    *)
      hit "WordPress $ver — ΕΥΠΑΘΗΣ έκδοση! Ενημέρωσε σε 6.8.6 / 6.9.5 / 7.0.2+" ;;
  esac

  # --- 2) Άμεσα αποτυπώματα exploit: wp2_ login + @wp2shell.invalid ----------
  bad_users="$(run_wp "$owner" "$WPP" user list --fields=ID,user_login,user_email,user_registered,roles --format=csv 2>/dev/null \
              | grep -Ei 'wp2_[0-9a-f]{6,}|@wp2shell\.invalid')"
  if [ -n "$bad_users" ]; then
    hit "Βρέθηκαν λογαριασμοί-αποτυπώματα wp2shell:"
    echo "$bad_users" | tee -a "$REPORT"
  else
    ok "Κανένας χρήστης με wp2_ / @wp2shell.invalid"
  fi

  # --- 3) Ύποπτοι administrators (πρόσφατα δημιουργημένοι) -------------------
  admins="$(run_wp "$owner" "$WPP" user list --role=administrator \
            --fields=ID,user_login,user_email,user_registered --format=csv 2>/dev/null)"
  log "Λίστα administrators:"
  echo "$admins" | tee -a "$REPORT"
  # admins με ημερομηνία εγγραφής μετά τις 15/07/2026
  echo "$admins" | awk -F, 'NR>1 && $4>"2026-07-15"{print}' | while IFS= read -r line; do
    [ -n "$line" ] && hit "Admin δημιουργημένος μετά τη γνωστοποίηση: $line"
  done

  # --- 4) Κενά στην ακολουθία user-ID + orphaned usermeta -------------------
  gaps="$(run_wp "$owner" "$WPP" db query \
    "SELECT (t1.ID+1) AS gap_start FROM wp_users t1 LEFT JOIN wp_users t2 ON t1.ID+1=t2.ID WHERE t2.ID IS NULL AND t1.ID < (SELECT MAX(ID) FROM wp_users);" \
    --skip-column-names 2>/dev/null)"
  [ -n "$gaps" ] && warn "Κενά στη ροή user-ID (πιθανώς διαγραμμένος admin): $(echo $gaps | tr '\n' ' ')"

  orphan="$(run_wp "$owner" "$WPP" db query \
    "SELECT COUNT(*) FROM wp_usermeta um LEFT JOIN wp_users u ON um.user_id=u.ID WHERE u.ID IS NULL;" \
    --skip-column-names 2>/dev/null)"
  [ "${orphan:-0}" -gt 0 ] 2>/dev/null && hit "Orphaned usermeta rows: $orphan (ίχνη διαγραμμένου χρήστη)"

  # --- 5) Δηλητηριασμένο oembed_cache / customize_changeset -----------------
  susp_oembed="$(run_wp "$owner" "$WPP" db query \
    "SELECT COUNT(*) FROM wp_postmeta WHERE meta_key='_oembed_response' AND (meta_value LIKE '%O:8:\"WP_Post\"%' OR meta_value LIKE '%wp2shell%');" \
    --skip-column-names 2>/dev/null)"
  [ "${susp_oembed:-0}" -gt 0 ] 2>/dev/null && hit "Ύποπτα oembed_response rows (object injection): $susp_oembed"

  susp_cs="$(run_wp "$owner" "$WPP" db query \
    "SELECT ID,post_date,post_status FROM wp_posts WHERE post_type='customize_changeset' AND post_date>'2026-07-15';" \
    --skip-column-names 2>/dev/null)"
  [ -n "$susp_cs" ] && warn "customize_changeset μετά τη 15/07/2026 (μηχανισμός του exploit): $(echo "$susp_cs" | tr '\n' ' | ')"

  # --- 6) Ακεραιότητα αρχείων πυρήνα ----------------------------------------
  cks="$(run_wp "$owner" "$WPP" core verify-checksums 2>&1)"
  if echo "$cks" | grep -qi 'Success'; then
    ok "Core checksums ΟΚ"
  else
    hit "Core checksums ΑΠΕΤΥΧΑΝ — τροποποιημένα/επιπλέον αρχεία πυρήνα:"
    echo "$cks" | grep -Ei 'Warning|does not|should not exist' | tee -a "$REPORT"
  fi

  # --- 7) Ακεραιότητα plugins (όσα είναι στο wp.org repo) -------------------
  pck="$(run_wp "$owner" "$WPP" plugin verify-checksums --all 2>&1 | grep -Ei 'Warning|does not match')"
  [ -n "$pck" ] && warn "Plugin checksums με αποκλίσεις:" && echo "$pck" | tee -a "$REPORT"

  # --- 8) PHP αρχεία σε uploads (κλασικό σημάδι webshell) -------------------
  content_dir="$WPP/wp-content"
  php_in_uploads="$(find "$content_dir/uploads" -type f -name '*.php' 2>/dev/null)"
  [ -n "$php_in_uploads" ] && hit "PHP αρχεία μέσα στο uploads/ (δεν πρέπει να υπάρχουν):" && echo "$php_in_uploads" | tee -a "$REPORT"

  # --- 9) Πρόσφατα τροποποιημένα PHP (τελευταίες $DAYS_MODIFIED ημέρες) ------
  recent="$(find "$WPP" -type f -name '*.php' -mtime "-$DAYS_MODIFIED" 2>/dev/null | head -50)"
  if [ -n "$recent" ]; then
    warn "PHP τροποποιημένα τις τελευταίες $DAYS_MODIFIED ημέρες (έλεγξέ τα χειροκίνητα):"
    echo "$recent" | tee -a "$REPORT"
  fi

  # --- 10) Signatures γνωστών webshell / obfuscation ------------------------
  sig="$(grep -RIlE --include='*.php' \
      "eval\(|assert\(|base64_decode\(|gzinflate\(|gzuncompress\(|str_rot13\(|create_function\(|\bpreg_replace\b.*/e|\bpassthru\b|\bshell_exec\b|\bproc_open\b|\bpopen\b|\bFilesMan\b|\bc99\b|\br57\b|\bWSO\b|move_uploaded_file\(|php://input" \
      "$WPP" 2>/dev/null | head -60)"
  if [ -n "$sig" ]; then
    warn "Αρχεία με ύποπτα patterns (ΠΡΟΣΟΧΗ: πολλά είναι false positives — έλεγξε το context):"
    echo "$sig" | tee -a "$REPORT"
  fi
done

# --- Σύνοψη ------------------------------------------------------------------
hdr "ΣΥΝΟΨΗ"
if [ "$FOUND_ANY" -eq 1 ]; then
  log "${RED}Βρέθηκαν σοβαροί δείκτες. Δες τα [!] παραπάνω και το πλήρες report:${RST}"
  log "  $REPORT"
  log "Μην βασιστείς μόνο στο update — αν υπήρξε παραβίαση, το site παραμένει μολυσμένο."
else
  log "${GRN}Δεν βρέθηκαν άμεσα αποτυπώματα wp2shell. Παρ' όλα αυτά, επιβεβαίωσε versions & πρόσφατα αρχεία.${RST}"
fi
log ""
log "Επίσημος checker: https://wp2shell.com  (SearchLight Cyber)"
log "Forensic plugin: 'Compromise Scanner for wp2shell' (wordpress.org)"
