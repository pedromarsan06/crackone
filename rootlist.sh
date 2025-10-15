#!/usr/bin/env bash
# auditoria_deep_auto.sh
# Deep audit (no args) -> reduce false positives, per-stage files, brief vectors + suggested fixes
# Safe: no destructive automatic fixes. Interactive whitelist at end to "correct false positives".
# Author: Assistente
# Date: $(date +%Y-%m-%d)

set -o pipefail
shopt -s nullglob

TS=$(date +%Y%m%d_%H%M%S)
OUTDIR="."
WHITEL="${HOME}/.audit_whitelist"
mkdir -p "$OUTDIR"

# output files
F1="$OUTDIR/stage1_suid_sus_${TS}.txt"
F2="$OUTDIR/stage2_writable_risky_${TS}.txt"
F3="$OUTDIR/stage3_configs_risky_${TS}.txt"
F4="$OUTDIR/stage4_uncommon_suid_${TS}.txt"
: > "$F1"; : > "$F2"; : > "$F3"; : > "$F4"

# preset known-safe SUID paths (common system binaries)
read -r -d '' KNOWN_SUID <<'E' || true
/usr/bin/passwd
/bin/su
/usr/bin/su
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/sudo
E
declare -A KN_SUID; while read -r p; do [[ -n "$p" ]] && KN_SUID["$p"]=1; done <<<"$KNOWN_SUID"

# whitelist by user (path or basename) lines in ~/.audit_whitelist
declare -A USER_WH
if [[ -f "$WHITEL" ]]; then
  while read -r w; do [[ -n "$w" ]] && USER_WH["$w"]=1; done < "$WHITEL"
fi

# helper funcs
perm(){ stat -c "%a" "$1" 2>/dev/null || echo "??"; }
ownergrp(){ stat -c "%U:%G" "$1" 2>/dev/null || echo "?:?"; }
is_exec(){ [[ -f "$1" && -x "$1" ]] && return 0 || return 1; }
is_script(){ file "$1" 2>/dev/null | grep -qi 'script\|text'; }
is_symlink(){ [[ -L "$1" ]] && return 0 || return 1; }
suid_sgid_flags(){
  local p; p=$(stat -c "%a" "$1" 2>/dev/null || echo ""); p="${p##*(0)}"
  local out=""
  [[ ${#p} -eq 4 ]] && (( ${p:0:1} & 4 )) && out="${out}SUID"
  [[ ${#p} -eq 4 ]] && (( ${p:0:1} & 2 )) && out="${out}${out:+,}SGID"
  echo "${out}"
}
belongs_to_package(){
  # returns package name if dpkg or rpm knows the file
  if command -v dpkg >/dev/null 2>&1; then
    dpkg -S "$1" 2>/dev/null | sed -n '1p' | awk -F: '{print $1}'
  elif command -v rpm >/dev/null 2>&1; then
    rpm -qf "$1" 2>/dev/null
  else
    echo ""
  fi
}

mark_if_whitelisted(){ local p="$1"; local name=$(basename "$p"); if [[ -n "${USER_WH[$p]:-}" || -n "${USER_WH[$name]:-}" ]]; then return 0; fi; return 1; }

# vector tags and why -> short defensive note and suggested fix
# SUDO_PRIV, CRON_ABUSE, TMP_EXEC, SERVICE_PWN, PERSISTENCE

# ---------------- STAGE 1 ----------------
# Deep: scan system for SUID/SGID but filter to "really suspicious"
echo "PERM | OWNER:GROUP | FLAGS | PATH | VECTOR | RISK | NOTE | SUGGESTED_FIX" >> "$F1"
for rootdir in /bin /sbin /usr/bin /usr/sbin /usr/local/bin /opt /usr /home /tmp /var/tmp; do
  [[ -d "$rootdir" ]] || continue
  find "$rootdir" -xdev -type f \( -perm -4000 -o -perm -2000 \) -print0 2>/dev/null | while IFS= read -r -d '' f; do
    # skip whitelist entries
    mark_if_whitelisted "$f" && continue
    # skip known ok SUIDs unless in unusual location (e.g. user dir or /tmp)
    if [[ -n "${KN_SUID[$f]:-}" ]]; then
      case "$f" in
        /tmp/*|/var/tmp/*|/home/*|/root/*) ;; # still evaluate
        *) continue ;;
      esac
    fi
    flags=$(suid_sgid_flags "$f")
    [[ -z "$flags" ]] && continue
    pf=$(perm "$f"); og=$(ownergrp "$f")
    pkg=$(belongs_to_package "$f")
    syml=$(is_symlink "$f" && echo "symlink" || echo "")
    # additional false-positive reduction:
    # if file belongs to distro package and is in standard location and not script -> likely OK (skip)
    if [[ -n "$pkg" && "$pkg" != " " ]]; then
      # allow if package owner and standard path
      if ! is_script "$f" && [[ "$f" =~ ^(/bin|/usr/bin|/sbin|/usr/sbin)$ ]]; then
        continue
      fi
    fi
    # if script and SUID -> HIGH risk (scripts should not be SUID)
    if is_script "$f"; then
      vector="SUDO_PRIV|LPE"
      risk="CRÍTICO"
      note="SUID on script -> can be exploited for LPE if writable or interpreter abused"
      fix="chmod u-s '$f'; inspect content; chown root:root '$f'"
    else
      # non-script SUID in odd location: high risk vector depends on path
      case "$f" in
        */cron*|*/crontab*|/etc/cron.*/*) vector="CRON_ABUSE"; risk="ALTO"; note="SUID binary in cron path may be run by scheduled tasks"; fix="chmod u-s '$f'; verify and move/remove" ;;
        /tmp/*|/var/tmp/*) vector="TMP_EXEC"; risk="CRÍTICO"; note="SUID in /tmp — extremely risky; attacker-writable dir"; fix="chmod u-s '$f'; remove or relocate" ;;
        /home/*|/root/*) vector="PERSISTENCE"; risk="ALTO"; note="SUID in user dir — likely malicious"; fix="chmod u-s '$f'; investigate owner" ;;
        *) vector="SUID_BINARY"; risk="MÉDIO"; note="Non-standard SUID/SGID binary - verify source"; fix="verify package origin; chmod u-s if unknown" ;;
      esac
    fi
    printf "%s | %s | %s | %s | %s | %s | %s\n" "$pf" "$og" "$flags" "$f" "$vector" "$risk" "$note - $fix" >> "$F1"
  done
done

echo
echo "=== STAGE 1 (SUID/SGID suspicious) ==="
cat "$F1"

# ---------------- STAGE 2 ----------------
# World-writable but only truly dangerous entries:
# - executable files in /tmp /var/tmp
# - writable files in cron directories
# - writable files under /etc/init.d or service dirs
echo "PERM | OWNER:GROUP | FLAGS | PATH | VECTOR | RISK | NOTE | SUGGESTED_FIX" >> "$F2"
# exec files in tmp world-writable
for td in /tmp /var/tmp; do
  [[ -d "$td" ]] || continue
  find "$td" -xdev -type f -perm -o+w -print0 2>/dev/null | while IFS= read -r -d '' f; do
    mark_if_whitelisted "$f" && continue
    if is_exec "$f"; then
      pf=$(perm "$f"); og=$(ownergrp "$f"); fl=$(flags_of "$f")
      vector="TMP_EXEC"; risk="CRÍTICO"; note="Executable file in world-writable tmp - replace and chmod o-w"; fix="chmod o-w '$f'; move to safe location"
      printf "%s | %s | %s | %s | %s | %s | %s\n" "$pf" "$og" "$fl" "$f" "$vector" "$risk" "$note - $fix" >> "$F2"
    fi
  done
done
# cron/service writables
for sd in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/init.d /etc/rc?.d; do
  [[ -e "$sd" ]] || continue
  find "$sd" -maxdepth 2 -type f -perm -o+w -print0 2>/dev/null | while IFS= read -r -d '' f; do
    mark_if_whitelisted "$f" && continue
    pf=$(perm "$f"); og=$(ownergrp "$f"); fl=$(flags_of "$f")
    vector="CRON_ABUSE"; risk="CRÍTICO"; note="Writable script in cron/service directory can be scheduled by root"; fix="chmod o-w '$f'; chown root:root '$f'"
    printf "%s | %s | %s | %s | %s | %s | %s\n" "$pf" "$og" "$fl" "$f" "$vector" "$risk" "$note - $fix" >> "$F2"
  done
done
# writable runtime files (not all are dangerous) -> mark MEDIO
for pd in /var/run /var/lock /run; do
  [[ -d "$pd" ]] || continue
  find "$pd" -maxdepth 2 -type f -perm -o+w -print0 2>/dev/null | while IFS= read -r -d '' f; do
    mark_if_whitelisted "$f" && continue
    pf=$(perm "$f"); og=$(ownergrp "$f"); fl=$(flags_of "$f")
    vector="PERSISTENCE"; risk="MÉDIO"; note="Writable runtime/lock file - may be abused for persistence"; fix="chmod o-w '$f'; restart service"
    printf "%s | %s | %s | %s | %s | %s | %s\n" "$pf" "$og" "$fl" "$f" "$vector" "$risk" "$note - $fix" >> "$F2"
  done
done

echo
echo "=== STAGE 2 (world-writable risky) ==="
cat "$F2"

# ---------------- STAGE 3 ----------------
# Sensitive configs: only list if writable by others or not root-owned or bad perms
echo "TAG | PERM | OWNER:GROUP | PATH | VECTOR | RISK | NOTE | SUGGESTED_FIX" >> "$F3"
configs=(/etc/sudoers /etc/crontab /etc/cron.d /etc/ssh/sshd_config /etc/passwd /etc/shadow)
for c in "${configs[@]}"; do
  if [[ -e "$c" ]]; then
    mark_if_whitelisted "$c" && continue
    pf=$(perm "$c"); og=$(ownergrp "$c"); tag="CFG"
    bad=false; note=""
    if others_writable "$c"; then bad=true; note="${note}world-writable; "; fi
    if [[ "$og" != "root:root" ]]; then bad=true; note="${note}not root-owned; "; fi
    if [[ "$c" == "/etc/sudoers" ]] && [[ "$pf" != "440" && "$pf" != "600" ]]; then bad=true; note="${note}sudoers perms abnormal; "; fi
    if $bad; then
      vector="SUDO_PRIV"
      risk="CRÍTICO"
      fix="chown root:root '$c' && chmod 440 '$c' (or chmod 600 for keys)"
      printf "%s | %s | %s | %s | %s | %s | %s\n" "$tag" "$pf" "$og" "$c" "$vector" "$risk" "$note - $fix" >> "$F3"
    fi
  fi
done

echo
echo "=== STAGE 3 (sensitive configs risky) ==="
cat "$F3"

# ---------------- STAGE 4 ----------------
# Uncommon SUID/SGID binaries in non-standard places (user dirs, /opt, /usr/local)
echo "PERM | OWNER:GROUP | FLAGS | PATH | VECTOR | RISK | NOTE | SUGGESTED_FIX" >> "$F4"
for d in /usr/local/bin /opt /home /tmp; do
  [[ -d "$d" ]] || continue
  find "$d" -xdev -type f \( -perm -4000 -o -perm -2000 \) -print0 2>/dev/null | while IFS= read -r -d '' f; do
    mark_if_whitelisted "$f" && continue
    pf=$(perm "$f"); og=$(ownergrp "$f"); fl=$(suid_sgid_flags "$f")
    vector="SUID_BINARY"; risk="ALTO"
    note="Non-standard SUID/SGID binary in user or /opt - verify origin"
    fix="chmod u-s '$f'; verify package"
    printf "%s | %s | %s | %s | %s | %s | %s\n" "$pf" "$og" "$fl" "$f" "$vector" "$risk" "$note - $fix" >> "$F4"
  done
done

echo
echo "=== STAGE 4 (uncommon suid/sgid) ==="
cat "$F4"

# ---------------- interactive whitelist update (correction of false positives) ----------------
echo
echo "Scan complete. If an item is a FALSE POSITIVE and you want to ignore it in future runs, type its NUMBER to add to whitelist."
# collect all results into a numbered list for the user
ALL_LINES_FILE="${OUTDIR}/audit_all_lines_${TS}.tmp"
: > "$ALL_LINES_FILE"
n=0
echo "---- INDEXED ITEMS ----" >> "$ALL_LINES_FILE"
for f in "$F1" "$F2" "$F3" "$F4"; do
  while IFS= read -r line; do
    # skip headers/empty lines
    [[ -z "$line" ]] && continue
    if [[ "$line" == PERM* || "$line" == TAG* || "$line" == "==="* || "$line" == "----"* ]]; then
      continue
    fi
    ((n++))
    printf "%4d) %s\n" "$n" "$line" >> "$ALL_LINES_FILE"
  done < "$f"
done

if (( n == 0 )); then
  echo "No high-risk items found."
  exit 0
fi

# show compact indexed to terminal (first 200 lines)
echo "Top results (indexed):"
sed -n '1,200p' "$ALL_LINES_FILE" | sed -n '1,200p'
echo
read -r -p "Enter numbers to whitelist (comma-separated), or press ENTER to skip: " sel
if [[ -n "$sel" ]]; then
  IFS=',' read -ra parts <<< "$sel"
  for v in "${parts[@]}"; do
    v=$(echo "$v" | tr -d '[:space:]')
    if [[ "$v" =~ ^[0-9]+$ ]] && (( v>=1 && v<=n )); then
      item=$(sed -n "${v}p" "$ALL_LINES_FILE" | sed 's/^[[:space:]]*[0-9]\+\)\s*//')
      # attempt to extract path (last field after '|' likely)
      path=$(echo "$item" | awk -F"|" '{print $4}')
      if [[ -z "$path" ]]; then
        # fallback: entire line
        path=$(echo "$item")
      fi
      echo "$path" >> "$WHITEL"
      echo "Whitelisted: $path"
    fi
  done
  echo "Whitelist updated: $WHITEL"
else
  echo "No whitelist changes."
fi
rm -f "$ALL_LINES_FILE"

echo
echo "Report files:"
ls -1 "$F1" "$F2" "$F3" "$F4"
echo "Done."
