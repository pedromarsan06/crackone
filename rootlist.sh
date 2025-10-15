#!/usr/bin/env bash
# auditoria_staged_simple.sh
# Auditoria rápida, por etapas, sem paralelismo, sem extras
# Autor: Assistente
# Data: $(date +%Y-%m-%d)

set -o pipefail
shopt -s nullglob

# defaults
MODE="fast"
RUN_ALL=false
declare -a RUN_STAGES=()
OUTDIR="."
DATE_TAG=$(date +%Y%m%d_%H%M%S)

# dirs e paths
BIN_DIRS=(/bin /sbin /usr/bin /usr/sbin /usr/local/bin /opt)
CRIT_PATHS=(/etc /root /tmp /var)
SEARCH_ROOTS=(/usr /opt /home)

# whitelist executáveis padrão
read -r -d '' WHITEL <<'W' || true
sh
bash
dash
zsh
sudo
su
passwd
chmod
chown
cp
mv
rm
ls
find
grep
awk
sed
tar
gzip
gunzip
zip
unzip
ssh
scp
curl
wget
systemctl
service
mount
umount
crontab
cat
less
more
man
head
tail
echo
cut
sort
uniq
ip
ss
ping
W
declare -A WH; while read -r n; do [[ -n "$n" ]] && WH["$n"]=1; done <<< "$WHITEL"

# helpers
is_suid_sgid(){ local f="$1"; local perm; perm=$(stat -c "%a" "$f" 2>/dev/null || echo ""); [[ -z "$perm" ]] && return 1; perm="${perm##*(0)}"; local special=0; [[ ${#perm} -eq 4 ]] && special=${perm:0:1}; local r=""; (( special & 4 )) && r="${r}SUID"; (( special & 2 )) && r="${r}${r:+,}SGID"; [[ -n "$r" ]] && printf "%s" "$r" && return 0; return 1; }
others_writable(){ local f="$1"; local p; p=$(stat -c "%a" "$f" 2>/dev/null || echo ""); [[ -z "$p" ]] && return 1; p="${p##*(0)}"; local o=${p: -1}; (( o & 2 )) && return 0 || return 1; }
accessible(){ local f="$1"; [[ -e "$f" && -r "$f" ]] && return 0 || return 1; }

_find_root(){ local root="$1"; shift; find "$root" -xdev "$@" -not -path "/proc/*" -not -path "/sys/*" -not -path "/dev/*" 2>/dev/null ; }

# parse args
while [[ $# -gt 0 ]]; do
  case "$1" in
    --all) RUN_ALL=true; shift ;;
    --stage) RUN_STAGES+=("$2"); shift 2 ;;
    --deep) MODE="deep"; shift ;;
    -h|--help) echo "Usage: $0 [--all] [--stage N] [--deep]"; exit 0 ;;
    *) echo "Unknown: $1"; exit 1 ;;
  esac
done

if $RUN_ALL; then RUN_STAGES=(1 2 3 4); fi
if [[ ${#RUN_STAGES[@]} -eq 0 ]]; then
  [[ "$MODE" == "fast" ]] && RUN_STAGES=(1 2 3 4) || RUN_STAGES=(1 2 3 4)
fi

# -------------------
# STAGES
# -------------------

stage1_suids(){
  FILE="${OUTDIR}/stage1_suids_${DATE_TAG}.txt"
  echo "=== STAGE 1: SUID/SGID ===" > "$FILE"
  printf "%-6s | %-8s | %s\n" "PERM" "FLAGS" "CAMINHO" >> "$FILE"
  echo "----------------------------------------" >> "$FILE"

  dirs=("${BIN_DIRS[@]}")
  [[ "$MODE" == "deep" ]] && dirs+=("/usr" "/opt")

  for d in "${dirs[@]}"; do
    [[ -d "$d" ]] || continue
    depth=3; [[ "$MODE" == "fast" ]] && depth=3
    _find_root "$d" -maxdepth "$depth" -type f \( -perm -4000 -o -perm -2000 \) | while read -r f; do
      perm=$(stat -c "%a" "$f" 2>/dev/null || echo "??")
      flags=$(is_suid_sgid "$f")
      printf "%-6s | %-8s | %s\n" "$perm" "$flags" "$f" >> "$FILE"
    done
  done
  echo "[+] Stage 1 concluído: $FILE"
}

stage2_world_writable(){
  FILE="${OUTDIR}/stage2_world_writable_${DATE_TAG}.txt"
  echo "=== STAGE 2: WORLD-WRITABLE ===" > "$FILE"
  printf "%-6s | %s\n" "PERM" "CAMINHO" >> "$FILE"
  echo "----------------------------------------" >> "$FILE"

  for p in "${CRIT_PATHS[@]}"; do
    [[ -d "$p" ]] || continue
    depth=2; [[ "$MODE" == "deep" ]] && depth=4
    _find_root "$p" -maxdepth "$depth" | while read -r f; do
      if others_writable "$f"; then
        perm=$(stat -c "%a" "$f" 2>/dev/null || echo "??")
        printf "%-6s | %s\n" "$perm" "$f" >> "$FILE"
      fi
    done
  done
  echo "[+] Stage 2 concluído: $FILE"
}

stage3_configs(){
  FILE="${OUTDIR}/stage3_configs_${DATE_TAG}.txt"
  echo "=== STAGE 3: CONFIGS SENSÍVEIS ===" > "$FILE"
  printf "%-8s | %-6s | %s\n" "TAG" "PERM" "CAMINHO" >> "$FILE"
  echo "----------------------------------------" >> "$FILE"

  sens=(/etc/passwd /etc/shadow /etc/gshadow /etc/group /etc/sudoers /root/.ssh/id_rsa)
  for s in "${sens[@]}"; do
    if [[ -e "$s" ]]; then
      perm=$(stat -c "%a" "$s" 2>/dev/null || echo "??")
      echo "CRITICAL | $perm | $s" >> "$FILE"
    else
      echo "MISSING  | --  | $s" >> "$FILE"
    fi
  done
  echo "[+] Stage 3 concluído: $FILE"
}

stage4_incomuns(){
  FILE="${OUTDIR}/stage4_incomuns_${DATE_TAG}.txt"
  echo "=== STAGE 4: EXECUTÁVEIS INCOMUNS ===" > "$FILE"
  printf "%-8s | %-6s | %s\n" "TAG" "PERM" "CAMINHO" >> "$FILE"
  echo "----------------------------------------" >> "$FILE"

  search_dirs=("${BIN_DIRS[@]}")
  [[ "$MODE" == "deep" ]] && search_dirs+=("/usr" "/opt" "/usr/local/bin" "/home")

  for bd in "${search_dirs[@]}"; do
    [[ -d "$bd" ]] || continue
    depth=2; [[ "$MODE" == "deep" ]] && depth=3
    _find_root "$bd" -maxdepth "$depth" -type f | while read -r f; do
      [[ -x "$f" ]] || continue
      name=$(basename "$f")
      base="${name%.*}"
      [[ -n "${WH[$name]:-}" || -n "${WH[$base]:-}" ]] && continue
      perm=$(stat -c "%a" "$f" 2>/dev/null || echo "??")
      flags=$(is_suid_sgid "$f")
      tag="INCOMUM"; [[ -n "$flags" ]] && tag="INCOMUM-SUID"
      printf "%-8s | %-6s | %s\n" "$tag" "$perm" "$f" >> "$FILE"
    done
  done
  echo "[+] Stage 4 concluído: $FILE"
}

# -------------------
# RUNNER
# -------------------
for s in "${RUN_STAGES[@]}"; do
  case "$s" in
    1) stage1_suids ;;
    2) stage2_world_writable ;;
    3) stage3_configs ;;
    4) stage4_incomuns ;;
    *) echo "Unknown stage $s" ;;
  esac
done

echo "[+] Auditoria concluída. Arquivos gerados por etapa em $OUTDIR"
