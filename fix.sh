#!/usr/bin/env bash
# check_privs.sh
# Varre a partir de / (sem sudo), suprime erros e gera test.txt
# Gera:
#  - Parte A: listas por categoria
#  - Parte B: lista CRÍTICA com avaliação, mitigação e erros comuns por item
# Não faz alterações no sistema.

OUT="./test.txt"
TMPDIR=$(mktemp -d)
: > "$OUT"

echo "Relatório de permissões defensivo - gerado: $(date)" >> "$OUT"
echo "Escopo: / (sem sudo). Erros suprimidos." >> "$OUT"
echo "================================================================" >> "$OUT"

# Helper para executar find e salvar
run_find() {
  local tag="$1"; shift
  local cmd="$*"
  eval "$cmd" 2>/dev/null > "$TMPDIR/${tag}.list" || true
}

# ------------- Coleta -------------
run_find "dirs_1777" "find / -xdev -type d -perm 1777 -printf '%M %m %p\n'"
run_find "files_setuid" "find / -xdev -type f -perm -4000 -printf '%M %m %p\n'"
run_find "files_setgid" "find / -xdev -type f -perm -2000 -printf '%M %m %p\n'"
run_find "files_setuid_setgid" "find / -xdev -type f -perm -6000 -printf '%M %m %p\n'"
run_find "files_exec" "find / -xdev -type f -perm /111 -printf '%M %m %p\n'"
run_find "files_sh" "find / -xdev -type f -iname '*.sh' -printf '%M %m %p\n'"
run_find "world_writable" "find / -xdev -perm -o+w -printf '%M %m %p\n'"
run_find "files_0777" "find / -xdev -type f -perm 0777 -printf '%M %m %p\n'"
run_find "dirs_0777" "find / -xdev -type d -perm 0777 -printf '%M %m %p\n'"

# combinações críticas
run_find "setuid_o_w" "find / -xdev -type f -perm -4000 -perm -o+w -printf '%M %m %p\n'"
run_find "setgid_o_w" "find / -xdev -type f -perm -2000 -perm -o+w -printf '%M %m %p\n'"
# ?777 pattern (1-7 as first digit and last three 777)
run_find "weird_files_q777" "find / -xdev -type f -printf '%m %p\n' | awk '\$1 ~ /^[1-7]777$/ { print \$1 \" \" \$2 }'"
run_find "weird_dirs_q777" "find / -xdev -type d -printf '%m %p\n' | awk '\$1 ~ /^[1-7]777$/ { print \$1 \" \" \$2 }'"

# Top críticos (exec + o+w and setuid)
run_find "top_exec_o_w" "find / -xdev -type f -perm /111 -perm -o+w -printf '%M %m %p\n' | head -n 200"
run_find "top_setuid" "find / -xdev -type f -perm -4000 -printf '%M %m %p\n' | head -n 200"

# ------------- Função para avaliação defensiva genérica -------------
eval_header() {
  local title="$1"
  local count="$2"
  echo "== $title : $count items" >> "$OUT"
}

# ------------- Parte A: listas simples por categoria -------------
echo "" >> "$OUT"
echo "PARTE A - LISTAS POR CATEGORIA" >> "$OUT"
echo "---------------------------------------------------------------" >> "$OUT"

for TAG in dirs_1777 files_setuid files_setgid files_setuid_setgid files_exec files_sh world_writable files_0777 dirs_0777; do
  LIST="$TMPDIR/${TAG}.list"
  COUNT=$(wc -l < "$LIST" 2>/dev/null || echo 0)
  eval_header "$TAG" "$COUNT"
  if [ "$COUNT" -gt 0 ]; then
    # lista limitada para não encher demais (até 1000 linhas por categoria)
    sed -n '1,1000p' "$LIST" >> "$OUT"
    if [ "$(wc -l < "$LIST")" -gt 1000 ]; then
      echo "... (lista truncada)" >> "$OUT"
    fi
  else
    echo "(nenhum item encontrado ou inacessível ao usuário)" >> "$OUT"
  fi
  echo "---------------------------------------------------------------" >> "$OUT"
done

# ------------- Parte B: lista crítica com avaliação por item -------------
echo "" >> "$OUT"
echo "PARTE B - LISTA CRÍTICA (EVAL, MITIGAÇÃO E ERROS COMUNS)" >> "$OUT"
echo "Nota: recomendações são defensivas; não altere sem entender a função do arquivo." >> "$OUT"
echo "---------------------------------------------------------------" >> "$OUT"

# Função que escreve avaliação/mitigação/erros comuns para um tipo
write_assessment() {
  local category="$1"
  local path="$2"
  case "$category" in
    setuid)
      echo "ITEM: $path" >> "$OUT"
      echo "Risco: ALTO — binário com setuid (pode executar com privilégios do dono, frequentemente root)." >> "$OUT"
      echo "Mitigação recomendada: verificar proprietário/do que é; se não for necessário, remover setuid: chmod u-s \"$path\"." >> "$OUT"
      echo "Erros comuns que levam a risco: instalar binários de fontes não confiáveis como setuid; permissões world-writable; falta de revisão do dono." >> "$OUT"
      ;;
    setgid)
      echo "ITEM: $path" >> "$OUT"
      echo "Risco: ALTO — setgid permite herança de grupo; pode expor recursos do grupo." >> "$OUT"
      echo "Mitigação recomendada: revisar necessidade, remover com chmod g-s se indevido." >> "$OUT"
      echo "Erros comuns: diretórios de projeto com group writable indevido; scripts que assumem confiança do grupo." >> "$OUT"
      ;;
    setuid_o_w)
      echo "ITEM: $path" >> "$OUT"
      echo "Risco: CRÍTICO — setuid + world-writable. Qualquer usuário pode alterar o binário e obter escalonamento." >> "$OUT"
      echo "Mitigação recomendada: isolar imediatamente, alterar permissão (chmod o-w \"$path\") e remover setuid se não for necessário." >> "$OUT"
      echo "Erros comuns: scripts de deploy que alteram permissões recursivamente; uso indevido de 'chmod 777' em binários." >> "$OUT"
      ;;
    setgid_o_w)
      echo "ITEM: $path" >> "$OUT"
      echo "Risco: CRÍTICO — setgid + world-writable. Alto risco de modificação por terceiros." >> "$OUT"
      echo "Mitigação recomendada: chmod o-w \"$path\"; revisar dono/grupo." >> "$OUT"
      echo "Erros comuns: diretórios compartilhados mal configurados; permissões aplicadas sem checar recursivamente." >> "$OUT"
      ;;
    q777_file)
      echo "ITEM: $path" >> "$OUT"
      echo "Risco: ALTO — permissão do tipo ?777. Dependendo do bit especial pode permitir escrita/execução indevida e bits especiais." >> "$OUT"
      echo "Mitigação recomendada: detectar se o primeiro dígito é setuid/setgid/sticky e agir: ex: chmod 0777 -> evitar; ajustar para 0755/0644 conforme necessidade." >> "$OUT"
      echo "Erros comuns: copiar arquivos com permissões amplas; usar ferramentas que setam 777 por padrão." >> "$OUT"
      ;;
    world_writable)
      echo "ITEM: $path" >> "$OUT"
      echo "Risco: ALTO — world-writable permite qualquer usuário modificar o arquivo/diretório." >> "$OUT"
      echo "Mitigação recomendada: remover write para others: chmod o-w \"$path\"; revisar dono e necessidade de escrita global." >> "$OUT"
      echo "Erros comuns: scripts de instalação que usam 'chmod -R 777'; permissões herdadas em sistemas compartilhados." >> "$OUT"
      ;;
    exec_o_w)
      echo "ITEM: $path" >> "$OUT"
      echo "Risco: CRÍTICO — executável e world-writable. Pode ser substituído por um binário malicioso." >> "$OUT"
      echo "Mitigação recomendada: chmod o-w \"$path\"; se for necessário, mover para local controlado e ajustar dono/perm." >> "$OUT"
      echo "Erros comuns: programas colocados em /usr/local/bin com permissões abertas; CI/CD que publica artefatos com 777." >> "$OUT"
      ;;
    sh_script)
      echo "ITEM: $path" >> "$OUT"
      echo "Risco: MÉDIO — scripts .sh com permissões inseguras podem ser editados para executar comandos." >> "$OUT"
      echo "Mitigação recomendada: revisar conteúdo, limitar escrita a dono; usar chmod 0755/0644 conforme necessário." >> "$OUT"
      echo "Erros comuns: confiabilidade cega em scripts baixados; falta de verificação de shebang e input validation." >> "$OUT"
      ;;
    dirs_1777)
      echo "ITEM: $path" >> "$OUT"
      echo "Risco: BAIXO/ESPERADO — diretórios 1777 são comuns (ex: /tmp). Verificar apenas se aparecem em locais sensíveis." >> "$OUT"
      echo "Mitigação recomendada: manter dono root e sticky bit; não usar 1777 em diretórios de configuração." >> "$OUT"
      ;;
    *)
      echo "ITEM: $path" >> "$OUT"
      echo "Risco: Revisar manualmente." >> "$OUT"
      ;;
  esac
  echo "" >> "$OUT"
}

# Processa cada lista crítica e escreve avaliações
# setuid
if [ -s "$TMPDIR/files_setuid.list" ]; then
  while IFS= read -r line; do
    # formato: %M %m %p -> perms symbolic, octal, path
    path=$(echo "$line" | awk '{ $1=""; $2=""; sub(/^  */, ""); print }')
    write_assessment "setuid" "$path"
  done < "$TMPDIR/files_setuid.list"
fi

# setgid
if [ -s "$TMPDIR/files_setgid.list" ]; then
  while IFS= read -r line; do
    path=$(echo "$line" | awk '{ $1=""; $2=""; sub(/^  */, ""); print }')
    write_assessment "setgid" "$path"
  done < "$TMPDIR/files_setgid.list"
fi

# setuid + o+w
if [ -s "$TMPDIR/setuid_o_w.list" ]; then
  while IFS= read -r line; do
    path=$(echo "$line" | awk '{ $1=""; $2=""; sub(/^  */, ""); print }')
    write_assessment "setuid_o_w" "$path"
  done < "$TMPDIR/setuid_o_w.list"
fi

# setgid + o+w
if [ -s "$TMPDIR/setgid_o_w.list" ]; then
  while IFS= read -r line; do
    path=$(echo "$line" | awk '{ $1=""; $2=""; sub(/^  */, ""); print }')
    write_assessment "setgid_o_w" "$path"
  done < "$TMPDIR/setgid_o_w.list"
fi

# ?777 files
if [ -s "$TMPDIR/weird_files_q777.list" ]; then
  while IFS= read -r line; do
    octal=$(echo "$line" | awk '{print $1}')
    path=$(echo "$line" | awk '{ $1=""; sub(/^ /, ""); print }')
    write_assessment "q777_file" "$octal $path"
  done < "$TMPDIR/weird_files_q777.list"
fi

# weird dirs ?777
if [ -s "$TMPDIR/weird_dirs_q777.list" ]; then
  while IFS= read -r line; do
    octal=$(echo "$line" | awk '{print $1}')
    path=$(echo "$line" | awk '{ $1=""; sub(/^ /, ""); print }')
    write_assessment "dirs_1777" "$octal $path"
  done < "$TMPDIR/weird_dirs_q777.list"
fi

# world writable (files & dirs)
if [ -s "$TMPDIR/world_writable.list" ]; then
  while IFS= read -r line; do
    path=$(echo "$line" | awk '{ $1=""; $2=""; sub(/^  */, ""); print }' || true)
    # sometimes find prints only path if using different printf; handle fallback
    [ -z "$path" ] && path="$line"
    write_assessment "world_writable" "$path"
  done < "$TMPDIR/world_writable.list"
fi

# exec + o+w
if [ -s "$TMPDIR/top_exec_o_w.list" ]; then
  while IFS= read -r line; do
    path=$(echo "$line" | awk '{ $1=""; $2=""; sub(/^  */, ""); print }' || true)
    [ -z "$path" ] && path="$line"
    write_assessment "exec_o_w" "$path"
  done < "$TMPDIR/top_exec_o_w.list"
fi

# scripts .sh
if [ -s "$TMPDIR/files_sh.list" ]; then
  while IFS= read -r line; do
    path=$(echo "$line" | awk '{ $1=""; $2=""; sub(/^  */, ""); print }' || true)
    [ -z "$path" ] && path="$line"
    write_assessment "sh_script" "$path"
  done < "$TMPDIR/files_sh.list"
fi

echo "" >> "$OUT"
echo "---------------------------------------------------------------" >> "$OUT"

# ------------- Resumo final com contagens rápidas -------------
echo "" >> "$OUT"
echo "RESUMO (contagens rápidas):" >> "$OUT"
for f in dirs_1777 files_setuid files_setgid files_setuid_setgid files_exec files_sh world_writable files_0777 dirs_0777 setuid_o_w setgid_o_w weird_files_q777 weird_dirs_q777 top_exec_o_w top_setuid; do
  c=$(wc -l < "$TMPDIR/${f}.list" 2>/dev/null || echo 0)
  printf "%-30s : %s\n" "$f" "$c" >> "$OUT"
done

echo "" >> "$OUT"
echo "RECOMENDAÇÕES GERAIS:" >> "$OUT"
echo " - Não remova bits especiais (setuid/setgid) de binários do sistema sem entender sua função." >> "$OUT"
echo " - Para remover setuid: chmod u-s /caminho/arquivo" >> "$OUT"
echo " - Para remover setgid: chmod g-s /caminho/arquivo" >> "$OUT"
echo " - Para remover escrita para 'others': chmod o-w /caminho/arquivo" >> "$OUT"
echo " - Para scripts, reveja conteúdo (shebang, checagem de input) antes de confiar." >> "$OUT"
echo " - Se for servidor/prod, consulte o administrador antes de ações." >> "$OUT"

echo "" >> "$OUT"
echo "Relatório salvo em: $OUT" >> "$OUT"
echo "Arquivos temporários em: $TMPDIR (mantidos para inspeção)." >> "$OUT"

# Imprime no terminal os top 20 críticos (se existirem)
echo ""
echo "Top 20 itens críticos (exec + o+w e setuid) — exibidos no terminal:"
echo "---------------------------------------------------------------"
[ -s "$TMPDIR/top_exec_o_w.list" ] && { head -n 20 "$TMPDIR/top_exec_o_w.list"; }
[ -s "$TMPDIR/top_setuid.list" ] && { head -n 20 "$TMPDIR/top_setuid.list"; }
echo "---------------------------------------------------------------"
echo "Relatório completo: $OUT"
