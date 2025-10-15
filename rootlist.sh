#!/usr/bin/env bash
# Script de Auditoria de Segurança - Detecção de Permissões Perigosas
# Autor: Assistente (versão revisada)
# Gerado em: $(date +%Y-%m-%d %T)

set -o errexit
set -o pipefail
set -o nounset

# Cores para output
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Parâmetros (pode trocar/ajustar)
TARGETS=(/ /etc /var /usr /bin /sbin /opt /home /root /tmp /var/tmp /dev/shm)
OUTPUT_DIR="."
OUTPUT_FILE="${OUTPUT_DIR}/auditoria_seguranca_completa_$(date +%Y%m%d_%H%M%S).txt"

# Verifica se tem permissão de escrita no output_dir
if ! touch "${OUTPUT_DIR}/.auditoria_test" 2>/dev/null; then
    echo -e "${RED}Erro: sem permissão para escrever em ${OUTPUT_DIR}.${NC}"
    exit 1
else
    rm -f "${OUTPUT_DIR}/.auditoria_test"
fi

echo -e "${BLUE}=== INICIANDO AUDITORIA DE SEGURANÇA COMPLETA ===${NC}"
echo "Analisando sistema em busca de permissões perigosas..."
echo "Arquivo de saída: $OUTPUT_FILE"
echo

# Função para classificar risco baseada em permissão octal (ex: 0755, 1777, 4755)
classificar_risco() {
    local permissao="$1"   # string como "755" ou "4755"
    local caminho="$2"
    local tipo="$3"        # "arquivo" ou "diretorio"

    # Normalizar: remover zeros à esquerda se existirem
    permissao="${permissao##*(0)}"

    # Se for 3 dígitos (ex: 755), pad com 0 à esquerda para facilitar
    if [[ ${#permissao} -eq 3 ]]; then
        special=0
        perms="$permissao"
    else
        special="${permissao:0:1}"
        perms="${permissao:1:3}"
    fi

    # obter dígito "others"
    others=$((10#${perms:2:1}))

    # verifica write para outros (bit 2)
    if (( others & 2 )); then
        # Se arquivo em paths sensíveis -> crítico
        if [[ "$caminho" =~ ^(/etc/|/bin/|/sbin/|/usr/bin/|/usr/sbin/|/root/) ]]; then
            echo "CRÍTICO"
            return
        else
            if [[ "$tipo" == "diretorio" ]]; then
                echo "MUITO ALTO"
                return
            else
                echo "ALTO"
                return
            fi
        fi
    fi

    # 777 total (todos com rwx)
    if [[ "${perms}" == "777" ]]; then
        echo "CRÍTICO"
        return
    fi

    # SUID (bit 4 no special)
    if (( special & 4 )); then
        if [[ "$caminho" =~ ^(/bin/|/sbin/|/usr/bin/|/usr/sbin/) && "$tipo" == "arquivo" ]]; then
            echo "ALTO"
            return
        else
            echo "MÉDIO"
            return
        fi
    fi

    # SGID (bit 2 no special) e sticky (bit 1)
    if (( special & 2 )); then
        if [[ "$tipo" == "diretorio" ]]; then
            echo "ALTO"
            return
        else
            echo "MÉDIO"
            return
        fi
    fi

    # Sticky bit em diretórios (ex: /tmp costuma ter sticky)
    if (( special & 1 )) && [[ "$tipo" == "diretorio" ]]; then
        echo "BAIXO"
        return
    fi

    echo "BAIXO"
}

# Função para descrever binário (apenas exemplos)
descrever_binario() {
    local binario="$1"
    local tipo="$2"
    case "$(basename "$binario")" in
        passwd) echo "Utilitário para alterar senhas de usuário" ;;
        su) echo "Comando para trocar de usuário" ;;
        sudo) echo "Executar comandos como outro usuário" ;;
        chmod) echo "Alterar permissões de arquivos" ;;
        chown) echo "Alterar proprietário de arquivos" ;;
        mount) echo "Montar sistemas de arquivos" ;;
        ssh|scp) echo "Cliente SSH" ;;
        crontab) echo "Agendador de tarefas" ;;
        *) 
            if [[ "$tipo" == "diretorio" ]]; then
                echo "Diretório do sistema"
            else
                echo "Binário/Arquivo do sistema"
            fi
            ;;
    esac
}

declare -a resultados=()

echo -e "${YELLOW}Procurando arquivos e diretórios perigosos...${NC}"

# 1) Arquivos com SUID/SGID (find já filtra)
while IFS= read -r -d '' arquivo; do
    # proteção extra: pular links simbólicos
    [[ -L "$arquivo" ]] && continue
    permissao=$(stat -c "%a" "$arquivo" 2>/dev/null || echo "")
    [[ -z "$permissao" ]] && continue
    risco=$(classificar_risco "$permissao" "$arquivo" "arquivo")
    descricao=$(descrever_binario "$arquivo" "arquivo")
    resultados+=("$risco|SUID/SGID|$arquivo|$permissao|$descricao")
done < <(find "${TARGETS[@]}" -xdev -type f \( -perm -4000 -o -perm -2000 \) -not -path "/proc/*" -not -path "/sys/*" -not -path "/dev/*" -print0 2>/dev/null || true)

# 2) Diretórios com write para others (inclui 777)
while IFS= read -r -d '' diretorio; do
    [[ -L "$diretorio" ]] && continue
    permissao=$(stat -c "%a" "$diretorio" 2>/dev/null || echo "")
    [[ -z "$permissao" ]] && continue
    # check others write
    perms="${permissao##*(0)}"
    # pad
    if [[ ${#perms} -eq 3 ]]; then others_dig="${perms:2:1}"; else others_dig="${perms:2:1}"; fi
    if (( 10#$others_dig & 2 )); then
        risco=$(classificar_risco "$permissao" "$diretorio" "diretorio")
        descricao=$(descrever_binario "$diretorio" "diretorio")
        resultados+=("$risco|DIRETÓRIO W|$diretorio|$permissao|$descricao - Write para outros usuários")
    fi
done < <(find "${TARGETS[@]}" -xdev -type d -not -path "/proc/*" -not -path "/sys/*" -not -path "/dev/*" -print0 2>/dev/null || true)

# 3) Arquivos em locais sensíveis com write para others
sensitive_paths=(/etc /var /usr /bin /sbin /opt /home /root)
while IFS= read -r -d '' arquivo; do
    [[ -L "$arquivo" ]] && continue
    permissao=$(stat -c "%a" "$arquivo" 2>/dev/null || echo "")
    [[ -z "$permissao" ]] && continue
    perms="${permissao##*(0)}"
    if [[ ${#perms} -ge 3 ]]; then others_dig="${perms:2:1}"; else others_dig="0"; fi
    if (( 10#$others_dig & 2 )); then
        risco=$(classificar_risco "$permissao" "$arquivo" "arquivo")
        descricao=$(descrever_binario "$arquivo" "arquivo")
        resultados+=("$risco|ARQUIVO W|$arquivo|$permissao|$descricao - Write para outros usuários")
    fi
done < <(find "${sensitive_paths[@]}" -xdev -type f -not -path "/proc/*" -not -path "/sys/*" -not -path "/dev/*" -print0 2>/dev/null || true)

# 4) Configurações sensíveis (lista)
config_sensiveis=(
    "/etc/passwd"
    "/etc/shadow"
    "/etc/gshadow"
    "/etc/group"
    "/etc/sudoers"
    "/etc/ssh/sshd_config"
    "/root/.bashrc"
    "/root/.ssh/authorized_keys"
    "/root/.ssh/id_rsa"
    "/etc/crontab"
)
for config in "${config_sensiveis[@]}"; do
    for expanded in $config; do
        [[ -e "$expanded" ]] || continue
        permissao=$(stat -c "%a" "$expanded" 2>/dev/null || echo "")
        [[ -z "$permissao" ]] && continue
        perms="${permissao##*(0)}"
        if [[ ${#perms} -ge 3 ]]; then others_dig="${perms:2:1}"; else others_dig="0"; fi
        if (( 10#$others_dig & 2 )) || [[ "$permissao" == "777" ]]; then
            risco="CRÍTICO"
            descricao="Arquivo de configuração sensível"
            resultados+=("$risco|CONFIGURAÇÃO|$expanded|$permissao|$descricao com permissões perigosas")
        fi
    done
done

# 5) Executáveis em /tmp etc.
dirs_tmp=(/tmp /var/tmp /dev/shm)
for tmp_dir in "${dirs_tmp[@]}"; do
    [[ -d "$tmp_dir" ]] || continue
    while IFS= read -r -d '' arquivo; do
        [[ -L "$arquivo" ]] && continue
        [[ -f "$arquivo" && -x "$arquivo" ]] || continue
        permissao=$(stat -c "%a" "$arquivo" 2>/dev/null || echo "")
        risco=$(classificar_risco "$permissao" "$arquivo" "arquivo")
        descricao="Script/binário em diretório temporário"
        resultados+=("$risco|TMP EXECUTÁVEL|$arquivo|$permissao|$descricao")
    done < <(find "$tmp_dir" -xdev -type f -executable -not -path "*/.*" -print0 2>/dev/null || true)
done

# 6) Arquivos ocultos em home dirs
while IFS= read -r -d '' home_dir; do
    [[ -d "$home_dir" ]] || continue
    while IFS= read -r -d '' hidden_file; do
        [[ -f "$hidden_file" ]] || continue
        permissao=$(stat -c "%a" "$hidden_file" 2>/dev/null || echo "")
        if [[ -x "$hidden_file" ]] || { perms="${permissao##*(0)}"; others_dig="${perms:2:1}"; (( 10#$others_dig & 2 )); }; then
            risco=$(classificar_risco "$permissao" "$hidden_file" "arquivo")
            descricao="Arquivo oculto com permissões perigosas"
            resultados+=("$risco|ARQUIVO OCULTO|$hidden_file|$permissao|$descricao")
        fi
    done < <(find "$home_dir" -maxdepth 1 -name ".*" -type f -print0 2>/dev/null || true)
done < <(find /home /root -maxdepth 1 -mindepth 1 -type d -print0 2>/dev/null || true)

# Ordenar resultados por risco simples (peso)
obter_peso_risco() {
    case "$1" in
        "CRÍTICO") echo 1 ;;
        "MUITO ALTO") echo 2 ;;
        "ALTO") echo 3 ;;
        "MÉDIO") echo 4 ;;
        "BAIXO") echo 5 ;;
        *) echo 6 ;;
    esac
}

# Bubble sort (suficiente para arrays de tamanho moderado)
for ((i=0; i<${#resultados[@]}; i++)); do
    for ((j=i+1; j<${#resultados[@]}; j++)); do
        ri=$(obter_peso_risco "${resultados[i]%%|*}")
        rj=$(obter_peso_risco "${resultados[j]%%|*}")
        if (( ri > rj )); then
            tmp="${resultados[i]}"; resultados[i]="${resultados[j]}"; resultados[j]="$tmp"
        fi
    done
done

# Gerar relatório
{
    echo "===================================================================="
    echo "RELATÓRIO DE AUDITORIA DE SEGURANÇA COMPLETA"
    echo "Data: $(date)"
    echo "Sistema: $(uname -a)"
    echo "===================================================================="
    echo
    echo "RESUMO:"
    echo "Total de itens encontrados: ${#resultados[@]}"
    echo
    echo "DETALHES:"
    echo
    printf "%-12s | %-18s | %-70s | %-8s | %s\n" "RISCO" "TIPO" "CAMINHO" "PERM" "DESCRIÇÃO"
    echo "------------|--------------------|-----------------------------------------------------------------------|----------|----------------"
} > "$OUTPUT_FILE"

for resultado in "${resultados[@]}"; do
    IFS='|' read -r risco tipo caminho permissao descricao <<< "$resultado"
    case "$risco" in
        "CRÍTICO") cor=$RED ;;
        "MUITO ALTO") cor=$RED ;;
        "ALTO") cor=$YELLOW ;;
        "MÉDIO") cor=$GREEN ;;
        *) cor=$CYAN ;;
    esac

    # Mostrar apenas os níveis mais críticos no terminal
    if [[ "$risco" == "CRÍTICO" || "$risco" == "MUITO ALTO" || "$risco" == "ALTO" ]]; then
        printf "${cor}%-12s${NC} | %-18s | %-70s | %-8s | %s\n" "$risco" "$tipo" "$(echo "$caminho" | cut -c1-70)" "$permissao" "$descricao"
    fi

    printf "%-12s | %-18s | %-70s | %-8s | %s\n" "$risco" "$tipo" "$caminho" "$permissao" "$descricao" >> "$OUTPUT_FILE"
done

# Rodapé resumido (padrões e recomendações)
{
    echo
    echo "===================================================================="
    echo "RECOMENDAÇÕES DE SEGURANÇA (RESUMO)"
    echo " - Remova escrita para 'others' quando não for necessária: chmod o-w <arquivo|dir>"
    echo " - Diretórios públicos: use sticky bit: chmod +t <dir> (ex: /tmp)"
    echo " - Remova SUID/SGID se não for essencial: chmod u-s <arquivo> ; chmod g-s <arquivo>"
    echo " - Arquivos sensíveis: chmod 600 <arquivo>"
    echo " - Evite executáveis em /tmp e similares; considere noexec,nosuid em fstab"
    echo
    echo "Comandos úteis:"
    echo "   chmod o-w <arquivo>"
    echo "   chmod 755 <diretório>"
    echo "   chmod 644 <arquivo>"
    echo "   chmod u-s <arquivo>"
    echo "   chmod g-s <arquivo>"
    echo "   chown root:root <arquivo>"
    echo "===================================================================="
} >> "$OUTPUT_FILE"

echo -e "${GREEN}AUDITORIA CONCLUÍDA! Relatório salvo em: ${OUTPUT_FILE}${NC}"
echo -e "${GREEN}Total de itens identificados: ${#resultados[@]}${NC}"
