#!/bin/bash

# Script de Auditoria de Segurança - Detecção de Permissões Perigosas
# Autor: Assistente
# Data: $(date +%Y-%m-%d)

# Cores para output
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Arquivo de saída
OUTPUT_FILE="auditoria_seguranca_completa_$(date +%Y%m%d_%H%M%S).txt"

echo -e "${BLUE}=== INICIANDO AUDITORIA DE SEGURANÇA COMPLETA ===${NC}"
echo "Analisando sistema em busca de permissões perigosas..."
echo "Arquivo de saída: $OUTPUT_FILE"
echo

# Função para verificar risco
classificar_risco() {
    local permissao="$1"
    local caminho="$2"
    local tipo="$3"
    
    # Converter permissão para octal se for string simbólica
    if [[ "$permissao" =~ ^[rwx-]{9}$ ]]; then
        permissao=$(echo "$permissao" | sed 's/^.//' | sed 's/^.//') # Remover primeiro e segundo caractere para testar others
    fi
    
    # Critério: Permissão 777
    if [[ "$permissao" == "777" ]]; then
        echo "CRÍTICO"
    # Critério: Qualquer permissão que dá write para others (writable by others)
    elif [[ "$permissao" =~ ^[0-9]{3}$ ]] && [[ $((permissao % 10 & 2)) -ne 0 ]]; then
        if [[ "$caminho" =~ /etc/|/bin/|/sbin/|/usr/bin/|/usr/sbin/|/root/ ]]; then
            echo "CRÍTICO"
        else
            echo "ALTO"
        fi
    # Critério: SUID em binários sensíveis
    elif [[ "$permissao" =~ ^[0-9]{4}$ && $((0x$permissao & 04000)) -ne 0 ]] && [[ "$tipo" == "arquivo" ]]; then
        if [[ "$caminho" =~ /bin/|/sbin/|/usr/bin/|/usr/sbin/ ]]; then
            echo "ALTO"
        else
            echo "MÉDIO"
        fi
    # Critério: SGID em diretórios sensíveis
    elif [[ "$permissao" =~ ^[0-9]{4}$ && $((0x$permissao & 02000)) -ne 0 ]] && [[ "$tipo" == "diretorio" ]]; then
        if [[ "$caminho" =~ /etc/|/var/|/home/|/root/ ]]; then
            echo "ALTO"
        else
            echo "MÉDIO"
        fi
    # Critério: Diretório com write para others
    elif [[ "$tipo" == "diretorio" ]] && [[ "$permissao" =~ ^[0-9]{3}$ ]] && [[ $((permissao % 10 & 2)) -ne 0 ]]; then
        echo "MUITO ALTO"
    else
        echo "BAIXO"
    fi
}

# Função para descrever o binário
descrever_binario() {
    local binario="$1"
    local tipo="$2"
    
    case "$(basename "$binario")" in
        "passwd") echo "Utilitário para alterar senhas de usuário" ;;
        "su") echo "Comando para trocar de usuário" ;;
        "sudo") echo "Executar comandos como outro usuário" ;;
        "chmod") echo "Alterar permissões de arquivos" ;;
        "chown") echo "Alterar proprietário de arquivos" ;;
        "mount") echo "Montar sistemas de arquivos" ;;
        "umount") echo "Desmontar sistemas de arquivos" ;;
        "ping") echo "Testar conectividade de rede" ;;
        "find") echo "Buscar arquivos no sistema" ;;
        "bash"|"sh"|"dash") echo "Shell do sistema" ;;
        "python"|"python3"|"perl"|"ruby") echo "Interpretador de linguagem" ;;
        "cp"|"mv"|"rm") echo "Utilitário de manipulação de arquivos" ;;
        "cat"|"less"|"more") echo "Visualizador de arquivos" ;;
        "vi"|"vim"|"nano") echo "Editor de texto" ;;
        "ssh"|"scp") echo "Cliente SSH" ;;
        "curl"|"wget") echo "Cliente de download" ;;
        "crontab") echo "Agendador de tarefas" ;;
        "systemctl") echo "Gerenciador de serviços systemd" ;;
        "service") echo "Gerenciador de serviços" ;;
        "tar"|"gzip"|"zip") echo "Utilitário de compactação" ;;
        "dd") echo "Utilitário de cópia e conversão de dados" ;;
        "ssh-agent") echo "Agente de autenticação SSH" ;;
        "pkexec") echo "Executar comandos como outro usuário (PolicyKit)" ;;
        "passwd") echo "Modificar senhas de usuário" ;;
        "newgrp") echo "Mudar para outro grupo" ;;
        "chsh") echo "Mudar shell de login" ;;
        "chfn") echo "Mudar informações do usuário" ;;
        *) 
            if [[ "$tipo" == "diretorio" ]]; then
                echo "Diretório do sistema"
            else
                echo "Binário/Arquivo do sistema"
            fi
            ;;
    esac
}

# Array para armazenar resultados
declare -a resultados

echo -e "${YELLOW}Procurando arquivos e diretórios perigosos...${NC}"

# 1. Procurar arquivos com SUID/SGID
echo -e "${BLUE}[1/6] Verificando arquivos SUID/SGID...${NC}"
while IFS= read -r -d '' arquivo; do
    if [[ -f "$arquivo" && ! -L "$arquivo" ]]; then
        permissao=$(stat -c "%a" "$arquivo" 2>/dev/null)
        if [[ $permissao =~ ^[0-9]{4}$ ]]; then
            risco=$(classificar_risco "$permissao" "$arquivo" "arquivo")
            descricao=$(descrever_binario "$arquivo" "arquivo")
            resultados+=("$risco|SUID/SGID|$arquivo|$permissao|$descricao")
        fi
    fi
done < <(find / -type f \( -perm -4000 -o -perm -2000 \) -not -path "/proc/*" -not -path "/sys/*" -not -path "/dev/*" -print0 2>/dev/null)

# 2. Procurar diretórios com permissão 777 ou writable para others
echo -e "${BLUE}[2/6] Verificando diretórios com permissões perigosas...${NC}"
while IFS= read -r -d '' diretorio; do
    if [[ -d "$diretorio" && ! -L "$diretorio" ]]; then
        permissao=$(stat -c "%a" "$diretorio" 2>/dev/null)
        # Verificar se tem write para others (perm 2 no último dígito)
        if [[ "$permissao" == "777" ]] || [[ $permissao =~ ^[0-9]{3}$ && $((permissao % 10 & 2)) -ne 0 ]]; then
            risco=$(classificar_risco "$permissao" "$diretorio" "diretorio")
            descricao=$(descrever_binario "$diretorio" "diretorio")
            resultados+=("$risco|DIRETÓRIO W|$diretorio|$permissao|$descricao - Write para outros usuários")
        fi
    fi
done < <(find / -type d -not -path "/proc/*" -not -path "/sys/*" -not -path "/dev/*" -print0 2>/dev/null)

# 3. Procurar arquivos com permissão 777 ou writable para others em locais sensíveis
echo -e "${BLUE}[3/6] Verificando arquivos com permissões perigosas...${NC}"
while IFS= read -r -d '' arquivo; do
    if [[ -f "$arquivo" && ! -L "$arquivo" ]]; then
        permissao=$(stat -c "%a" "$arquivo" 2>/dev/null)
        # Verificar se tem write para others OU permissão 777
        if [[ "$permissao" == "777" ]] || [[ $permissao =~ ^[0-9]{3}$ && $((permissao % 10 & 2)) -ne 0 ]]; then
            risco=$(classificar_risco "$permissao" "$arquivo" "arquivo")
            descricao=$(descrever_binario "$arquivo" "arquivo")
            resultados+=("$risco|ARQUIVO W|$arquivo|$permissao|$descricao - Write para outros usuários")
        fi
    fi
done < <(find /etc /var /usr /bin /sbin /opt /home /root -type f -not -path "/proc/*" -not -path "/sys/*" -not -path "/dev/*" -print0 2>/dev/null)

# 4. Procurar arquivos de configuração sensíveis com permissões perigosas
echo -e "${BLUE}[4/6] Verificando arquivos de configuração sensíveis...${NC}"
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
    "/root/.ssh/id_rsa.pub"
    "/etc/crontab"
    "/etc/cron.d/*"
    "/etc/cron.daily/*"
    "/etc/cron.hourly/*"
    "/etc/cron.monthly/*"
    "/etc/cron.weekly/*"
    "/etc/profile"
    "/etc/bash.bashrc"
)

for config in "${config_sensiveis[@]}"; do
    # Expandir wildcards
    for expanded_config in $config; do
        if [[ -e "$expanded_config" ]]; then
            permissao=$(stat -c "%a" "$expanded_config" 2>/dev/null)
            # Se permissão for muito aberta (writable por others ou 777)
            if [[ "$permissao" =~ ^[0-9]+$ ]] && [[ $((permissao % 10 & 2)) -ne 0 || $permissao -eq 777 ]]; then
                risco="CRÍTICO"
                descricao="Arquivo de configuração sensível"
                resultados+=("$risco|CONFIGURAÇÃO|$expanded_config|$permissao|$descricao com permissões perigosas")
            fi
        fi
    done
done

# 5. Procurar scripts e binários em diretórios temporários com permissões perigosas
echo -e "${BLUE}[5/6] Verificando diretórios temporários...${NC}"
diretorios_tmp=(
    "/tmp"
    "/var/tmp"
    "/dev/shm"
)

for tmp_dir in "${diretorios_tmp[@]}"; do
    if [[ -d "$tmp_dir" ]]; then
        # Verificar arquivos executáveis no tmp
        while IFS= read -r -d '' arquivo; do
            if [[ -f "$arquivo" && -x "$arquivo" ]]; then
                permissao=$(stat -c "%a" "$arquivo" 2>/dev/null)
                risco=$(classificar_risco "$permissao" "$arquivo" "arquivo")
                descricao="Script/binário em diretório temporário"
                resultados+=("$risco|TMP EXECUTÁVEL|$arquivo|$permissao|$descricao")
            fi
        done < <(find "$tmp_dir" -type f -executable -not -path "*/.*" -print0 2>/dev/null)
    fi
done

# 6. Procurar arquivos ocultos em diretórios home com permissões perigosas
echo -e "${BLUE}[6/6] Verificando arquivos ocultos em home directories...${NC}"
while IFS= read -r -d '' home_dir; do
    if [[ -d "$home_dir" && "$home_dir" != "/proc/*" && "$home_dir" != "/sys/*" ]]; then
        # Verificar arquivos ocultos executáveis ou writable
        while IFS= read -r -d '' hidden_file; do
            if [[ -f "$hidden_file" ]]; then
                permissao=$(stat -c "%a" "$hidden_file" 2>/dev/null)
                # Se for executável ou writable por others
                if [[ -x "$hidden_file" ]] || [[ $permissao =~ ^[0-9]{3}$ && $((permissao % 10 & 2)) -ne 0 ]]; then
                    risco=$(classificar_risco "$permissao" "$hidden_file" "arquivo")
                    descricao="Arquivo oculto com permissões perigosas"
                    resultados+=("$risco|ARQUIVO OCULTO|$hidden_file|$permissao|$descricao")
                fi
            fi
        done < <(find "$home_dir" -maxdepth 1 -name ".*" -type f -print0 2>/dev/null)
    fi
done < <(find /home /root -type d -maxdepth 0 -print0 2>/dev/null)

# Ordenar resultados por risco
echo -e "${YELLOW}Ordenando resultados por nível de risco...${NC}"

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

ordenar_resultados() {
    local i j
    for ((i=0; i<${#resultados[@]}; i++)); do
        for ((j=i+1; j<${#resultados[@]}; j++)); do
            risco_i=$(obter_peso_risco "${resultados[i]%%|*}")
            risco_j=$(obter_peso_risco "${resultados[j]%%|*}")
            if [[ $risco_i -gt $risco_j ]]; then
                local temp="${resultados[i]}"
                resultados[i]="${resultados[j]}"
                resultados[j]="$temp"
            fi
        done
    done
}

ordenar_resultados

# Gerar relatório
echo -e "${GREEN}Gerando relatório final...${NC}"
echo

# Cabeçalho do arquivo
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
    printf "%-12s | %-18s | %-45s | %-8s | %s\n" "RISCO" "TIPO" "CAMINHO" "PERM" "DESCRIÇÃO"
    echo "------------|--------------------|-----------------------------------------------|----------|----------------"
} > "$OUTPUT_FILE"

# Output para terminal e arquivo
for resultado in "${resultados[@]}"; do
    IFS='|' read -r risco tipo caminho permissao descricao <<< "$resultado"
    
    # Definir cor baseada no risco
    case "$risco" in
        "CRÍTICO") cor=$RED ;;
        "MUITO ALTO") cor=$RED ;;
        "ALTO") cor=$YELLOW ;;
        "MÉDIO") cor=$GREEN ;;
        *) cor=$CYAN ;;
    esac
    
    # Mostrar no terminal (apenas os mais críticos)
    if [[ "$risco" == "CRÍTICO" || "$risco" == "MUITO ALTO" || "$risco" == "ALTO" ]]; then
        echo -e "${cor}%-12s${NC} | %-18s | %-45s | %-8s | %s" "$risco" "$tipo" "$(echo "$caminho" | cut -c1-45)" "$permissao" "$descricao"
    fi
    
    # Escrever tudo no arquivo
    printf "%-12s | %-18s | %-45s | %-8s | %s\n" "$risco" "$tipo" "$caminho" "$permissao" "$descricao" >> "$OUTPUT_FILE"
done

# Rodapé e recomendações
{
    echo
    echo "===================================================================="
    echo "RECOMENDAÇÕES DE SEGURANÇA:"
    echo
    echo "1. ITENS CRÍTICOS:"
    echo "   - Remover permissão de escrita (write) para 'others' em arquivos/diretórios sensíveis"
    echo "   - Use: chmod o-w <arquivo>"
    echo
    echo "2. DIRETÓRIOS COM WRITE PARA OTHERS:"
    echo "   - Revise se é realmente necessário"
    echo "   - Considere usar sticky bit: chmod +t <diretório>"
    echo "   - Use: chmod o-w <diretório>"
    echo
    echo "3. ARQUIVOS SUID/SGID:"
    echo "   - Remova SUID/SGID se não for essencial: chmod u-s <arquivo>"
    echo "   - Mantenha apenas em binários do sistema que realmente precisam"
    echo
    echo "4. ARQUIVOS EM /tmp /var/tmp:"
    echo "   - Evite arquivos executáveis em diretórios temporários"
    echo "   - Configure no /etc/fstab: noexec,nosuid para partições temporárias"
    echo
    echo "5. CONFIGURAÇÕES SENSÍVEIS:"
    echo "   - Mantenha permissões restritas: chmod 600 para arquivos de configuração"
    echo "   - Use: chmod 600 /etc/shadow /etc/gshadow /root/.ssh/*"
    echo
    echo "COMANDOS ÚTEIS:"
    echo "   chmod o-w <arquivo>          # Remove escrita para outros"
    echo "   chmod 755 <diretório>        # Permissão segura para diretórios"
    echo "   chmod 644 <arquivo>          # Permissão segura para arquivos"
    echo "   chmod u-s <arquivo>          # Remove bit SUID"
    echo "   chmod g-s <arquivo>          # Remove bit SGID"
    echo "   chown root:root <arquivo>    # Define proprietário como root"
    echo
    echo "===================================================================="
    echo "LEGENDA:"
    echo "SUID - Set User ID (executa com permissões do proprietário)"
    echo "SGID - Set Group ID (executa com permissões do grupo)"
    echo "W    - Write (escrita) - Permissão perigosa se concedida a outros"
    echo "777  - Permissão total para todos (leitura, escrita, execução)"
    echo "===================================================================="
} >> "$OUTPUT_FILE"

echo
echo -e "${GREEN}====================================================================${NC}"
echo -e "${GREEN}AUDITORIA CONCLUÍDA!${NC}"
echo -e "${GREEN}Relatório salvo em: $OUTPUT_FILE${NC}"
echo -e "${GREEN}Total de itens identificados: ${#resultados[@]}${NC}"
echo -e "${GREEN}====================================================================${NC}"

# Estatísticas finais
criticos=0
muito_altos=0
altos=0
for resultado in "${resultados[@]}"; do
    risco="${resultado%%|*}"
    case "$risco" in
        "CRÍTICO") ((criticos++)) ;;
        "MUITO ALTO") ((muito_altos++)) ;;
        "ALTO") ((altos++)) ;;
    esac
done

echo
echo -e "${YELLOW}ESTATÍSTICAS:${NC}"
echo -e "  ${RED}● Críticos: $criticos${NC}"
echo -e "  ${RED}● Muito Alto: $muito_altos${NC}"
echo -e "  ${YELLOW}● Alto: $altos${NC}"
echo -e "  ${GREEN}● Total: ${#resultados[@]}${NC}"

echo
echo -e "${PURPLE}RECOMENDAÇÃO:${NC}"
echo -e "  ${CYAN}Revise os itens classificados como 'CRÍTICO' e 'MUITO ALTO' primeiro${NC}"
echo -e "  ${CYAN}Use os comandos sugeridos no relatório para corrigir as permissões${NC}"
