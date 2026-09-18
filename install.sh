#!/bin/bash

# --- ЦВЕТА ---
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
NC='\033[0m'

# --- ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ---

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}[ERROR] Запустите скрипт с правами root!${NC}"
        exit 1
    fi
}

# Парсинг полей DNAT из строки iptables -L / -S
_parse_dnat_fields_from_line() {
    local line="$1"
    _dnat_port=$(echo "$line" | grep -oE '(dpt:|--dport )[0-9]+' | grep -oE '[0-9]+$' | head -1)
    _dnat_dest=$(echo "$line" | grep -oE '(to:|--to-destination )[0-9.]+:[0-9]+' | grep -oE '[0-9.]+:[0-9]+$' | head -1)
    _dnat_proto=$(echo "$line" | grep -oE -- '-p (tcp|udp)' | awk '{print $2}')
    if [[ -z "$_dnat_proto" ]]; then
        _dnat_proto=$(echo "$line" | awk '{print $3}')
        if [[ "$_dnat_proto" == "DNAT" ]]; then
            _dnat_proto=$(echo "$line" | awk '{print $4}')
        fi
    fi
    [[ -n "$_dnat_port" && -n "$_dnat_dest" && -n "$_dnat_proto" ]]
}

# Заполняет DNAT_MENU_NUM[i], DNAT_MENU_RECORD[i] (port|proto|dest) начиная с 1
load_dnat_prerouting_menu() {
    DNAT_MENU_NUM=()
    DNAT_MENU_RECORD=()
    local i=0 line num port proto dest

    while IFS= read -r line; do
        [[ "$line" =~ ^[0-9] ]] || continue
        [[ "$line" != *DNAT* ]] && continue
        num="${line%% *}"
        if ! _parse_dnat_fields_from_line "$line"; then
            continue
        fi
        port="$_dnat_port"
        proto="$_dnat_proto"
        dest="$_dnat_dest"
        ((i++))
        DNAT_MENU_NUM[$i]="$num"
        DNAT_MENU_RECORD[$i]="$port|$proto|$dest"
    done < <(iptables -t nat -L PREROUTING --line-numbers -n 2>/dev/null)

    if [[ "$i" -eq 0 ]]; then
        local idx=0
        while IFS= read -r line; do
            [[ "$line" != "-A PREROUTING"* ]] && continue
            ((idx++))
            [[ "$line" != *DNAT* ]] && continue
            if ! _parse_dnat_fields_from_line "$line"; then
                continue
            fi
            port="$_dnat_port"
            proto="$_dnat_proto"
            dest="$_dnat_dest"
            ((i++))
            DNAT_MENU_NUM[$i]="$idx"
            DNAT_MENU_RECORD[$i]="$port|$proto|$dest"
        done < <(iptables -t nat -S PREROUTING 2>/dev/null)
    fi
}

dnat_prerouting_exists() {
    local want_port=$1 want_proto=$2 want_dest=$3
    load_dnat_prerouting_menu
    local n record port proto dest
    for n in "${!DNAT_MENU_RECORD[@]}"; do
        record="${DNAT_MENU_RECORD[$n]}"
        IFS='|' read -r port proto dest <<< "$record"
        if [[ "$port" == "$want_port" && "$proto" == "$want_proto" && "$dest" == "$want_dest" ]]; then
            return 0
        fi
    done
    return 1
}

remove_filter_rules_for_dnat() {
    local d_proto=$1 d_port=$2 target_ip=$3 target_port=$4
    while iptables -D INPUT -p "$d_proto" --dport "$d_port" -j ACCEPT 2>/dev/null; do :; done
    while iptables -D FORWARD -p "$d_proto" -d "$target_ip" --dport "$target_port" -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT 2>/dev/null; do :; done
    while iptables -D FORWARD -p "$d_proto" -s "$target_ip" --sport "$target_port" -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null; do :; done
}

# --- ПОДГОТОВКА СИСТЕМЫ ---
prepare_system() {
    # Автоматическое создание глобальной команды kaskad
    if [ -x "/usr/local/bin/gokaskad" ]; then
        rm -f "/usr/local/bin/gokaskad"
        echo -e "${CYAN}[*] Удалена устаревшая команда gokaskad (используйте kaskad).${NC}" >&2
    fi
    if [ "$0" != "/usr/local/bin/kaskad" ]; then
        cp -f "$0" "/usr/local/bin/kaskad"
        chmod +x "/usr/local/bin/kaskad"
    fi

    # Включение IP Forwarding
    if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf; then
        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    else
        sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf
    fi

    # Активация Google BBR
    if ! grep -q "net.core.default_qdisc=fq" /etc/sysctl.conf; then
        echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
    fi
    if ! grep -q "net.ipv4.tcp_congestion_control=bbr" /etc/sysctl.conf; then
        echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
    fi
    sysctl -p > /dev/null

    # Установка зависимостей
    export DEBIAN_FRONTEND=noninteractive
    if ! dpkg -s iptables-persistent >/dev/null 2>&1; then
        apt-get update -y > /dev/null
        apt-get install -y iptables-persistent netfilter-persistent > /dev/null
    fi
}

# --- ИНСТРУКЦИЯ (ТЕКСТ ВНУТРИ КОДА) ---
show_instructions() {
    clear
    echo -e "${MAGENTA}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${MAGENTA}║             📚 ИНСТРУКЦИЯ: КАК НАСТРОИТЬ КАСКАД              ║${NC}"
    echo -e "${MAGENTA}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}ШАГ 1: Подготовка${NC}"
    echo -e "У вас должны быть данные от зарубежного сервера (VPN/Прокси и т.д.):"
    echo -e " - ${YELLOW}IP адрес${NC} (зарубежный)"
    echo -e " - ${YELLOW}Порт${NC} (на котором работает целевой сервис)"
    echo ""
    echo -e "${CYAN}ШАГ 2: Настройка этого сервера${NC}"
    echo -e "1. Выберите нужный пункт (${GREEN}1-3${NC} для стандартных или ${GREEN}4${NC} для кастомных)."
    echo -e "2. Введите ${YELLOW}IP${NC} и ${YELLOW}Порты${NC} (входящий и исходящий)."
    echo -e "3. Скрипт создаст 'мост' через этот VPS."
    echo ""
    echo -e "${CYAN}ШАГ 3: Настройка Клиента (Важно!)${NC}"
    echo -e "1. Откройте приложение клиента."
    echo -e "2. В настройках соединения найдите поле ${YELLOW}Endpoint / Адрес сервера${NC}."
    echo -e "3. Замените зарубежный IP на ${GREEN}IP ЭТОГО СЕРВЕРА${NC}."
    echo -e "4. Если вы использовали разные порты в правиле №4, укажите Входящий порт."
    echo ""
    echo -e "${GREEN}Готово! Теперь трафик идет: Клиент -> Этот Сервер -> Зарубеж.${NC}"
    echo ""
    read -p "Нажмите Enter, чтобы вернуться в меню..."
}

# --- СТАНДАРТНАЯ НАСТРОЙКА (ПОРТ ВХОДА = ПОРТ ВЫХОДА) ---
configure_rule() {
    local PROTO=$1
    local NAME=$2

    echo -e "\n${CYAN}--- Настройка $NAME ($PROTO) ---${NC}"

    while true; do
        echo -e "Введите IP адрес назначения:"
        read -p "> " TARGET_IP
        if [[ -n "$TARGET_IP" ]]; then break; fi
    done

    while true; do
        echo -e "Введите Порт (одинаковый для входа и выхода):"
        read -p "> " PORT
        if [[ "$PORT" =~ ^[0-9]+$ ]] && [ "$PORT" -le 65535 ]; then break; fi
        echo -e "${RED}Ошибка: порт должен быть числом!${NC}"
    done

    apply_iptables_rules "$PROTO" "$PORT" "$PORT" "$TARGET_IP" "$NAME"
}

# --- КАСТОМНАЯ НАСТРОЙКА (РАЗНЫЕ ПОРТЫ) ---
configure_custom_rule() {
    echo -e "\n${CYAN}--- 🛠 Универсальное кастомное правило ---${NC}"
    echo -e "${WHITE}Подходит для перенаправления ЛЮБЫХ протоколов (SSH, RDP, нестандартные порты)."
    echo -e "Позволяет сделать так, чтобы клиент подключался к одному порту,"
    echo -e "а трафик уходил на другой порт зарубежного сервера.${NC}\n"

    while true; do
        echo -e "Выберите протокол (${YELLOW}tcp${NC} или ${YELLOW}udp${NC}):"
        read -p "> " PROTO
        if [[ "$PROTO" == "tcp" || "$PROTO" == "udp" ]]; then break; fi
        echo -e "${RED}Ошибка: введите tcp или udp!${NC}"
    done

    while true; do
        echo -e "Введите IP адрес назначения (куда отправляем трафик):"
        read -p "> " TARGET_IP
        if [[ -n "$TARGET_IP" ]]; then break; fi
    done

    while true; do
        echo -e "Введите ${YELLOW}ВХОДЯЩИЙ Порт${NC} (на этом сервере):"
        read -p "> " IN_PORT
        if [[ "$IN_PORT" =~ ^[0-9]+$ ]] && [ "$IN_PORT" -le 65535 ]; then break; fi
        echo -e "${RED}Ошибка: порт должен быть числом!${NC}"
    done

    while true; do
        echo -e "Введите ${YELLOW}ИСХОДЯЩИЙ Порт${NC} (на конечном сервере):"
        read -p "> " OUT_PORT
        if [[ "$OUT_PORT" =~ ^[0-9]+$ ]] && [ "$OUT_PORT" -le 65535 ]; then break; fi
        echo -e "${RED}Ошибка: порт должен быть числом!${NC}"
    done

    apply_iptables_rules "$PROTO" "$IN_PORT" "$OUT_PORT" "$TARGET_IP" "Custom Rule"
}

# --- ПРИМЕНЕНИЕ ПРАВИЛ IPTABLES ---
apply_iptables_rules() {
    local PROTO=$1
    local IN_PORT=$2
    local OUT_PORT=$3
    local TARGET_IP=$4
    local NAME=$5

    IFACE=$(ip route get 8.8.8.8 | awk -- '{printf $5}')
    if [[ -z "$IFACE" ]]; then
        echo -e "${RED}[ERROR] Не удалось определить интерфейс!${NC}"
        exit 1
    fi

    echo -e "${YELLOW}[*] Применение правил...${NC}"

    # Удаление старых правил (по входящему порту)
    iptables -t nat -D PREROUTING -p "$PROTO" --dport "$IN_PORT" -j DNAT --to-destination "$TARGET_IP:$OUT_PORT" 2>/dev/null
    iptables -D INPUT -p "$PROTO" --dport "$IN_PORT" -j ACCEPT 2>/dev/null
    iptables -D FORWARD -p "$PROTO" -d "$TARGET_IP" --dport "$OUT_PORT" -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT 2>/dev/null
    iptables -D FORWARD -p "$PROTO" -s "$TARGET_IP" --sport "$OUT_PORT" -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null

    # Новые правила
    iptables -A INPUT -p "$PROTO" --dport "$IN_PORT" -j ACCEPT
    iptables -t nat -A PREROUTING -p "$PROTO" --dport "$IN_PORT" -j DNAT --to-destination "$TARGET_IP:$OUT_PORT"
    
    if ! iptables -t nat -C POSTROUTING -o "$IFACE" -j MASQUERADE 2>/dev/null; then
        iptables -t nat -A POSTROUTING -o "$IFACE" -j MASQUERADE
    fi

    iptables -A FORWARD -p "$PROTO" -d "$TARGET_IP" --dport "$OUT_PORT" -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
    iptables -A FORWARD -p "$PROTO" -s "$TARGET_IP" --sport "$OUT_PORT" -m state --state ESTABLISHED,RELATED -j ACCEPT

    # Настройка UFW если активен
    if command -v ufw &> /dev/null && ufw status | grep -q "Status: active"; then
        ufw allow "$IN_PORT"/"$PROTO" >/dev/null
        sed -i 's/DEFAULT_FORWARD_POLICY="DROP"/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw
        ufw reload >/dev/null
    fi

    netfilter-persistent save > /dev/null
    
    echo -e "${GREEN}[SUCCESS] $NAME настроен!${NC}"
    echo -e "$PROTO: Вход $IN_PORT -> Выход $TARGET_IP:$OUT_PORT"
    read -p "Нажмите Enter для возврата в меню..."
}

# --- СПИСОК ПРАВИЛ ---
list_active_rules() {
    echo -e "\n${CYAN}--- Активные переадресации ---${NC}"
    echo -e "${MAGENTA}ПОРТ (ВХОД)\tПРОТОКОЛ\tЦЕЛЬ (IP:ВЫХОД)${NC}"
    load_dnat_prerouting_menu
    local n record port proto dest
    for n in $(printf '%s\n' "${!DNAT_MENU_RECORD[@]}" | sort -n); do
        record="${DNAT_MENU_RECORD[$n]}"
        IFS='|' read -r port proto dest <<< "$record"
        echo -e "$port\t\t$proto\t\t$dest"
    done
    echo ""

    read -p "Нажмите Enter..."
}

# --- УДАЛЕНИЕ ОДНОГО ПРАВИЛА ---
delete_single_rule() {
    echo -e "\n${CYAN}--- Удаление правила ---${NC}"
    load_dnat_prerouting_menu

    if [[ ${#DNAT_MENU_RECORD[@]} -eq 0 ]]; then
        echo -e "${RED}Нет активных правил.${NC}"
        read -p "Нажмите Enter..."
        return
    fi

    local n record port proto dest
    for n in $(printf '%s\n' "${!DNAT_MENU_RECORD[@]}" | sort -n); do
        record="${DNAT_MENU_RECORD[$n]}"
        IFS='|' read -r port proto dest <<< "$record"
        echo -e "${YELLOW}[$n]${NC} Вход: $port ($proto) -> Выход: $dest"
    done

    echo ""
    read -p "Номер правила для удаления (0 отмена): " rule_num
    if [[ "$rule_num" == "0" || -z "${DNAT_MENU_RECORD[$rule_num]}" ]]; then return; fi

    IFS='|' read -r d_port d_proto d_dest <<< "${DNAT_MENU_RECORD[$rule_num]}"
    local chain_num="${DNAT_MENU_NUM[$rule_num]}"
    local target_ip="${d_dest%:*}"
    local target_port="${d_dest##*:}"

    if ! iptables -t nat -D PREROUTING "$chain_num" 2>/dev/null; then
        echo -e "${RED}[ERROR] Не удалось снять DNAT (номер в цепочке: $chain_num).${NC}"
        echo -e "${YELLOW}Проверка: iptables -t nat -L PREROUTING --line-numbers -n${NC}"
        read -p "Нажмите Enter..."
        return
    fi

    if dnat_prerouting_exists "$d_port" "$d_proto" "$d_dest"; then
        echo -e "${YELLOW}[!] В PREROUTING осталось ещё одно такое же правило — удаляю...${NC}"
        while dnat_prerouting_exists "$d_port" "$d_proto" "$d_dest"; do
            load_dnat_prerouting_menu
            local dup_num dup_chain
            for dup_num in "${!DNAT_MENU_RECORD[@]}"; do
                record="${DNAT_MENU_RECORD[$dup_num]}"
                IFS='|' read -r port proto dest <<< "$record"
                if [[ "$port" == "$d_port" && "$proto" == "$d_proto" && "$dest" == "$d_dest" ]]; then
                    dup_chain="${DNAT_MENU_NUM[$dup_num]}"
                    iptables -t nat -D PREROUTING "$dup_chain" 2>/dev/null || break
                    break
                fi
            done
        done
    fi

    if dnat_prerouting_exists "$d_port" "$d_proto" "$d_dest"; then
        echo -e "${RED}[ERROR] Правило DNAT всё ещё в ядре. Удалите вручную по номеру из -L.${NC}"
        read -p "Нажмите Enter..."
        return
    fi

    remove_filter_rules_for_dnat "$d_proto" "$d_port" "$target_ip" "$target_port"

    netfilter-persistent save > /dev/null
    echo -e "${GREEN}[OK] Правило удалено.${NC}"
    read -p "Нажмите Enter..."
}

# --- ПОЛНАЯ ОЧИСТКА ---
flush_rules() {
    echo -e "\n${RED}!!! ВНИМАНИЕ !!!${NC}"
    echo "Сброс ВСЕХ настроек iptables."
    read -p "Вы уверены? (y/n): " confirm
    if [[ "$confirm" == "y" ]]; then
        iptables -P INPUT ACCEPT
        iptables -P FORWARD ACCEPT
        iptables -P OUTPUT ACCEPT
        iptables -t nat -F
        iptables -t mangle -F
        iptables -F
        iptables -X
        netfilter-persistent save > /dev/null
        echo -e "${GREEN}[OK] Очищено.${NC}"
    fi
    read -p "Нажмите Enter..."
}

# --- МЕНЮ ---
show_menu() {
    while true; do
        clear
        echo -e "${MAGENTA}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${MAGENTA}║              Kaskad — NAT переадресация (каскад)              ║${NC}"
        echo -e "${MAGENTA}╚══════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        
        echo -e "1) Настроить ${CYAN}AmneziaWG / WireGuard${NC} (UDP)"
        echo -e "2) Настроить ${CYAN}VLESS / XRay${NC} (TCP)"
        echo -e "3) Настроить ${CYAN}TProxy / MTProto${NC} (TCP)"
        echo -e "4) 🛠 Создать ${YELLOW}Кастомное правило${NC} (Разные порты, SSH, RDP...)"
        echo -e "5) Посмотреть активные правила"
        echo -e "6) ${RED}Удалить одно правило${NC}"
        echo -e "7) ${RED}Сбросить ВСЕ настройки${NC}"
        echo -e "8) ${MAGENTA}📚 ИНСТРУКЦИЯ (Как настроить)${NC}"
        echo -e "0) Выход"
        echo -e "------------------------------------------------------"
        read -p "Ваш выбор: " choice

        case $choice in
            1) configure_rule "udp" "AmneziaWG" ;;
            2) configure_rule "tcp" "VLESS" ;;
            3) configure_rule "tcp" "MTProto/TProxy" ;;
            4) configure_custom_rule ;;
            5) list_active_rules ;;
            6) delete_single_rule ;;
            7) flush_rules ;;
            8) show_instructions ;;
            0) exit 0 ;;
            *) ;;
        esac
    done
}

# --- ЗАПУСК ---
check_root
prepare_system
show_menu