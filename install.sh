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

# Удаление точной спецификации правила из iptables -t nat -S PREROUTING
delete_dnat_by_spec() {
    local target_port="$1"
    local target_proto="$2"
    local target_dest="$3"
    local deleted_any=0

    local raw_lines=()
    while IFS= read -r line; do
        raw_lines+=("$line")
    done < <(iptables -t nat -S PREROUTING 2>/dev/null)

    for line in "${raw_lines[@]}"; do
        [[ "$line" != "-A PREROUTING"* ]] && continue
        [[ "$line" != *"DNAT"* ]] && continue

        local p_port p_proto p_dest
        p_port=$(echo "$line" | grep -oP '(?<=--dport )\d+')
        p_proto=$(echo "$line" | grep -oP '(?<=-p )\w+')
        p_dest=$(echo "$line" | grep -oP '(?<=--to-destination )[\d\.:]+')

        if [[ "$p_port" == "$target_port" && "$p_proto" == "$target_proto" && "$p_dest" == "$target_dest" ]]; then
            local rule_args="${line#-A PREROUTING }"
            if [ -n "$rule_args" ]; then
                eval "iptables -t nat -D PREROUTING $rule_args" 2>/dev/null && deleted_any=1
            fi
        fi
    done

    [ "$deleted_any" -eq 1 ]
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
    local pkgs_needed=()
    dpkg -s iptables-persistent >/dev/null 2>&1 || pkgs_needed+=("iptables-persistent" "netfilter-persistent")
    dpkg -s socat               >/dev/null 2>&1 || pkgs_needed+=("socat")
    if [ ${#pkgs_needed[@]} -gt 0 ]; then
        apt-get update -y > /dev/null
        apt-get install -y "${pkgs_needed[@]}" > /dev/null
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
    echo -e "${CYAN}IPv4→IPv6 relay (socat):${NC}"
    echo -e "Используйте пункт ${GREEN}5${NC} если конечный сервер доступен только по IPv6."
    echo -e "Трафик: Клиент (IPv4) → этот VPS → конечный сервер (IPv6)."
    echo -e "Relay работает как systemd-сервис и стартует автоматически при перезагрузке."
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
    if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then
        ufw allow "$IN_PORT"/"$PROTO" > /dev/null
        sed -i 's/DEFAULT_FORWARD_POLICY="DROP"/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw
        ufw reload > /dev/null
    fi

    netfilter-persistent save > /dev/null

    echo -e "${GREEN}[SUCCESS] $NAME настроен!${NC}"
    echo -e "$PROTO: Вход $IN_PORT -> Выход $TARGET_IP:$OUT_PORT"
    read -p "Нажмите Enter для возврата в меню..."
}

# --- СПИСОК ПРАВИЛ (iptables) ---
list_active_rules() {
    echo -e "\n${CYAN}--- Активные переадресации (iptables) ---${NC}"
    echo -e "${MAGENTA}ПОРТ (ВХОД)\tПРОТОКОЛ\tЦЕЛЬ (IP:ВЫХОД)${NC}"
    iptables -t nat -S PREROUTING 2>/dev/null | grep "DNAT" | while read -r line ; do
        l_port=$(echo "$line" | grep -oP '(?<=--dport )\d+')
        l_proto=$(echo "$line" | grep -oP '(?<=-p )\w+')
        l_dest=$(echo "$line" | grep -oP '(?<=--to-destination )[\d\.:]+')
        if [[ -n "$l_port" ]]; then echo -e "$l_port\t\t$l_proto\t\t$l_dest"; fi
    done
    echo ""
    read -p "Нажмите Enter..."
}

# --- УДАЛЕНИЕ ОДНОГО ПРАВИЛА (iptables) ---
delete_single_rule() {
    echo -e "\n${CYAN}--- Удаление правила ---${NC}"
    declare -a RULES_LIST
    local i=1
    while read -r line; do
        [[ "$line" != "-A PREROUTING"* ]] && continue
        [[ "$line" != *"DNAT"* ]] && continue

        l_port=$(echo "$line" | grep -oP '(?<=--dport )\d+')
        l_proto=$(echo "$line" | grep -oP '(?<=-p )\w+')
        l_dest=$(echo "$line" | grep -oP '(?<=--to-destination )[\d\.:]+')
        if [[ -n "$l_port" && -n "$l_proto" && -n "$l_dest" ]]; then
            RULES_LIST[$i]="$l_port|$l_proto|$l_dest"
            echo -e "${YELLOW}[$i]${NC} Вход: $l_port ($l_proto) -> Выход: $l_dest"
            ((i++))
        fi
    done < <(iptables -t nat -S PREROUTING 2>/dev/null)

    if [ ${#RULES_LIST[@]} -eq 0 ]; then
        echo -e "${RED}Нет активных правил.${NC}"
        read -p "Нажмите Enter..."
        return
    fi

    echo ""
    read -p "Номер правила для удаления (0 отмена): " rule_num
    if [[ "$rule_num" == "0" || -z "${RULES_LIST[$rule_num]}" ]]; then return; fi

    IFS='|' read -r d_port d_proto d_dest <<< "${RULES_LIST[$rule_num]}"
    local target_ip="${d_dest%:*}"
    local target_port="${d_dest##*:}"

    if ! delete_dnat_by_spec "$d_port" "$d_proto" "$d_dest"; then
        iptables -t nat -D PREROUTING -p "$d_proto" --dport "$d_port" -j DNAT --to-destination "$d_dest" 2>/dev/null
    fi

    local iface
    iface=$(ip route get 8.8.8.8 2>/dev/null | awk -- '{printf $5}')
    if [[ -n "$iface" ]]; then
        iptables -t nat -D PREROUTING -i "$iface" -p "$d_proto" -m "$d_proto" --dport "$d_port" -j DNAT --to-destination "$d_dest" 2>/dev/null
        iptables -t nat -D PREROUTING -i "$iface" -p "$d_proto" --dport "$d_port" -j DNAT --to-destination "$d_dest" 2>/dev/null
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

# ===========================================================================
# --- SOCAT IPv4 -> IPv6 RELAY ---
# ===========================================================================

# Имя systemd-сервиса по параметрам
_socat_svc_name() {
    local proto=$1 in_port=$2
    echo "kaskad-socat-${proto}-${in_port}"
}

# Создать и запустить systemd-сервис для socat relay
configure_socat_relay() {
    echo -e "\n${CYAN}--- 🌐 socat relay: IPv4 → IPv6 ---${NC}"
    echo -e "${WHITE}Клиент подключается по IPv4, трафик уходит на IPv6-адрес конечного сервера.${NC}\n"

    # Протокол
    local PROTO
    while true; do
        echo -e "Выберите протокол (${YELLOW}udp${NC} или ${YELLOW}tcp${NC}):"
        read -p "> " PROTO
        if [[ "$PROTO" == "udp" || "$PROTO" == "tcp" ]]; then break; fi
        echo -e "${RED}Ошибка: введите udp или tcp!${NC}"
    done

    # Входящий порт (IPv4)
    local IN_PORT
    while true; do
        echo -e "Введите ${YELLOW}ВХОДЯЩИЙ Порт${NC} (на этом сервере, IPv4):"
        read -p "> " IN_PORT
        if [[ "$IN_PORT" =~ ^[0-9]+$ ]] && [ "$IN_PORT" -le 65535 ]; then break; fi
        echo -e "${RED}Ошибка: порт должен быть числом (1-65535)!${NC}"
    done

    # IPv6-адрес назначения
    local TARGET_IPV6
    while true; do
        echo -e "Введите ${YELLOW}IPv6-адрес${NC} конечного сервера (без скобок, например: 2a01:dead:beef::1):"
        read -p "> " TARGET_IPV6
        if [[ -n "$TARGET_IPV6" ]]; then break; fi
        echo -e "${RED}Ошибка: адрес не может быть пустым!${NC}"
    done

    # Исходящий порт (IPv6)
    local OUT_PORT
    while true; do
        echo -e "Введите ${YELLOW}ИСХОДЯЩИЙ Порт${NC} на конечном сервере (IPv6):"
        read -p "> " OUT_PORT
        if [[ "$OUT_PORT" =~ ^[0-9]+$ ]] && [ "$OUT_PORT" -le 65535 ]; then break; fi
        echo -e "${RED}Ошибка: порт должен быть числом (1-65535)!${NC}"
    done

    local SVC_NAME
    SVC_NAME=$(_socat_svc_name "$PROTO" "$IN_PORT")
    local SVC_FILE="/etc/systemd/system/${SVC_NAME}.service"

    # Если сервис уже есть — остановить и пересоздать
    if systemctl is-active --quiet "$SVC_NAME" 2>/dev/null; then
        echo -e "${YELLOW}[*] Останавливаю существующий relay на порту $IN_PORT...${NC}"
        systemctl stop "$SVC_NAME"
        systemctl disable "$SVC_NAME" 2>/dev/null
    fi

    # Формируем socat-аргументы в зависимости от протокола
    local SOCAT_LISTEN SOCAT_TARGET
    if [[ "$PROTO" == "udp" ]]; then
        # fork — один процесс на каждый новый UDP-«поток» (по source addr:port)
        SOCAT_LISTEN="UDP4-LISTEN:${IN_PORT},reuseaddr,fork"
        SOCAT_TARGET="UDP6:[${TARGET_IPV6}]:${OUT_PORT}"
    else
        SOCAT_LISTEN="TCP4-LISTEN:${IN_PORT},reuseaddr,fork"
        SOCAT_TARGET="TCP6:[${TARGET_IPV6}]:${OUT_PORT}"
    fi

    # Создаём systemd unit
    cat > "$SVC_FILE" <<EOF
[Unit]
Description=Kaskad socat relay ${PROTO^^} IPv4:${IN_PORT} -> IPv6:[${TARGET_IPV6}]:${OUT_PORT}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/socat ${SOCAT_LISTEN} ${SOCAT_TARGET}
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    # Открываем порт в firewall
    if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then
        ufw allow "${IN_PORT}/${PROTO}" > /dev/null
        echo -e "${CYAN}[*] UFW: открыт порт ${IN_PORT}/${PROTO}${NC}"
    else
        # iptables: разрешить входящий трафик
        iptables -C INPUT -p "$PROTO" --dport "$IN_PORT" -j ACCEPT 2>/dev/null \
            || iptables -A INPUT -p "$PROTO" --dport "$IN_PORT" -j ACCEPT
        netfilter-persistent save > /dev/null
    fi

    # Запускаем
    systemctl daemon-reload
    systemctl enable "$SVC_NAME" > /dev/null 2>&1
    systemctl start "$SVC_NAME"

    sleep 1
    if systemctl is-active --quiet "$SVC_NAME"; then
        echo -e "${GREEN}[SUCCESS] socat relay запущен!${NC}"
        echo -e "  Протокол : ${CYAN}${PROTO^^}${NC}"
        echo -e "  Вход     : ${CYAN}0.0.0.0:${IN_PORT} (IPv4)${NC}"
        echo -e "  Выход    : ${CYAN}[${TARGET_IPV6}]:${OUT_PORT} (IPv6)${NC}"
        echo -e "  Сервис   : ${YELLOW}${SVC_NAME}${NC}"
        echo -e "  Статус   : $(systemctl is-active "$SVC_NAME")"
    else
        echo -e "${RED}[ERROR] Сервис не запустился. Лог:${NC}"
        journalctl -u "$SVC_NAME" -n 20 --no-pager
    fi

    read -p "Нажмите Enter для возврата в меню..."
}

# --- СПИСОК ACTIVE SOCAT RELAY'ОВ ---
list_socat_relays() {
    echo -e "\n${CYAN}--- Активные socat relay'ы ---${NC}"
    local found=0
    for svc_file in /etc/systemd/system/kaskad-socat-*.service; do
        [[ -f "$svc_file" ]] || continue
        local svc_name
        svc_name=$(basename "$svc_file" .service)
        local desc status
        desc=$(grep -oP '(?<=Description=).*' "$svc_file" | head -1)
        status=$(systemctl is-active "$svc_name" 2>/dev/null)
        local color="${GREEN}"
        [[ "$status" != "active" ]] && color="${RED}"
        echo -e "  ${color}●${NC} ${YELLOW}${svc_name}${NC}  [${color}${status}${NC}]"
        echo -e "    ${desc}"
        found=1
    done
    if [ "$found" -eq 0 ]; then
        echo -e "  ${YELLOW}Нет настроенных socat relay'ов.${NC}"
    fi
    echo ""
    read -p "Нажмите Enter..."
}

# --- УДАЛЕНИЕ SOCAT RELAY'А ---
delete_socat_relay() {
    echo -e "\n${CYAN}--- Удаление socat relay ---${NC}"

    local svcs=()
    for svc_file in /etc/systemd/system/kaskad-socat-*.service; do
        [[ -f "$svc_file" ]] || continue
        svcs+=("$(basename "$svc_file" .service)")
    done

    if [ ${#svcs[@]} -eq 0 ]; then
        echo -e "${RED}Нет настроенных socat relay'ов.${NC}"
        read -p "Нажмите Enter..."
        return
    fi

    local i=1
    for svc in "${svcs[@]}"; do
        local desc status
        desc=$(grep -oP '(?<=Description=).*' "/etc/systemd/system/${svc}.service" | head -1)
        status=$(systemctl is-active "$svc" 2>/dev/null)
        echo -e "${YELLOW}[$i]${NC} ${svc}  [${status}]  ${desc}"
        ((i++))
    done
    echo ""
    read -p "Номер для удаления (0 — отмена): " choice
    if [[ "$choice" == "0" || -z "${svcs[$((choice-1))]}" ]]; then return; fi

    local target_svc="${svcs[$((choice-1))]}"

    # Извлекаем порт и протокол из имени сервиса: kaskad-socat-<proto>-<port>
    local proto in_port
    proto=$(echo "$target_svc" | grep -oP '(?<=kaskad-socat-)\w+(?=-\d+$)')
    in_port=$(echo "$target_svc" | grep -oP '\d+$')

    systemctl stop "$target_svc" 2>/dev/null
    systemctl disable "$target_svc" 2>/dev/null
    rm -f "/etc/systemd/system/${target_svc}.service"
    systemctl daemon-reload

    # Убрать iptables-правило для входящего порта (если добавляли)
    if [[ -n "$proto" && -n "$in_port" ]]; then
        while iptables -D INPUT -p "$proto" --dport "$in_port" -j ACCEPT 2>/dev/null; do :; done
        netfilter-persistent save > /dev/null 2>&1
    fi

    echo -e "${GREEN}[OK] Relay ${target_svc} удалён.${NC}"
    read -p "Нажмите Enter..."
}

# ===========================================================================
# --- МЕНЮ ---
# ===========================================================================
show_menu() {
    while true; do
        clear
        echo -e "${MAGENTA}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${MAGENTA}║              Kaskad — NAT переадресация (каскад)              ║${NC}"
        echo -e "${MAGENTA}╚══════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "${CYAN}── iptables (IPv4→IPv4) ──────────────────────────────────────${NC}"
        echo -e "1) Настроить ${CYAN}AmneziaWG / WireGuard${NC} (UDP)"
        echo -e "2) Настроить ${CYAN}VLESS / XRay${NC} (TCP)"
        echo -e "3) Настроить ${CYAN}TProxy / MTProto${NC} (TCP)"
        echo -e "4) 🛠 Создать ${YELLOW}Кастомное правило${NC} (Разные порты, SSH, RDP...)"
        echo -e "5) Посмотреть активные правила (iptables)"
        echo -e "6) ${RED}Удалить одно правило (iptables)${NC}"
        echo -e "7) ${RED}Сбросить ВСЕ правила iptables${NC}"
        echo ""
        echo -e "${CYAN}── socat relay (IPv4→IPv6) ───────────────────────────────────${NC}"
        echo -e "8) 🌐 Добавить ${GREEN}socat relay${NC} (IPv4 вход → IPv6 выход)"
        echo -e "9) Список активных ${GREEN}socat relay${NC}'ов"
        echo -e "10) ${RED}Удалить socat relay${NC}"
        echo ""
        echo -e "11) ${MAGENTA}📚 ИНСТРУКЦИЯ${NC}"
        echo -e "0)  Выход"
        echo -e "──────────────────────────────────────────────────────────────"
        read -p "Ваш выбор: " choice

        case $choice in
            1)  configure_rule "udp" "AmneziaWG" ;;
            2)  configure_rule "tcp" "VLESS" ;;
            3)  configure_rule "tcp" "MTProto/TProxy" ;;
            4)  configure_custom_rule ;;
            5)  list_active_rules ;;
            6)  delete_single_rule ;;
            7)  flush_rules ;;
            8)  configure_socat_relay ;;
            9)  list_socat_relays ;;
            10) delete_socat_relay ;;
            11) show_instructions ;;
            0)  exit 0 ;;
            *)  ;;
        esac
    done
}

# --- ЗАПУСК ---
check_root
prepare_system
show_menu
