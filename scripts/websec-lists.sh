#!/bin/bash
# WebSec Lists Manager - Gestionnaire de blacklist/whitelist
# Permet d'ajouter/supprimer des IPs et réseaux CIDR

set -e

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Config
LISTS_DIR="${WEBSEC_LISTS_DIR:-./lists}"
BLACKLIST="$LISTS_DIR/blacklist.txt"
WHITELIST="$LISTS_DIR/whitelist.txt"

# Create lists directory if needed
mkdir -p "$LISTS_DIR"
touch "$BLACKLIST" "$WHITELIST"

# Functions
show_usage() {
    cat <<EOF
${BLUE}WebSec Lists Manager${NC}

${YELLOW}Usage:${NC}
  $0 <command> [arguments]

${YELLOW}Commands:${NC}
  blacklist add <ip|cidr>      Ajouter IP/CIDR à la blacklist
  blacklist remove <ip|cidr>   Retirer IP/CIDR de la blacklist
  blacklist list               Afficher la blacklist
  blacklist clear              Vider la blacklist

  whitelist add <ip|cidr>      Ajouter IP/CIDR à la whitelist
  whitelist remove <ip|cidr>   Retirer IP/CIDR de la whitelist
  whitelist list               Afficher la whitelist
  whitelist clear              Vider la whitelist

  check <ip>                   Vérifier si IP est dans une liste
  stats                        Statistiques des listes
  export <json|csv>            Exporter les listes
  import <file>                Importer depuis fichier

${YELLOW}Examples:${NC}
  $0 blacklist add 192.168.1.100
  $0 blacklist add 10.0.0.0/8
  $0 whitelist add 203.0.113.50
  $0 check 192.168.1.100
  $0 export json > lists.json

${YELLOW}Environment:${NC}
  WEBSEC_LISTS_DIR    Directory for lists (default: ./lists)
EOF
}

validate_ip() {
    local ip=$1
    # Simple IP/CIDR validation
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(/[0-9]{1,2})?$ ]]; then
        return 0
    else
        return 1
    fi
}

add_to_list() {
    local list_file=$1
    local entry=$2

    if ! validate_ip "$entry"; then
        echo -e "${RED}❌ Invalid IP/CIDR format: $entry${NC}"
        exit 1
    fi

    if grep -Fxq "$entry" "$list_file" 2>/dev/null; then
        echo -e "${YELLOW}⚠️  Already in list: $entry${NC}"
        exit 0
    fi

    echo "$entry" >> "$list_file"
    echo -e "${GREEN}✅ Added: $entry${NC}"
}

remove_from_list() {
    local list_file=$1
    local entry=$2

    if grep -Fxq "$entry" "$list_file" 2>/dev/null; then
        # Create temp file without the entry
        grep -Fxv "$entry" "$list_file" > "${list_file}.tmp" || true
        mv "${list_file}.tmp" "$list_file"
        echo -e "${GREEN}✅ Removed: $entry${NC}"
    else
        echo -e "${YELLOW}⚠️  Not found in list: $entry${NC}"
        exit 1
    fi
}

list_entries() {
    local list_file=$1
    local list_name=$2

    if [ ! -s "$list_file" ]; then
        echo -e "${YELLOW}📋 $list_name is empty${NC}"
        return
    fi

    echo -e "${BLUE}📋 $list_name ($(wc -l < "$list_file") entries):${NC}"
    cat "$list_file" | while read -r line; do
        echo "  - $line"
    done
}

clear_list() {
    local list_file=$1
    local list_name=$2

    read -p "Are you sure you want to clear $list_name? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        > "$list_file"
        echo -e "${GREEN}✅ $list_name cleared${NC}"
    else
        echo -e "${YELLOW}Cancelled${NC}"
    fi
}

check_ip() {
    local ip=$1
    local in_blacklist=false
    local in_whitelist=false

    if grep -Fxq "$ip" "$BLACKLIST" 2>/dev/null; then
        in_blacklist=true
    fi

    if grep -Fxq "$ip" "$WHITELIST" 2>/dev/null; then
        in_whitelist=true
    fi

    echo -e "${BLUE}🔍 Check IP: $ip${NC}"

    if $in_blacklist; then
        echo -e "  Blacklist: ${RED}YES ❌${NC}"
    else
        echo -e "  Blacklist: ${GREEN}NO ✓${NC}"
    fi

    if $in_whitelist; then
        echo -e "  Whitelist: ${GREEN}YES ✓${NC}"
    else
        echo -e "  Whitelist: ${YELLOW}NO${NC}"
    fi

    if $in_whitelist && $in_blacklist; then
        echo -e "\n${YELLOW}⚠️  Warning: IP is in BOTH lists (whitelist takes precedence)${NC}"
    fi
}

show_stats() {
    local bl_count=$(wc -l < "$BLACKLIST" 2>/dev/null || echo 0)
    local wl_count=$(wc -l < "$WHITELIST" 2>/dev/null || echo 0)

    echo -e "${BLUE}📊 Lists Statistics${NC}"
    echo -e "  Blacklist entries: ${RED}$bl_count${NC}"
    echo -e "  Whitelist entries: ${GREEN}$wl_count${NC}"
    echo -e "  Total entries:     $(($bl_count + $wl_count))"
    echo -e "\n  Lists directory:   $LISTS_DIR"
}

export_lists() {
    local format=$1

    case "$format" in
        json)
            echo "{"
            echo "  \"blacklist\": ["
            if [ -s "$BLACKLIST" ]; then
                cat "$BLACKLIST" | sed 's/^/    "/' | sed 's/$/"/' | paste -sd ',' -
            fi
            echo "  ],"
            echo "  \"whitelist\": ["
            if [ -s "$WHITELIST" ]; then
                cat "$WHITELIST" | sed 's/^/    "/' | sed 's/$/"/' | paste -sd ',' -
            fi
            echo "  ]"
            echo "}"
            ;;
        csv)
            echo "type,ip"
            if [ -s "$BLACKLIST" ]; then
                cat "$BLACKLIST" | sed 's/^/blacklist,/'
            fi
            if [ -s "$WHITELIST" ]; then
                cat "$WHITELIST" | sed 's/^/whitelist,/'
            fi
            ;;
        *)
            echo -e "${RED}❌ Unknown format: $format (use json or csv)${NC}"
            exit 1
            ;;
    esac
}

import_lists() {
    local file=$1

    if [ ! -f "$file" ]; then
        echo -e "${RED}❌ File not found: $file${NC}"
        exit 1
    fi

    local imported=0

    # Try JSON format first
    if command -v jq &> /dev/null && jq empty "$file" 2>/dev/null; then
        echo -e "${BLUE}📥 Importing from JSON...${NC}"
        jq -r '.blacklist[]?' "$file" 2>/dev/null | while read -r ip; do
            if [ -n "$ip" ]; then
                add_to_list "$BLACKLIST" "$ip"
                ((imported++))
            fi
        done
        jq -r '.whitelist[]?' "$file" 2>/dev/null | while read -r ip; do
            if [ -n "$ip" ]; then
                add_to_list "$WHITELIST" "$ip"
                ((imported++))
            fi
        done
    # Try CSV format
    elif grep -q "^type,ip" "$file" 2>/dev/null; then
        echo -e "${BLUE}📥 Importing from CSV...${NC}"
        tail -n +2 "$file" | while IFS=, read -r type ip; do
            if [ "$type" = "blacklist" ]; then
                add_to_list "$BLACKLIST" "$ip"
                ((imported++))
            elif [ "$type" = "whitelist" ]; then
                add_to_list "$WHITELIST" "$ip"
                ((imported++))
            fi
        done
    else
        echo -e "${RED}❌ Unknown file format (expected JSON or CSV)${NC}"
        exit 1
    fi

    echo -e "${GREEN}✅ Import completed${NC}"
}

# Main
case "${1:-}" in
    blacklist)
        case "${2:-}" in
            add)
                [ -z "${3:-}" ] && { echo -e "${RED}❌ Missing IP/CIDR${NC}"; exit 1; }
                add_to_list "$BLACKLIST" "$3"
                ;;
            remove)
                [ -z "${3:-}" ] && { echo -e "${RED}❌ Missing IP/CIDR${NC}"; exit 1; }
                remove_from_list "$BLACKLIST" "$3"
                ;;
            list)
                list_entries "$BLACKLIST" "Blacklist"
                ;;
            clear)
                clear_list "$BLACKLIST" "blacklist"
                ;;
            *)
                show_usage
                exit 1
                ;;
        esac
        ;;
    whitelist)
        case "${2:-}" in
            add)
                [ -z "${3:-}" ] && { echo -e "${RED}❌ Missing IP/CIDR${NC}"; exit 1; }
                add_to_list "$WHITELIST" "$3"
                ;;
            remove)
                [ -z "${3:-}" ] && { echo -e "${RED}❌ Missing IP/CIDR${NC}"; exit 1; }
                remove_from_list "$WHITELIST" "$3"
                ;;
            list)
                list_entries "$WHITELIST" "Whitelist"
                ;;
            clear)
                clear_list "$WHITELIST" "whitelist"
                ;;
            *)
                show_usage
                exit 1
                ;;
        esac
        ;;
    check)
        [ -z "${2:-}" ] && { echo -e "${RED}❌ Missing IP${NC}"; exit 1; }
        check_ip "$2"
        ;;
    stats)
        show_stats
        ;;
    export)
        [ -z "${2:-}" ] && { echo -e "${RED}❌ Missing format (json|csv)${NC}"; exit 1; }
        export_lists "$2"
        ;;
    import)
        [ -z "${2:-}" ] && { echo -e "${RED}❌ Missing file${NC}"; exit 1; }
        import_lists "$2"
        ;;
    *)
        show_usage
        exit 1
        ;;
esac
