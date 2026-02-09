#!/usr/bin/env bash
#/usr/bin/bash
# webtaz.sh 2.0 Web Pentest Kickstarter Modular
# Fabio Almeida <mentesan@gmail.com>
# Improvements: Modular structure, better logging, safer parsing, hooks for expansion.

# ==================
# MAIN CONFIGURATION
# ==================
CONFIG_FILE="webtaz.conf"
if [ -f "$CONFIG_FILE" ]; then
    source "$CONFIG_FILE"
    echo "[*] Configuration loaded from $CONFIG_FILE"
else
    # Default values
    PROXY="127.0.0.1:8082"
    USE_PROXY="true"
    USER_AGENT="Mozilla/5.0 (webtaz)"
    LOG_DIR_PREFIX="/output/"
    # For future tools
    FFUF_WORDLIST="/usr/share/wordlists/dirb/common.txt"
    ENABLE_SUBDOMAIN_SCAN="false"
fi

# Tools paths (if not in PATH, specify full path here)
[ -z NUCLEI_BIN ] && NUCLEI_BIN="$(which nuclei 2>/dev/null)"
[ -z PPMAP ] && PPMAP="$(which ppmap 2>/dev/null)"  
[ -z WHATWEB ] && WHATWEB="$(which whatweb 2>/dev/null)"
[ -z WAFW00F ] && WAFW00F="$(which wafw00f 2>/dev/null)"
[ -z SHCHECK ] && SHCHECK="$(which shcheck.py 2>/dev/null)"
[ -z SPIDER ] && SPIDER="$(which spider 2>/dev/null)"
[ -z GAU ] && GAU="$(which gau 2>/dev/null)"
# Proxy configuration
[ $USE_PROXY == "true" ] && PROXY_CHAINS=$(which proxychains) || PROXY_CHAINS=""
[ ! -z $PROXY ] && CURL_PROXY="-x http://${PROXY}" || CURL_PROXY=""
echo "[*] Proxy configuration: ${USE_PROXY} | Proxy: ${PROXY} | proxychains: ${PROXY_CHAINS}\n"

# OS detection
detect_os() {
    case "$(uname -s)" in
        Linux*)     OS="linux" ;;
        Darwin*)    OS="macos" ;;
        CYGWIN*)    OS="windows" ;;
        MINGW*)     OS="windows" ;;
        *)          OS="unknown" ;;
    esac
    echo "[*] Detected OS: $OS" >&2
}

# Output funcitions
console_log() {
    local message="$1"
    local level="${2:-INFO}"
    
    # For macOs uses fd 3 if available, or stderr if not
    if [ "$OS" = "macos" ]; then
        if [ -e "/dev/fd/3" ]; then
            echo "[$(date +'%H:%M:%S')] [$level] $message" >&3
        else
            echo "[$(date +'%H:%M:%S')] [$level] $message" >&2
        fi
    else
        # Linux normal
        echo "[$(date +'%H:%M:%S')] [$level] $message" >&3
    fi
    
    # Always log to global log file
    echo "[$(date +'%H:%M:%S')] [$level] $message" >> "$GLOBAL_LOG"
}

# Prints to screen alternative for "tee /dev/fd/3"
print_to_console() {
    if [ "$OS" = "macos" ]; then
        # macOS: prints to stderr (still visible)
        echo -e "$@" >&2
    else
        # Linux: uses saved fd 3
        echo -e "$@" >&3
    fi
}

# =======================
# DEPENDENCY VERIFICATION
# =======================
check_dependencies() {
    print_to_console ""
    print_to_console "${YELLOW}[*] DEPENDENCCY VERIFICATION${NC}"
    print_to_console ""
    
    # Essential tools (must be installed for core functionality)
    ESSENTIAL_TOOLS=("curl" "dig" "nmap" "sslscan" "whatweb" "gau")
    
    # Optional tools (for extra features, but not critical)
    OPTIONAL_TOOLS=("sslyze" "wafw00f" "nuclei" "amass" "ffuf" "subfinder" "shcheck.py" "ppmap" "spider")
    
    # Tools that may require sudo permissions
    SUDO_TOOLS=("nmap" "hping3")
    
    local missing_essential=()
    local missing_optional=()
    local sudo_problems=()
    
    # Essential tools verification
    print_to_console "[i] Essential tools:"
    for tool in "${ESSENTIAL_TOOLS[@]}"; do
        if command -v "$tool" &>/dev/null || [ -f "$tool" ]; then
            print_to_console "  ${GREEN}✓${NC} $tool"
        else
            print_to_console "  ${RED}✗${NC} $tool ${RED}(MISSING)${NC}"
            missing_essential+=("$tool")
        fi
    done
    
    # Verify optionals
    print_to_console "[i] Optional tools (for extra modules):"
    for tool in "${OPTIONAL_TOOLS[@]}"; do
        if command -v "$tool" &>/dev/null || [ -f "$tool" ]; then
            print_to_console "  ${GREEN}✓${NC} $tool"
        else
            print_to_console "  ${YELLOW}⚠${NC} $tool (optional)"
            missing_optional+=("$tool")
        fi
    done
    
    # Verify sudo permissions
    print_to_console "[i] Some tools need sudo permissions:"
    #for tool in "${SUDO_TOOLS[@]}"; do
    #    if command -v "$tool" &>/dev/null; then
    #        if sudo -l -U "$(whoami)" 2>/dev/null | grep -q "$tool"; then
    #            print_to_console "  ${GREEN}✓${NC} $tool (sudo allowed)"
    #        else
    #            print_to_console "  ${YELLOW}⚠${NC} $tool (sudo may be necessary but not permitted)"
    #            sudo_problems+=("$tool")
    #        fi
    #    fi
    #done
    
    # Summary of results
    print_to_console "\n${YELLOW}[*] VERIFICATION SUMMARY${NC}"
    
    if [ ${#missing_essential[@]} -eq 0 ]; then
        print_to_console "${GREEN}[+] All essential tools are installed!${NC}"
    else
        print_to_console "${RED}[!] Some essential tools are missing (${#missing_essential[@]}):${NC}"
        print_to_console "  - %s\n" "${missing_essential[@]}"
    fi
    
    # Missing optionals warning
    if [ ${#missing_optional[@]} -gt 0 ]; then
        print_to_console "\n${YELLOW}[!] Optional tools missing (modules will be disabled):${NC}"
        print_to_console "${RED} ${missing_optional[@]}${NC}"
    else
        print_to_console "\n${GREEN}[+] All optional tools are installed!${NC}"
    fi
    
    # Pause for confirmation if essentials are missing
    if [ ${#missing_essential[@]} -gt 0 ]; then
        print_to_console "\n${RED}[!] SOME TESTS WILL NOT BE EXECUTED${NC}"
        print_to_console "${YELLOW}[?] Continue? (s/n)${NC}"
        read -r response
        if [[ ! "$response" =~ ^[Ss] ]]; then
            exit 1
        fi
    fi
    
    log "INFO" "Finished dependencies verification."
}

# =========================
# FUNÇÕES DE CORE & LOGGING
# =========================
LOG_DIR="${LOG_DIR_PREFIX}${TARGET_DOMAIN}"
GLOBAL_LOG="${LOG_DIR}/webtaz.log"

init_logging() {
    mkdir -p "${LOG_DIR}"
    exec 3>&1 4>&2  # Store original stdout/stderr
    exec 1> >(tee -a "${GLOBAL_LOG}") 2>&1
    print_to_console "[*] Logs will be saved in: ${LOG_DIR}"
    print_to_console "[+] Logs saved in: ${LOG_DIR}"
}

log() {
    local level="$1"
    local message="$2"
    print_to_console "[$(date +'%H:%M:%S')] [${level}] ${message}"
    if [ "${level}" = "ERROR" ]; then
        print_to_console "[!] ${message}" >&2
    fi
}

run_tool() {
    # Wrapper function to execute tools with logging and error handling
    local tool_name="$1"
    local command="$2"
    local output_file="${LOG_DIR}/${tool_name}.txt"
    
    log "INFO" "Initializing: ${tool_name}"
    print_to_console "\n=== [ ${tool_name} ] ==="
    
    if [ -s "${output_file}" ]; then
        log "INFO" "File exists. Skipping execution: ${output_file}"
        print_to_console "[*] (Previus results loaded from ${output_file})"
        return 0
    fi
    
    eval "${command}" >> "${output_file}" 2>&1
    local exit_code=$?
    
    if [ ${exit_code} -eq 0 ]; then
        log "SUCCESS" "${tool_name} finished successfully."
        # Show preview of results
        head -20 "${output_file}"
    else
        log "ERROR" "${tool_name} failed (code: ${exit_code})"
        print_to_console "[!] Execution failed. Check the log file for details." >&2
    fi
    return ${exit_code}
}

main() {
    # Apenas verificar dependências
    if [ "$1" = "--check-only" ] || [ "$1" = "--check" ]; then
        init_logging
        check_dependencies
        exit 0
    fi

    # Validação básica
    if [ $# -lt 1 ]; then
        echo "Uso: $0 <site or domain address> [--quick]" >&2
        echo "Ex:   $0 alvo.com.br" >&2
        echo "      $0 alvo.com.br --quick   (only reconnaissance)" >&2
        exit 1
    fi
    
    TARGET_DOMAIN="$1"
    MODE="full"
    [ "$2" = "--quick" ] && MODE="quick"
    
    # Initialize logging and check dependencies
    init_logging
    # Verify dependencies before doing anything else
    check_dependencies
    
    # Pause for user to see the dependency check
    sleep 2

    log "INFO" "Initializing webtaz for: ${TARGET_DOMAIN} (mode: ${MODE})"
    print_to_console "[ WEBTAZ v2 ] Target: ${TARGET_DOMAIN}\n"


    MODULE_ORDER=(
        "module_recon"
        "module_vulns"
        "module_ssl"
        "module_report"
    )

    load_and_execute_modules() {
        local modules_dir="./modules"
        
        for module_name in "${MODULE_ORDER[@]}"; do
            local module_file="$modules_dir/${module_name}.sh"
            
            if [ ! -f "$module_file" ]; then
                print_to_console "[!] Module file not found: $module_file"
                print_to_console "[*] Creating template module..."
                create_module_template "$module_name"
                continue
            fi
            
            # Load module
            print_to_console "[*] Loading: $module_name"
            if source "$module_file" 2>/dev/null; then
                print_to_console "    ✓ Loaded successfully"
            else
                print_to_console "    ✗ Failed to load"
                continue
            fi
            
            # Executes module function
            if type "$module_name" &>/dev/null; then
                print_to_console "    → Executing module..."
                print_to_console ""
                
                # Executa o módulo
                if "$module_name"; then
                    print_to_console "    ✓ Module executed successfully"
                else
                    print_to_console "    ⚠ Module returned error code: $?"
                fi
            else
                print_to_console "    ⚠ Function '$module_name' not found in module file"
            fi
            
            print_to_console ""
            sleep 1  # Short pause between modules
        done
    }

    if [ "${MODE}" = "full" ]; then
        # Array of URLs for testing
        TEST_URLS=("https://${TARGET_DOMAIN}" "http://${TARGET_DOMAIN}")
        
        load_and_execute_modules
    fi

    print_to_console "\n[+] Done! Logs: ${LOG_DIR}"
    log "SUCCESS" "Finished execution for ${TARGET_DOMAIN}"
}

# Entry point
main "$@"