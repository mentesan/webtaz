# ==========
# SSL MODULE
# ==========

module_ssl() {
    print_to_console "\n>>> [ SSL MODULE ]"
    
    # DO NOT USE PROXY_CHAINS FOR SSL TOOLS 
    # SSL tools often fail with proxychains due to handshake issues, so we run them directly.
    # Also we do not want to analyze SSL of the proxy, but of the target.
    
    # Verify sslyze presence
    if command -v sslyze &>/dev/null; then
        run_tool "sslyze" "sslyze $TARGET | sed '/^$/d'"
    else
        print_to_console "${YELLOW}[!] sslyze not found. Using sslscan instead.${NC}"
        log "WARN" "sslyze not installed, falling back to sslscan"
    fi
    
    # sslscan
    if command -v sslscan &>/dev/null; then
        run_tool "sslscan" "sslscan --no-colour $TARGET"
        
        # Automatic analysis of sslscan results
        if [ -f "${LOG_DIR}/sslscan.txt" ]; then
            analyze_ssl_results
        fi
    else
        echo -e "${RED}[!] sslscan not available${NC}" | tee /dev/fd/3
        print_to_console "[*] Alternative: curl -k --ssl :"
        run_tool "curl_ssl" "curl -k -v --max-time 10 'https://$TARGET' 2>&1 | grep -i ssl"
    fi
}