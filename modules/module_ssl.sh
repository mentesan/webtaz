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

analyze_ssl_results() {
    print_to_console "\n[i] SSL Analisys:"
    
    local ssl_file="${LOG_DIR}/sslscan.txt"
    
    # Problems found
    local issues=0
    local warnings=0
    
    # Security checks
    if grep -q "SSLv2" "$ssl_file" || grep -q "SSLv3" "$ssl_file"; then
        print_to_console "  ${RED}✗ SSLv2/SSLv3 enabled (CRITICAL)${NC}"
        ((issues++))
    fi
    
    if grep -q "TLSv1.0" "$ssl_file"; then
        print_to_console "  ${YELLOW}⚠ TLS 1.0 enabled (should be disabled)${NC}"
        ((warnings++))
        print_to_console "  ${YELLOW}⚠ TLS 1.0 enabled (should be disabled)${NC}"
        ((warnings++))
    fi
    
    # Wadk Ciphers
    if grep -q "Weak" "$ssl_file"; then
        print_to_console "  ${YELLOW}⚠ Weak Ciphers found${NC}"
        ((warnings++))
    fi
    
    # Summary
    if [ $issues -eq 0 ] && [ $warnings -eq 0 ]; then
        print_to_console "  ${GREEN}✓ Configuração SSL parece segura${NC}"
    else
        print_to_console "  ${YELLOW}[!] Found: $issues critical, $warnings warnings${NC}"
    fi
}