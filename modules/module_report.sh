# ======================
# SUMMARY REPORT MODULE
# ======================
module_report() {
    print_to_console "\n${GREEN}========================================================${NC}"
    print_to_console "\n${GREEN}>>> [ WEBTAZ - EXECUTION SUMMARY ]${NC}"
    
    echo "Date: $(date)"
    echo "Target: ${TARGET}"
    echo "IPs found: $(tr '\n' ' ' < "${LOG_DIR}/dig_ips.txt" 2>/dev/null)"
    print_to_console "${GREEN}OPEN PORTS:${NC}"
    grep -h "^[0-9]" "${LOG_DIR}"/nmap_quick_*.txt 2>/dev/null | sort -nu
    analyze_ssl_results
    print_to_console "\n${GREEN}Security Headers:${NC}"
    [ -f "${LOG_DIR}/shcheck.py.txt" ] && cat ${LOG_DIR}/shcheck.py.txt
    print_to_console "${GREEN}MISC:${NC}"
    [ -f "${LOG_DIR}/nuclei_recon.txt" ] && cat ${LOG_DIR}/nuclei_recon.txt
    print_to_console "\n${GREEN}VULNERABILITIES:${NC}"
    [ -f "${LOG_DIR}/nuclei_vuln.txt" ] && cat ${LOG_DIR}/nuclei_vuln.txt
    print_to_console "\n${GREEN}========================================================${NC}"
}

analyze_ssl_results() {
    print_to_console "\n${GREEN}[i] SSL Analisys:${NC}"
    
    local ssl_file="${LOG_DIR}/sslscan.txt"
    
    # Problems found
    local issues=0
    local warnings=0
    
    # Security checks
    if grep -q "SSLv2" "$ssl_file" | grep -v disabled || grep -q "SSLv3" "$ssl_file" | grep -v disables; then
        print_to_console "  ${RED}✗ SSLv2/SSLv3 enabled (CRITICAL)${NC}"
        ((issues++))
    fi
    
    if grep -q "TLSv1.0" "$ssl_file" | grep -v disabled; then
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