# ======================
# SUMMARY REPORT MODULE
# ======================
module_report() {
    local report_file="${LOG_DIR}/report_summary.txt"
    print_to_console "\n>>> [ GENERATING SUMMARY ]"
    
    {
        echo "=== WEBTAZ - EXECUTION SUMMARY ==="
        echo "Date: $(date)"
        echo "Target: ${TARGET}"
        echo "IPs found: $(tr '\n' ' ' < "${LOG_DIR}/dig_ips.txt" 2>/dev/null)"
        echo ""
        echo "OPEN PORTS:"
        grep -h "^[0-9]" "${LOG_DIR}"/nmap_quick_*.txt 2>/dev/null | sort -nu
        echo ""
        echo "VULNERABILITIES:"
        [ -f "${LOG_DIR}/vuln_crlf.txt" ] && echo "CRLF: $(grep -c '\[!\]' "${LOG_DIR}/vuln_crlf.txt") found"
        [ -f "${LOG_DIR}/nuclei_quick.txt" ] && echo "Nuclei: $(wc -l < "${LOG_DIR}/nuclei_quick.txt") found"
    } > "${report_file}"
    
    log "SUCCESS" "Summary generated: ${report_file}"
    cat "${report_file}" | tee /dev/fd/2
}