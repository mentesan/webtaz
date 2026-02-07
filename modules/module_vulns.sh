# ======================
# VULNERABILITIES MODULE
# ======================
module_vulns() {
    module_security_headers
    module_vuln_scan
    module_wapiti
}

module_security_headers() {
    print_to_console "\n>>> [ SECURITY HEADERS MODULE ]"
    
    local headers=("Content-Security-Policy" "X-Frame-Options" "X-Content-Type-Options" 
                   "Strict-Transport-Security" "Referrer-Policy" "Permissions-Policy")
    
    print_to_console "Analyzing security headers..."
    
    # Download headers
    $PROXY_CHAINS curl -k -I "https://${TARGET_DOMAIN}" 2>/dev/null > "${LOG_DIR}/security_headers_raw.txt"
    run_tool "shcheck.py" "$PROXY_CHAINS -q $SHCHECK https://$TARGET_DOMAIN"

    # Create formatted report
    {
        echo "HEADER;STATUS;RECOMENDAÇÃO"
        for header in "${headers[@]}"; do
            if grep -qi "^${header}:" "${LOG_DIR}/security_headers_raw.txt"; then
                echo "${header};PRESENT;OK"
            else
                echo "${header};ABSENT;Add this header"
            fi
        done
    } > "${LOG_DIR}/security_headers_report.csv"
    
    # Show summary
    print_to_console "\n${YELLOW}[i] Security Headers Report:${NC}"
    column -t -s ";" "${LOG_DIR}/security_headers_report.csv"
}

module_vuln_scan() {
    print_to_console "\n>>> [ VULNERABILITIES MODULE ]"
    
    # Use URLs from spider if available, otherwise fallback to target domain
    FETCHED_URLS=$(cat "${LOG_DIR}/spider.txt" 2>/dev/null)
    [ -z "$FETCHED_URLS" ] && FETCHED_URLS="${TEST_URLS[@]}"

    # CRLF
    log "INFO" "Testing CRLF Injection"
    CRLF_PAYLOADS=("0a0aSet-Cookie:crlf=injection" "%0aSet-Cookie:crlf=injection" "%Od%OaSet-Cookie:crlf=injection" \
                    "%OdSet-Cookie:crlf=injection" "%23%OaSet-Cookie:crlf=injection" "%23%Od%OaSet-Cookie:crlf=injection" \
                    "%23%OdSet-Cookie:crlf=injection" "%25%30%61Set-Cookie:crlf=injection" "%25%30aSet-Cookie:crlf=injection" \
                    "%250aSet-Cookie:crlf=injection" "%25250aSet-Cookie:crlf=injection" "%2e%2e%2f%Od%OaSet-Cookie:crlf=injection" \
                    "%2f%2e%2e%Od%OaSet-Cookie:crlf=injection" "%2F..%Od%OaSet-Cookie:crlf=injection" "%3f%Od%OaSet-Cookie:crlf=injection" \
                    "%3f%OdSet-Cookie:crlf=injection" "%u000aSet-Cookie:crlf=injection")

    for url in $FETCHED_URLS; do
        for payload in "${CRLF_PAYLOADS[@]}"; do
            test_url="${url}/${payload}"
            run_tool "crlf_test" "$PROXY_CHAINS curl -k -s -o /dev/null -w '%{http_code}' '${test_url}' 2>&1 | \
                grep -q \"< Set-Cookie: crlf\" && \
                log 'FOUND' \"CRLF in ${test_url}\" && \
                print_to_console \"[!] CRLF: ${test_url}\" "
        done
    done

    # PPMAP
    for url in $FETCHED_URLS; do
        run_tool "ppmap" "$PROXY_CHAINS ppmap_${url} echo $url | sed 's/ /\n/g' | $PPMAP"
    
    # Nuclei
    if [ -n "${NUCLEI_BIN}" ] && [ -x "${NUCLEI_BIN}" ]; then
        log "INFO" "Executing Nuclei (quick checks)"
        run_tool "nuclei_quick" "$PROXY_CHAINS ${NUCLEI_BIN} -u https://${TARGET_DOMAIN} -t http/technologies-detection.yaml -severity low,medium -silent"
    fi
}

module_wapiti() {
    echo -e "Running Wapiti\n--"
    echo "Its recommended to run wapiti-getcookie, set WAPITI_COOKIE_FILE and run again"
    echo -e "EX: wapiti-getcookie -c cookie.txt -u https://${DNS_NAME}/\n-"
    WAPITI_CMD="wapiti --scope folder -S normal --color -d 10 -o $WAPITI_FILE \
                    -f $WAPITI_OUTPUT_FMT -u https://${DNS_NAME}/"
    # Setting proxy
    [ $USE_PROXY == "true" ] && WAPITI_CMD="$WAPITI_CMD -p http://${PROXY}"
    # Setting cookie
    [ $WAPITI_COOKIE_FILE != "" ] && WAPITI_CMD="$WAPITI_CMD -c $WAPITI_COOKIE_FILE"
    run_tool "wapiti" "$WAPITI_CMD"
}