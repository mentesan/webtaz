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
    proxychains curl -k -I "https://${TARGET}" 2>/dev/null > "${LOG_DIR}/security_headers_raw.txt"
    run_tool "shcheck.py" "proxychains shcheck.py -d https://$TARGET"

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
            curl $CURL_PROXY -vs --max-time 9 $test_url 2>&1 | \
                grep -q '< Set-Cookie: ?crlf' && \
                echo "[+] is vulnerable with payload: $test_url" >> ${LOG_DIR}/crlf_test.txt || \
                echo "[-] Not vulnerable: $test_url" >> ${LOG_DIR}/crlf_test.txt
        done
    done

    # PPMAP
    if [ -f ${LOG_DIR}/ppmap.txt ]; then
        print_to_console "\n[i] PPMAP Results:\n$(cat ${LOG_DIR}/ppmap.txt)" 
    else 
        log "INFO" "Executing PPMAP for technology-specific vulnerabilities"
        run_tool "ppmap" "cat ${LOG_DIR}/spider.txt | ppmap"
    fi
    # Nuclei
    if [ -f ${LOG_DIR}/nuclei_vuln.txt ]; then
        print_to_console "\n[i] Nuclei Vulnerability Scan Results:\n$(cat ${LOG_DIR}/nuclei_vuln.txt)"
    else
        log "INFO" "Executing Nuclei"
        run_tool "nuclei_vuln" "nuclei -u https://${TARGET} -silent -t http/cves -t http/misconfiguration -t http/vulnerabilities -t http/exposures"
    fi
}

module_wapiti() {
    echo -e "Running Wapiti\n--"
    echo "Its recommended to run wapiti-getcookie, set WAPITI_COOKIE_FILE and run again"
    echo -e "EX: wapiti-getcookie -c cookie.txt -u https://${TARGET}/\n-"
    WAPITI_OPT="--scope folder -S normal --color -d 10 -f $WAPITI_OUTPUT_FMT -u https://${TARGET}/"
    # Setting proxy
    [ $USE_PROXY == "true" ] && WAPITI_OPT="$WAPITI_OPT -p http://${PROXY}"
    # Setting cookie
    [ $WAPITI_COOKIE_FILE != "" ] && WAPITI_OPT="$WAPITI_OPT -c $WAPITI_COOKIE_FILE"
    run_tool "wapiti" "wapiti $WAPITI_OPT"
    echo "COMMANDO: wapiti $WAPITI_OPT"
}