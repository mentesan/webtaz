# ============
# RECON MODULE
# ============
module_recon() {
    module_dns
    module_whois
    module_hping
    module_subdomain
    module_portscan
    module_tech_detection   
    module_osint
}

module_dns() {
    print_to_console "\n>>> [ DNS MODULE ]"
    run_tool "dig_ips" "dig +short ${TARGET} | grep -oE '([0-9]{1,3}\\.){3}[0-9]{1,3}' | sort -u"
    run_tool "dig_ns" "dig +short NS ${TARGET}"
    run_tool "dig_mx" "dig +short MX ${TARGET}"
}

module_whois() {
    print_to_console "\n>>> [ WHOIS MODULE ]" 
    WHOIS_FILE="${LOG_DIR}/whois.txt"
    for IP in $(cat "${LOG_DIR}/dig_ips.txt" 2>/dev/null); do
        log "INFO" "Executing whois for: ${IP}"
        run_tool "whois_${IP}" "
            whois $IP -HI -h whois.arin.net  \
                | grep -v '^[\%,#,]'         \
                | tr -s '\n' '\n'            \
                | egrep -i '^(netrange|cidr|organization|address|city|state|inetnum|aut-num|owner|responsible|person|e-mail|country|created|changed)'"
    done
}

module_hping() {
    print_to_console "\n>>> [ TRACEROUTE MODULE ]"
    for IP in $(cat "${LOG_DIR}/dig_ips.txt" 2>/dev/null); do
        run_tool "hping_${IP}" "sudo hping3 --traceroute $TARGET -p $TRACEROUTE_PORT -S -c $TRACEROUTE_MAX_PKTS"
    done
}

module_subdomain() {
    print_to_console "\n>>> [ SUBDOMAINS - BASIC MODE ]"
    
    # Uses simple crt.sh query for subdomains
    run_tool "subdomain_crtsh" "curl -k -s 'https://crt.sh/?q=%25.${TARGET}&output=json' | jq -r '.[].name_value' 2>/dev/null | sort -u"
    
    # Verify common subdomains
    COMMON_SUBS="www mail ftp admin api test dev staging"
    for sub in $COMMON_SUBS; do
        host "${sub}.${TARGET}" 2>/dev/null | grep "has address" | tee -a "${LOG_DIR}/subdomains.txt"
    done
    
    # Sums up results
    if [ -f "${LOG_DIR}/subdomains.txt" ]; then
        COUNT=$(wc -l < "${LOG_DIR}/subdomains.txt")
        print_to_console "\n${GREEN}[+] ${COUNT} subdomains found${NC}"
    fi
}

module_portscan() {
    print_to_console "\n>>> [ PORTSCAN MODULE ]"
    
    for ip in $(cat "${LOG_DIR}/dig_ips.txt" 2>/dev/null); do
        log "INFO" "Scanning host: ${ip}"
        run_tool "nmap_quick_${ip}" "$PROXY_CHAINS sudo nmap -Pn -T4 --open -n ${ip} | grep '^[0-9]' | cut -d'/' -f1"
    done

    for ip in $(cat "${LOG_DIR}/dig_ips.txt" 2>/dev/null); do
        echo -e "Nmap scan for ip $ip"
        OPEN_PORTS_FILE="${LOG_DIR}/nmap-open_ports.txt"
        touch $OPEN_PORTS_FILE
        # Check if file is blank
        if [ ! -s $OPEN_PORTS_FILE ]; then
            OPEN_PORTS=$(sudo nmap -PN -sT $ip --open | grep '^[0-9]' | cut -d/ -f1)
            echo $OPEN_PORTS > $OPEN_PORTS_FILE
        else
            OPEN_PORTS=$(cat $OPEN_PORTS_FILE)
        fi
        echo "--"

        # Show open ports
        echo -n "- Open ports: "
        for port in $OPEN_PORTS; do
              echo -n "$port, "
        done
        echo ""

        # Scan each port
        for port in $OPEN_PORTS; do
            NMAP_FILE="${LOG_DIR}/nmap-${ip}-${port}.xml"
            NMAP_CMD="nmap -Pn -A -sT -sV -sC -oX $NMAP_FILE -p $port $ip"

            if [ -s $NMAP_FILE ]; then
                echo "Skippint nmap for port $port, file already exists"
            else
                if ($( curl -k -s --connect-timeout 5 -X GET http://${ip}:$port >/dev/null ) \
                && [ ! -z $PROXY_CHAINS ]);
                then
                    echo -e "Detailed scan for $ip port $port with Proxychains.\n-"
                    run_tool "nmap http port" "sudo $PROXY_CHAINS -q $NMAP_CMD --script-args http.useragent=\"$USER_AGENT\""
                else
                    echo -e "Detailed scan for $ip port $port with direct connection (non HTTP port).\n-"
                    run_tool "nmap direct port" "sudo $NMAP_CMD"
                fi
                echo "--"
            fi
        done
        echo "--"
    done
}

module_tech_detection() {
    print_to_console "\n>>> [ TECHNOLOGY DETECTION MODULE ]"
    
    # WhatWeb
    run_tool "whatweb" "$PROX_CHAINS whatweb -v -color=never --no-errors https://${TARGET}"
    
    # Wappalyzer local
    run_tool "wappalyzer" "wappalyzer https://${TARGET} 2>/dev/null | jq . 2>/dev/null || echo 'JSON format not available'"
    # Header analysis
    print_to_console "\n[i] Detected Technologies in Headers:"
    curl -k -I "https://${TARGET}" 2>/dev/null | grep -iE "(server|x-powered-by|asp.net|php|wordpress|drupal|joomla)" | tee "${LOG_DIR}/tech_headers.txt"
    # Waf detection with wafw00f
    run_tool "wafw00f" "$WAFW00F https://${TARGET}"
    # Fetch URLs
    run_tool "spider" "https_proxy=$PROXY spider -v -u \"$USER_AGENT\" -s \
            --domain  https://${TARGET} scrape 2>/dev/null \
            | grep url | cut -d\" -f4)"
}

module_osint() {
    # theHarvester
    echo -e "theHarvester OSINT tool.\nYou can configure api keys in /etc/theHarvester/api-keys.yaml to increase coverage...\n--"
    HARVESTER_SOURCES="baidu,bevigil,bing,bingapi,bufferoverun,censys,certspotter,crtsh,dnsdumpster,duckduckgo,fullhunt,github-code,hackertarget,hunter,intelx,omnisint,otx,pentesttools,projectdiscovery,qwant,rapiddns,rocketreach,securityTrails,sublist3r,threatcrowd,threatminer,urlscan,virustotal,yahoo,zoomeye"
    HARVESTER_CMD="theHarvester -d $TARGET -n -c -r -f $HARVESTER_FILE -b $HARVESTER_SOURCES"

    run_tool "theHarvester" "$HARVESTER_CMD"

    # nuclei
    run_tool "nuclei" "$NUCLEI_BIN -t http,ssl,misconfiguration,vulnerabilities,cves,file -u $TARGET -o $NUCLEI_FILE"
}