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
    COMMON_SUBS="www mail ftp admin api test dev development dev1 dev2 dev-api dev-app dev-web devops \
staging stage stg preprod pre-production preprod-api hmg homolog homologacao uatt uat qa qat test \
testing testsrv sandbox lab lab01 lab02 ci cd cicd jenkins gitlab build builds artifacts intranet \
internal int corp corporate vpn fw router gw proxy api api-dev api-staging api-qa api-test app app-dev \
app-test web web-test db db-dev database mysql postgres redis cache files storage minio backup ti infra \
security sec devteam support helpdesk tmp temp experimental exp beta alpha preview playground"

    for sub in $COMMON_SUBS; do
        host "${sub}.${TARGET}" 2>/dev/null | grep "has address" | tee -a "${LOG_DIR}/subdomains.txt"
        host "${sub}-${TARGET}" 2>/dev/null | grep "has address" | tee -a "${LOG_DIR}/subdomains.txt"
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
                    run_tool "nmap_http_port" "sudo $PROXY_CHAINS -q $NMAP_CMD --script-args http.useragent=\"$USER_AGENT\""
                else
                    echo -e "Detailed scan for $ip port $port with direct connection (non HTTP port).\n-"
                    run_tool "nmap_direct_port" "sudo $NMAP_CMD"
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
    
    # Header analysis
    print_to_console "\n[i] Detected Technologies in Headers:"
    curl -k -I "https://${TARGET}" 2>/dev/null | grep -iE "(server|x-powered-by|asp.net|php|wordpress|drupal|joomla)" | tee "${LOG_DIR}/tech_headers.txt"
    # Waf detection with wafw00f
    run_tool "wafw00f" "wafw00f https://${TARGET}"
    echo "COMANDO WAFW00F: wafw0ff https://${TARGET}"
    # Fetch URLs
    run_tool "spider" "spider --url ${TARGET} scrape 2>/dev/null | grep url | cut -d'\"' -f4"
}

module_osint() {
    # theHarvester
    echo -e "theHarvester OSINT tool.\nYou can configure api keys in /etc/theHarvester/api-keys.yaml to increase coverage...\n--"
#    #HARVESTER_SOURCES="baidu,bevigil,bufferoverun,censys,certspotter,crtsh,dnsdumpster,duckduckgo,fullhunt,github-code,hackertarget,hunter,intelx,omnisint,otx,pentesttools,projectdiscovery,qwant,rapiddns,rocketreach,securityTrails,sublist3r,threatcrowd,urlscan,virustotal,yahoo,zoomeye"
    HARVESTER_SOURCES="baidu,certspotter,duckduckgo,hackertarget,otx,rapiddns,threatcrowd,urlscan,crtsh,yahoo"
    HARVESTER_OPT="-d $TARGET -n -r -b $HARVESTER_SOURCES"
    run_tool "theHarvester" "theHarvester $HARVESTER_OPT"

    # nuclei
    run_tool "nuclei_recon" "nuclei -u https://${TARGET}/ -silent -t http/technologies -t http/exposed-panels -t ssl -t dns/dns-waf-detect -t javascript/enumeration"
    echo "COMMANDO: nuclei -u https://${TARGET}/ -silent -t http/technologies -t http/exposed-panels -t ssl -t dns/dns-waf-detect -t javascript/enumeration"
}