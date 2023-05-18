#!/usr/bin/bash
# webtaz.sh
# Fabio Almeida <mentesan@gmail.com>

# Config options
#PROXY=""
PROXY="127.0.0.1:8082"  # Levave it blank if not used
USE_PROXY="true"
USE_PROXY_CHAINS="true"
PENTESTER_URL="https://evil.com"
USER_AGENT="Mozilla/5.0"
TRACEROUTE_PORT=443
TRACEROUTE_MAX_PKTS=10
SHCHECK_BIN="/home/micron/.local/bin/shcheck.py" # pip install shcheck
WAPITI_OUTPUT_FMT="html"
WAPITI_COOKIE_FILE="cookie.txt"
NUCLEI_BIN="/home/micron/go/bin/nuclei"
LOG_DIR_PREFIX="../outputs/"
# ----------------------------
# Do not edit bellow this line
# ----------------------------
# Set vars to value or empty
[ $USE_PROXY_CHAINS == "true" ] && PROXY_CHAINS=$(which proxychains) || PROXY_CHAINS=""
[ ! -z $PROXY ] && CURL_PROXY="-x http://${PROXY}" || CURL_PROXY=""
# Minimal proxychains for use with ZAP or BurpSuite
# /etc/proxychains.conf ---> It's needed because we will use nmap with SUDO
# ---
#  strict chain
#  [ProxyList]
#  http    127.0.0.1       8082
# ---
# Also, remember to add the found HTTP IPs to the ZAP Scope!
#
#
JQ_BIN=$(which jq) || JQ_BIN="false"
LOG_DIR="${LOG_DIR_PREFIX}$(basename ${0} | sed 's/.sh//')" && mkdir -p ${LOG_DIR}
# Start clean
NO_ARGS=0
URL="unset"
DOMAIN="unset"
IP="unset"
# Error conditions
E_OPTERROR=85
E_NO_DOMAIN=86
E_LOG_FILE=87

# Setting environment
CRLF_PAYLOADS="0a0aSet-Cookie:crlf=injection
%0aSet-Cookie:crlf=injection
%Od%OaSet-Cookie:crlf=injection
%OdSet-Cookie:crlf=injection
%23%OaSet-Cookie:crlf=injection
%23%Od%OaSet-Cookie:crlf=injection
%23%OdSet-Cookie:crlf=injection
%25%30%61Set-Cookie:crlf=injection
%25%30aSet-Cookie:crlf=injection
%250aSet-Cookie:crlf=injection
%25250aSet-Cookie:crlf=injection
%2e%2e%2f%Od%OaSet-Cookie:crlf=injection
%2f%2e%2e%Od%OaSet-Cookie:crlf=injection
%2F..%Od%OaSet-Cookie:crlf=injection
%3f%Od%OaSet-Cookie:crlf=injection
%3f%OdSet-Cookie:crlf=injection
%u000aSet-Cookie:crlf=injection"

if [ $# -eq "$NO_ARGS" ] ; then
    echo "Usage: $0 -t <dns name/target> -d <domain> OR -i <ip/cidr>"
    echo "ex: ./$0 -t system.site.com.br -d site.com.br"
    exit $E_OPTERROR
fi

while getopts "t:d:i:" OPTION
do
    case $OPTION in
        t ) DNS_NAME=$OPTARG ;;
        d ) DOMAIN=$OPTARG ;;
        i ) IP=$OPTARG ;;
        * ) echo "Option not implemented";;
    esac
done

echo -e "Default options\n--------------"
echo "Traceroute port: $TRACEROUTE_PORT, max_pkts: $TRACEROUTE_MAX_PKTS"
echo "--"

dns_lookup() {
    echo -e "DNS\n---"
    # IP address of site/url resolution
    echo -n "IP: "
    IPS_FILE="${LOG_DIR}/ip_addresses.txt"
    if [ -s $IPS_FILE ]; then
        echo -e "Skipping host dns resolution, file already exixts:"
        IPS=$(cat $IPS_FILE)
    else
        IPS=$(dig +short $DNS_NAME)
        echo $IPS > $IPS_FILE
    fi
    echo -e "$IPS\n-"

    # IF DOMAIN not specified we stop here
    if [[ $DNS_NAME != "unset" && $DOMAIN == "unset" ]]; then
        echo "You need to inform the domain"
        exit $E_NODOMAIN
    fi

    # Getting nameservers of domain
    NS_FILE="${LOG_DIR}/nameservers.txt"
    if [ -s $NS_FILE ]; then
        echo -e "Skipping nameserver resolution, file already exixts:"
        NS=$(cat $NS_FILE)
    else
        echo -n "Name Servers: "
        NS=$(dig +short ns $DOMAIN)
        echo $NS > $NS_FILE
    fi
    echo $NS
    echo "--"
}

whois_lookup() {
    echo -e "WHOIS data\n----------"
    WHOIS_FILE="${LOG_DIR}/whois.txt"
    if [ -s $WHOIS_FILE ]; then
        echo -e "Skipping whois lookup, file already exists:\n--"
        cat $WHOIS_FILE
    else
        for ip in $IPS; do
             whois $ip -HI -h whois.arin.net  \
                 | grep -v '^[\%,#,]'         \
                 | tr -s '\n' '\n'            \
                     | egrep -i '^(netrange|cidr|organization|address|city|state|inetnum|aut-num|owner|responsible|person|e-mail|country|created|changed)' >> $WHOIS_FILE
         done
    fi
    echo "--"
}

hping_traceroute() {
    echo -e "Traceroute info\n----------"
    TRACEROUTE_FILE="${LOG_DIR}/traceroute.txt"
    if [ -s $TRACEROUTE_FILE ]; then
        echo -e "Skipping traceroute analysis, file already exists:\n--"
    else
        echo "Using sudo to execute raw socket operations with HPING3"
        sudo hping3 --traceroute $DNS_NAME -p $TRACEROUTE_PORT -S -c $TRACEROUTE_MAX_PKTS > $TRACEROUTE_FILE
        echo "--"
    fi
    cat $TRACEROUTE_FILE
    echo "--"
}

check_waf() {
    echo -e "Checking waf\n----------"
    WAF_FILE="${LOG_DIR}/waf.txt"
    if [ -s $WAF_FILE ]; then
        echo -e "Skipping waf analysis, file already exists:\n-"
    else
        wafw00f $DNS_NAME > $WAF_FILE
    fi
    cat $WAF_FILE
    echo "--"
}

run_nmap() {
    echo "Nmap Scan"
    echo "Using sudo to execute nmap privileged operations..."
    for ip in $IPS; do
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
                if ($( curl -s --connect-timeout 5 -X GET http://${ip}:$port >/dev/null ) \
                && [ ! -z $PROXY_CHAINS ]);
                then
                    echo -e "Detailed scan for $ip port $port with Proxychains.\n-"
                    sudo $PROXY_CHAINS -q $NMAP_CMD --script-args http.useragent="$USER_AGENT"
                else
                    echo -e "Detailed scan for $ip port $port with direct connection (non HTTP port).\n-"
                    sudo $NMAP_CMD
                fi
                echo "--"
            fi
        done
        echo "--"
    done
}

check_ssl() {
    # sslyze
    echo -e "SSL Scan (sslyze)\n--"
    SSLYZE_FILE="${LOG_DIR}/sslyze.txt"
    if [ -s $SSLYZE_FILE ]; then
        echo "Skipping sslscan, file already exists:"
    else
        sslyze  $DNS_NAME | sed '/^$/d' > $SSLYZE_FILE
    fi
    cat $SSLYZE_FILE
    echo "-"

    # sslscan
    echo -e "SSL Scan (sslscan)\n--"
    SSLSCAN_FILE="${LOG_DIR}/sslscan.txt"
    if [ -s $SSLSCAN_FILE ]; then
        echo "Skipping sslscan, file already exists:"
    else
        sslscan  $DNS_NAME | sed '/^$/d' > $SSLSCAN_FILE
    fi

    cat $SSLSCAN_FILE
    echo "--"
}

check_headers() {
    echo -e "Cheking Headers\n-- Running shcheck.py"
    HEADERS_FILE="${LOG_DIR}/headers.txt"
    if [ -s $HEADERS_FILE ]; then
        echo "Skipping headers check, file already exists:"
    else
        # No need to test, just execute with $PROXY_CHAINS empty if so
        $PROXY_CHAINS -q $SHCHECK_BIN https://$DNS_NAME > $HEADERS_FILE
    fi
    cat $HEADERS_FILE
    echo "--"
}

get_technologies() {
    # Watweb
    echo "Getting web techonologies used"
    WHATWEB_FILE="${LOG_DIR}/whatweb.txt"
    if [ -s $WHATWEB_FILE ]; then
        echo -e "Skipping whatweb, file already exists:\n-"
    else
       whatweb -v -color=always --user-agent "$USER_AGENT" --no-errors https://$DNS_NAME > $WHATWEB_FILE
    fi
    cat $WHATWEB_FILE
    echo "--"
}

fetch_urls() {
    echo -e "Fetching URLs\n--"
    FETCHED_URLS_FILE="${LOG_DIR}/fetched_urls.txt"
    touch $FETCHED_URLS_FILE
    # File already exixts
    if [ ! -s $FETCHED_URLS_FILE ]; then
        # https://github.com/lc/gau
        FETCHED_URLS=$DNS_NAME # Add base url for testing
        FETCHED_URLS=$FETCHED_URLS" "$(echo $DNS_NAME | gau)
        # https://github.com/spider-rs/spider/blob/main/spider_cli/README.md
        FETCHED_URLS=$FETCHED_URLS" "$(https_proxy=$PROXY spider -v -u "$USER_AGENT" -s \
            --domain  https://${URL} scrape 2>/dev/null \
            | grep url | cut -d\" -f4)
        # Create file with found URLs
        echo $FETCHED_URLS > $FETCHED_URLS_FILE
    else
        echo -e "URLs already fetched, if you want to fetch again remove the file with: rm $FETCHED_URLS_FILE\n--"
        FETCHED_URLS=$(cat $FETCHED_URLS_FILE)
    fi

}

check_cors() {
    # Based on https://github.com/kleiton0x00/CORS-one-liner
    echo -e "Checkinf for CORS on FETCHED_URLS\n-"
    CORS_FILE="${LOG_DIR}/cors.txt"
    if [ -s $CORS_FILE ]; then
        echo -e "Skipping CORS check, file already exists:\n-"
    else
        for url in $FETCHED_URLS; do
            for payload in $CRLF_PAYLOADS; do
                test_url=${url}/${payload}
                curl $CURL_PROXY -s -I -H "Origin: $PENTESTER_URL" -X GET $test_url | \
                    grep "$PENTESTER_URL" && \
                    echo "[Potentional CORS Found] $test_url" >> $CORS_FILE || \
                    echo "Nothing on $test_url" >> $CORS_FILE
            done
        done
    fi
    cat $CORS_FILE
    echo "--"
}

check_crlf() {
    # Based on https://github.com/kleiton0x00/CRLF-one-liner
    echo -e "Checking for Carriage Return Line Feed (CRLF)"
    CRLF_FILE="${LOG_DIR}/crlf.txt"
    if [ -s $CRLF_FILE ]; then
        echo -e "Skipping CRLF checks, file already exists:\n-"
    else
        for url in $FETCHED_URLS; do
            for payload in $CRLF_PAYLOADS; do
                test_url=${url}/${payload}
                curl $CURL_PROXY -vs --max-time 9 $test_url 2>&1 | \
                    grep -q '< Set-Cookie: ?crlf' && \
                    echo "[+] is vulnerable with payload: $test_url" >> $CRLF_FILE || \
                    echo "[-] Not vulnerable: $test_url" >> $CRLF_FILE
            done
        done
    fi
    cat $CRLF_FILE
    echo "--"
}

check_pp() {
    # https://github.com/kleiton0x00/ppmap
    echo -e "Checking for Prototype Pollution"
    PP_FILE="${LOG_DIR}/prototype_pollution.txt"
    if [ -s $PP_FILE ]; then
        echo -e "Skipping PROTOTYPE POLLUTION checks, file already exists:\n-"
    else
        echo $FETCHED_URLS | sed 's/ /\n/g' | ppmap &>> $PP_FILE
    fi
    cat $PP_FILE
    echo "--"
}

run_wapiti() {
    echo -e "Running Wapiti\n--"
    echo "Its recommended to run wapiti-getcookie, set WAPITI_COOKIE_FILE and run again"
    echo -e "EX: wapiti-getcookie -c cookie.txt -u https://${DNS_NAME}/\n-"
    WAPITI_FILE=${LOG_DIR}/wapiti-${DNS_NAME}
    # If output file exists, skip execution
    if [[ -f $WAPITI_FILE || -d $WAPITI_FILE ]]; then
        echo "Skipping Wapiti execution, output file/dir exists"
        echo "delete the file or directory $WAPITI_FILE to run again."
    else
        WAPITI_CMD="wapiti --scope folder -S normal --color -d 10 -o $WAPITI_FILE \
                     -f $WAPITI_OUTPUT_FMT -u https://${DNS_NAME}/"
        # Setting proxy
        [ $USE_PROXY == "true" ] && WAPITI_CMD="$WAPITI_CMD -p http://${PROXY}"
        # Setting cookie
        [ $WAPITI_COOKIE_FILE != "" ] && WAPITI_CMD="$WAPITI_CMD -c $WAPITI_COOKIE_FILE"
        $WAPITI_CMD
    fi
}

run_nuclei() {
    echo -e "Running nuclei\n--"
    NUCLEI_FILE="${LOG_DIR}/nuclei.txt"
    if [ -s $NUCLEI_FILE ]; then
        echo -e "Skipping nuclei execution, file already exists:\n-"
        cat $NUCLEI_FILE
    else
        $NUCLEI_BIN -t http,ssl,misconfiguration,vulnerabilities,cves,file -u $DNS_NAME -o $NUCLEI_FILE
    fi
    echo "--"
}

run_theharvester() {
    echo -e "theHarvester OSINT tool.\nYou can configure api keys in /etc/theHarvester/api-keys.yaml to increase coverage...\n--"
    HARVESTER_FILE="${LOG_DIR}/theHarvester.json"
    HARVESTER_SOURCES="anubis,baidu,bevigil,binaryedge,bing,bingapi,bufferoverun,censys,certspotter,crtsh,dnsdumpster,duckduckgo,fullhunt,github-code,hackertarget,hunter,intelx,omnisint,otx,pentesttools,projectdiscovery,qwant,rapiddns,rocketreach,securityTrails,sublist3r,threatcrowd,threatminer,urlscan,virustotal,yahoo,zoomeye"
    HARVESTER_CMD="theHarvester -d $DOMAIN -n -c -r -f $HARVESTER_FILE -b $HARVESTER_SOURCES"

    if [ -s $HARVESTER_FILE ]; then
        echo -e "Skipping theHarvester execution, file already exists:\n-"
        [[ $JQ_BIN == "false" ]] && cat $HARVESTER_FILE || cat $HARVESTER_FILE | jq
    else
        $HARVESTER_CMD
    fi
    echo "--"
}

dns_lookup
whois_lookup
#run_dnsrecon
hping_traceroute
run_theharvester
run_nuclei
check_waf
run_nmap
check_ssl
check_headers
get_technologies
fetch_urls
check_cors
check_crlf
# Prototype Pollution
check_pp
run_wapiti
#run_nikto
#run_cewl
#run_commix
#run_xss
#run_skipfish
