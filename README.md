# webtaz.sh

A web pentest kickstarter.

It's a simple script that executes tools and record their execution in separate files, some of them you suitable to import on [Faraday](https://faradaysec.com), [Dradis](https://dradisframework.com/ce/), [PCF](https://gitlab.com/invuls/pentest-projects/pcf), etc.

It aims to be simple and readable rather than fancy, so it can be easily understood and extended.

The script saves ouput from commands so if for some reason you get erros with some steps you can run it again without executing all steps again. It kind of "save state" for executed commands so to speak...

# What it does
Given de DNS site name and domain, it runs tools against them, taking a web pentest starter approach.

Do not try to trick the script, it's not that smart yet!

Proper execution:
```
./webtaz.sh -t site.doman.com -d domain.com
```
Not recommended execution
```
./webtaz.sh -t site.domain.com -d otherdom.com   ### No anticipated behavior...
```
There's an "-i" option for passing target IP address but it's not tested for the time being.

# Dependencies
The script rely on system and external tools to do it's job, at this moment there's no proper check for availability of needed tools on the system, it's a TODO feature with some other important improvements, check TODO file for more information.

Some tools are available in Kali Linux and other pentesting Linux distros, some you'll need to install from github, links are provided bellow.

# DNS and route mapping
* [dig](https://github.com/tigeli/bind-utils) for direct ip resolution and nameservers mapping
* [whois](https://github.com/rfc1036/whois) summay information
* [hping3](https://github.com/antirez/hping/tree/master) for traceroute via TCP port

# OSINT
* [theHarvester](https://github.com/laramies/theHarvester/)
* [nuclei](https://github.com/projectdiscovery/nuclei)

# Technologies discovery
* [wafw00f](https://github.com/EnableSecurity/wafw00f) to identify WAF systems
* [whatweb](https://github.com/urbanadventurer/WhatWeb) to discover site technologies

# Network and services
* [nmap](https://nmap.org) detect open ports (-sT), then proceed to verify eatch port, if it listens HTTP the command is customized

# SSL
* [sslyze](https://github.com/nabla-c0d3/sslyze)
* [sslscan](https://github.com/rbsec/sslscan)

# URL and path discovery
* [gau](https://github.com/lc/gau)
* [spider](https://github.com/spider-rs/spider)
```
cargo install spider_cli
```

# Vulnerabilities check
* [one liner cors check](https://github.com/kleiton0x00/CORS-one-liner)
* [one liner crlf check](https://github.com/kleiton0x00/CRLF-one-liner)
* [ppmap](https://github.com/kleiton0x00/ppmap) search for prototype pollution flaws

# Web scanners
* [wapiti](https://github.com/wapiti-scanner/wapiti)
* [nuclei](https://github.com/projectdiscovery/nuclei)

# Configuration
In the script header there are some important variables to edit, so it runs properly.

Some of them may seem redundant, but it's an early release ;)

## Proxy config
```
#PROXY=""
PROXY="127.0.0.1:8082"
USE_PROXY="true"
USE_PROXY_CHAINS="true"
```
* /etc/proxychains.conf
--> Because we will use nmap with SUDO.

Minimal proxychains for use with ZAP and/or BurpSuite.

Remember to add the found HTTP IPs to ZAP Scope!

```
# ---
#  strict chain
#  [ProxyList]
#  http    127.0.0.1       8082
# ---
```
## URL to use on some payloads
Ex: CORS check.
```
PENTESTER_URL="https://evil.com"
```
## USER Agent to use
Maybe implement random user agent in the future, for now just put it here.
```
USER_AGENT="Mozilla/5.0"
```
## TCP port for "hping3" traceroute
We can automate it, but as we are doing a "web pentest", it's a good default.

Also, specify "max pkts" which is kind of "max hops", so it not hangs too much.
```
TRACEROUTE_PORT=443
TRACEROUTE_MAX_PKTS=10
```
## Headers check
shcheck.py you cann install with "pip install shcheck"
```
SHCHECK_BIN="/home/micron/.local/bin/shcheck.py"
```
## Wapiti
Output format and cookie file, this cookie var probably will change in future releases and used with other tools.
```
WAPITI_OUTPUT_FMT="html"
WAPITI_COOKIE_FILE="cookie.txt"
```
## Nuclei
```
NUCLEI_BIN="/home/micron/go/bin/nuclei"
```
## Output directory
Just the prefix, something like "./reports" "../webtaz" "/home/user/work/webtaz"
```
LOG_DIR_PREFIX="/outputs/"
```

# Know caveats
* Some tools work with proxychains, others work with ZAP and BurpSuite Chained, others just with BurpSuite, other with own options (-p, --proxy)
* Unfortunately I couldn't get some tools to work witha any proxy yet, some may not make sense like SSL and Waf checks

# Contributing
Fell free to sugest features, improvements and tips.

