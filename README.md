# webtaz.sh

A web pentest kickstarter.
It's a simple script that executes some tools and record the run in separate files, some of them you can import on [Faraday](https://faradaysec.com), [Dradis](https://dradisframework.com/ce/), [PCF](https://gitlab.com/invuls/pentest-projects/pcf), etc.
It aims to be simple and readable rather than fancy, so it can be easily understood and extended.

## What it does
Given de DNS site name and domain, it runs various tools against them, taking a web pentest starter approach.

# At this momemnt the script runs:

## DNS and route mapping
* dig for direct ip resolution and nameservers mapping
* whois summay information.
* dnsrecon
* hping for traceroute via TCP port

# Technologies discovery
* wafw00f to identify WAF systems
* whatweb to discover site technologies.

# Network and services
* nmap to etect open ports, then proceed to verify eatch port, if it listens HTTP the command is customized.

# SSL
* sslyze
* sslscan

# URL and path discovery
* gau
* spider

# Vulnerabilities check
* one liner cors check
* one liner crlf check
* ppmap to search for parameter pollution flaws

# Web scanners
* wapiti
* nuclei

# OSINT
* theHarvester
* nuclei

# Custom wordlist build
* cewl

# Basic SQL flaws
* sqlmap

# Command injection
* commix
