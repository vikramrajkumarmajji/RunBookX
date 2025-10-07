import React, { useState, useRef } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '/components/ui/card';
import { Button } from '/components/ui/button';
import { Input } from '/components/ui/input';
import { Label } from '/components/ui/label';
import { Target, Shield, Search, Code, Database, Cloud, Smartphone, Wifi, Lock, FileText, Copy, Check } from 'lucide-react';

interface CommandCategory {
  name: string;
  description: string;
  commands: Command[];
}

interface Command {
  name: string;
  description: string;
  command: string;
  category: string;
}

const BugBountyToolkit: React.FC = () => {
  const [target, setTarget] = useState('');
  const [targetType, setTargetType] = useState<'domain' | 'ip' | ''>('');
  const [copiedCommand, setCopiedCommand] = useState<string | null>(null);
  const commandRefs = useRef<{ [key: string]: HTMLPreElement | null }>({});

  const detectTargetType = (input: string): 'domain' | 'ip' | '' => {
    if (!input) return '';
    
    // Basic IP validation
    const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    if (ipRegex.test(input)) return 'ip';
    
    // Basic domain validation
    const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$/;
    if (domainRegex.test(input) || input.includes('.')) return 'domain';
    
    return '';
  };

  const handleTargetChange = (value: string) => {
    setTarget(value);
    setTargetType(detectTargetType(value));
  };

  const copyToClipboard = async (command: string, commandName: string) => {
    try {
      // Fallback for browsers that don't support clipboard API
      if (!navigator.clipboard) {
        const textArea = document.createElement('textarea');
        textArea.value = command;
        textArea.style.position = 'fixed';
        textArea.style.left = '-999999px';
        textArea.style.top = '-999999px';
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        document.execCommand('copy');
        document.body.removeChild(textArea);
      } else {
        await navigator.clipboard.writeText(command);
      }
      setCopiedCommand(commandName);
      setTimeout(() => setCopiedCommand(null), 2000);
    } catch (err) {
      console.error('Failed to copy command:', err);
      // Additional fallback
      const textArea = document.createElement('textarea');
      textArea.value = command;
      document.body.appendChild(textArea);
      textArea.select();
      document.execCommand('copy');
      document.body.removeChild(textArea);
      setCopiedCommand(commandName);
      setTimeout(() => setCopiedCommand(null), 2000);
    }
  };

  const generateCommands = (target: string, type: 'domain' | 'ip'): CommandCategory[] => {
    const categories: CommandCategory[] = [
      {
        name: "Network Reconnaissance",
        description: "Basic network discovery and port scanning",
        commands: [
          {
            name: "Nmap TCP SYN Scan",
            description: "Fast TCP port scan with service detection",
            command: `nmap -sS -sV -O -A ${target}`,
            category: "recon"
          },
          {
            name: "Nmap Comprehensive Scan",
            description: "Comprehensive scan with scripts and version detection",
            command: `nmap -sC -sV -A -T4 -p- ${target}`,
            category: "recon"
          },
          {
            name: "Nmap UDP Scan",
            description: "UDP port scan for common services",
            command: `nmap -sU --top-ports 1000 ${target}`,
            category: "recon"
          },
          {
            name: "Nmap Stealth Scan",
            description: "Stealth scan with timing controls",
            command: `nmap -sS -T2 -f --data-length 25 ${target}`,
            category: "recon"
          },
          {
            name: "Nmap Top Ports Scan",
            description: "Scan most common 1000 ports quickly",
            command: `nmap --top-ports 1000 -sV ${target}`,
            category: "recon"
          },
          {
            name: "Nmap OS Detection",
            description: "Operating system detection scan",
            command: `nmap -O --osscan-guess ${target}`,
            category: "recon"
          },
          {
            name: "Nmap Script Scan",
            description: "Run default NSE scripts",
            command: `nmap -sC ${target}`,
            category: "recon"
          },
          {
            name: "Nmap Aggressive Scan",
            description: "Aggressive scan with all features",
            command: `nmap -A -T4 ${target}`,
            category: "recon"
          },
          {
            name: "Masscan Fast Port Scan",
            description: "Very fast port scanner",
            command: `masscan -p1-65535 ${target} --rate=1000`,
            category: "recon"
          },
          {
            name: "Masscan Top Ports",
            description: "Masscan common ports at high speed",
            command: `masscan -p80,443,8080,8443,22,21,25,53,110,143,993,995 ${target} --rate=10000`,
            category: "recon"
          },
          {
            name: "RustScan Port Discovery",
            description: "Ultra-fast port scanner written in Rust",
            command: `rustscan -a ${target} -- -sC -sV`,
            category: "recon"
          },
          {
            name: "Zmap Internet Scan",
            description: "Fast single packet network scanner",
            command: `zmap -p 80 ${target}/24`,
            category: "recon"
          },
          {
            name: "Unicornscan Port Discovery",
            description: "Asynchronous network stimulus delivery engine",
            command: `unicornscan ${target}:1-65535`,
            category: "recon"
          },
          {
            name: "Hping3 Port Scan",
            description: "Advanced ping utility with custom packet crafting",
            command: `hping3 -S -p 80 ${target}`,
            category: "recon"
          },
          {
            name: "Nping Network Packet Generation",
            description: "Network packet generation and response analysis",
            command: `nping --tcp-connect -c 4 -p 80,443 ${target}`,
            category: "recon"
          },
          {
            name: "Zenmap GUI Scan",
            description: "Nmap GUI for visual network mapping",
            command: `zenmap`,
            category: "recon"
          },
          {
            name: "Angry IP Scanner",
            description: "Fast and friendly network scanner",
            command: `ipscan ${target}/24`,
            category: "recon"
          },
          {
            name: "Advanced Port Scanner",
            description: "Multi-threaded port scanner",
            command: `aps ${target} 1-65535`,
            category: "recon"
          },
          {
            name: "Netdiscover ARP Scanner",
            description: "Active/passive ARP reconnaissance tool",
            command: `netdiscover -r ${target}/24`,
            category: "recon"
          },
          {
            name: "FPing Host Discovery",
            description: "Fast ping utility for host discovery",
            command: `fping -g ${target}/24`,
            category: "recon"
          },
          {
            name: "NBTScan NetBIOS Scanner",
            description: "NetBIOS nameserver scanner",
            command: `nbtscan ${target}/24`,
            category: "recon"
          },
          {
            name: "Ping Sweep",
            description: "Simple ping sweep for live host discovery",
            command: `nmap -sn ${target}/24`,
            category: "recon"
          },
          {
            name: "TCP Connect Scan",
            description: "Basic TCP connect scan",
            command: `nmap -sT -p- ${target}`,
            category: "recon"
          },
          {
            name: "ACK Scan Firewall Detection",
            description: "ACK scan to detect firewall rules",
            command: `nmap -sA ${target}`,
            category: "recon"
          },
          {
            name: "Window Scan",
            description: "TCP window scan for stealth reconnaissance",
            command: `nmap -sW ${target}`,
            category: "recon"
          },
          {
            name: "Maimon Scan",
            description: "Maimon scan technique",
            command: `nmap -sM ${target}`,
            category: "recon"
          },
          {
            name: "Idle Scan",
            description: "Stealth scan using idle host",
            command: `nmap -sI zombie_host ${target}`,
            category: "recon"
          },
          {
            name: "FIN Scan",
            description: "FIN scan for firewall evasion",
            command: `nmap -sF ${target}`,
            category: "recon"
          },
          {
            name: "NULL Scan",
            description: "NULL scan with no flags set",
            command: `nmap -sN ${target}`,
            category: "recon"
          },
          {
            name: "XMAS Scan",
            description: "Christmas tree scan with multiple flags",
            command: `nmap -sX ${target}`,
            category: "recon"
          }
        ]
      },
      {
        name: "DNS Enumeration",
        description: "DNS reconnaissance and subdomain discovery",
        commands: type === 'domain' ? [
          {
            name: "DNS Zone Transfer",
            description: "Attempt DNS zone transfer",
            command: `dig axfr @ns1.${target} ${target}`,
            category: "dns"
          },
          {
            name: "DNS Record Enumeration",
            description: "Enumerate common DNS records",
            command: `dig ${target} ANY +noall +answer`,
            category: "dns"
          },
          {
            name: "Sublist3r Subdomain Discovery",
            description: "Subdomain enumeration using Sublist3r",
            command: `sublist3r -d ${target} -b -t 100`,
            category: "dns"
          },
          {
            name: "Subfinder Subdomain Discovery",
            description: "Fast subdomain discovery tool",
            command: `subfinder -d ${target} -silent`,
            category: "dns"
          },
          {
            name: "DNSRecon Enumeration",
            description: "DNS enumeration and zone walking",
            command: `dnsrecon -d ${target} -a`,
            category: "dns"
          },
          {
            name: "Amass Subdomain Enumeration",
            description: "Advanced subdomain discovery",
            command: `amass enum -d ${target}`,
            category: "dns"
          },
          {
            name: "Amass Active Enumeration",
            description: "Active subdomain enumeration",
            command: `amass enum -active -d ${target} -brute`,
            category: "dns"
          },
          {
            name: "AssetFinder Subdomain Discovery",
            description: "Find domains and subdomains",
            command: `assetfinder --subs-only ${target}`,
            category: "dns"
          },
          {
            name: "Findomain Subdomain Search",
            description: "Fast subdomain enumerator",
            command: `findomain -t ${target}`,
            category: "dns"
          },
          {
            name: "Chaos Subdomain Discovery",
            description: "ProjectDiscovery's subdomain service",
            command: `chaos -d ${target}`,
            category: "dns"
          },
          {
            name: "DNS Bruteforce",
            description: "Bruteforce subdomains with custom wordlist",
            command: `dnsrecon -d ${target} -D /usr/share/wordlists/dnsmap.txt -t brt`,
            category: "dns"
          },
          {
            name: "Fierce DNS Scanner",
            description: "DNS reconnaissance tool",
            command: `fierce -dns ${target}`,
            category: "dns"
          },
          {
            name: "DNSEnum Enumeration",
            description: "Multithreaded perl script for DNS enumeration",
            command: `dnsenum ${target}`,
            category: "dns"
          },
          {
            name: "MassDNS Resolution",
            description: "High-performance DNS resolver",
            command: `massdns -r /opt/massdns/lists/resolvers.txt -t A ${target} -o S`,
            category: "dns"
          },
          {
            name: "Shuffledns Resolution",
            description: "Wrapper around massdns for subdomain resolution",
            command: `shuffledns -d ${target} -list subdomains.txt -r resolvers.txt`,
            category: "dns"
          },
          {
            name: "Puredns Bruteforcing",
            description: "Fast domain resolver with wildcard filtering",
            command: `puredns bruteforce /usr/share/wordlists/best-dns-wordlist.txt ${target}`,
            category: "dns"
          },
          {
            name: "Altdns Subdomain Permutation",
            description: "Generate permutations, alterations and mutations of subdomains",
            command: `altdns -i subdomains.txt -o output.txt -w /usr/share/wordlists/altdns-words.txt`,
            category: "dns"
          },
          {
            name: "Knock Subdomain Scanner",
            description: "Python subdomain enumeration tool",
            command: `knockpy ${target}`,
            category: "dns"
          },
          {
            name: "Gobuster DNS Bruteforce",
            description: "DNS mode bruteforcing",
            command: `gobuster dns -d ${target} -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 50`,
            category: "dns"
          },
          {
            name: "FFuF Subdomain Fuzzing",
            description: "Fast subdomain fuzzing",
            command: `ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.${target}" -u http://${target}`,
            category: "dns"
          },
          {
            name: "Dig ALL Records",
            description: "Get all DNS records for domain",
            command: `dig ${target} ANY`,
            category: "dns"
          },
          {
            name: "Nslookup MX Records",
            description: "Mail exchange record lookup",
            command: `nslookup -type=MX ${target}`,
            category: "dns"
          },
          {
            name: "Nslookup NS Records",
            description: "Name server record lookup",
            command: `nslookup -type=NS ${target}`,
            category: "dns"
          },
          {
            name: "Nslookup TXT Records",
            description: "Text record enumeration",
            command: `nslookup -type=TXT ${target}`,
            category: "dns"
          },
          {
            name: "Nslookup SOA Records",
            description: "Start of authority record lookup",
            command: `nslookup -type=SOA ${target}`,
            category: "dns"
          },
          {
            name: "DNSdumpster Search",
            description: "DNS reconnaissance using DNSdumpster",
            command: `curl -s "https://dnsdumpster.com/api/" -d "targetip=${target}"`,
            category: "dns"
          },
          {
            name: "Crt.sh Certificate Search",
            description: "Certificate transparency subdomain discovery",
            command: `curl -s "https://crt.sh/?q=%.${target}&output=json" | jq -r '.[].name_value' | sort -u`,
            category: "dns"
          },
          {
            name: "Virus Total API",
            description: "Subdomain discovery via VirusTotal",
            command: `curl -s "https://www.virustotal.com/vtapi/v2/domain/report?apikey=YOUR_API_KEY&domain=${target}"`,
            category: "dns"
          },
          {
            name: "SecurityTrails API",
            description: "Historical DNS data and subdomains",
            command: `curl -s "https://api.securitytrails.com/v1/domain/${target}/subdomains" -H "APIKEY: YOUR_API_KEY"`,
            category: "dns"
          },
          {
            name: "RapidDNS Search",
            description: "Rapid DNS subdomain search",
            command: `curl -s "https://rapiddns.io/subdomain/${target}" | grep -oP '(?<=<td><a href="//)[^"]*' | sort -u`,
            category: "dns"
          },
          {
            name: "CertSpotter API",
            description: "Certificate Spotter subdomain discovery",
            command: `curl -s "https://certspotter.com/api/v0/certs?domain=${target}" | jq -r '.[].dns_names[]' | sort -u`,
            category: "dns"
          },
          {
            name: "HackerTarget API",
            description: "Online subdomain scanner",
            command: `curl -s "https://api.hackertarget.com/hostsearch/?q=${target}"`,
            category: "dns"
          },
          {
            name: "ThreatMiner API",
            description: "Threat intelligence subdomain search",
            command: `curl -s "https://api.threatminer.org/v2/domain.php?q=${target}&rt=5"`,
            category: "dns"
          }
        ] : [
          {
            name: "Reverse DNS Lookup",
            description: "Get hostname from IP address",
            command: `dig -x ${target}`,
            category: "dns"
          },
          {
            name: "PTR Record Lookup",
            description: "Reverse DNS pointer record lookup",
            command: `nslookup ${target}`,
            category: "dns"
          },
          {
            name: "Reverse DNS with Host",
            description: "Reverse lookup using host command",
            command: `host ${target}`,
            category: "dns"
          }
        ]
      },
      {
        name: "Web Application Testing",
        description: "Web application reconnaissance and testing",
        commands: [
          {
            name: "Gobuster Directory Bruteforce",
            description: "Directory and file discovery",
            command: `gobuster dir -u http://${target} -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,js,txt,xml`,
            category: "web"
          },
          {
            name: "Gobuster DNS Subdomain",
            description: "DNS subdomain bruteforcing",
            command: `gobuster dns -d ${target} -w /usr/share/wordlists/dnsmap.txt`,
            category: "web"
          },
          {
            name: "Gobuster Virtual Host Discovery",
            description: "Virtual host discovery",
            command: `gobuster vhost -u http://${target} -w /usr/share/wordlists/subdomains-top1million-5000.txt`,
            category: "web"
          },
          {
            name: "FFUF Directory Fuzzing",
            description: "Fast web fuzzer",
            command: `ffuf -u http://${target}/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -mc 200,204,301,302,307,401,403`,
            category: "web"
          },
          {
            name: "FFUF Parameter Fuzzing",
            description: "Parameter discovery with ffuf",
            command: `ffuf -u http://${target}/?FUZZ=test -w /usr/share/wordlists/burp-parameter-names.txt -mc 200`,
            category: "web"
          },
          {
            name: "FFUF Virtual Host Fuzzing",
            description: "Virtual host fuzzing",
            command: `ffuf -w /usr/share/wordlists/subdomains-top1million-5000.txt -u http://${target} -H "Host: FUZZ.${target}"`,
            category: "web"
          },
          {
            name: "Feroxbuster Recursive Scan",
            description: "Fast, simple, recursive content discovery",
            command: `feroxbuster -u http://${target} -w /usr/share/wordlists/raft-medium-directories.txt`,
            category: "web"
          },
          {
            name: "Dirsearch Directory Scanner",
            description: "Web path scanner",
            command: `dirsearch -u http://${target} -e php,html,js,txt`,
            category: "web"
          },
          {
            name: "Nikto Web Scanner",
            description: "Web server vulnerability scanner",
            command: `nikto -h http://${target}`,
            category: "web"
          },
          {
            name: "WhatWeb Technology Detection",
            description: "Identify web technologies",
            command: `whatweb http://${target}`,
            category: "web"
          },
          {
            name: "Dirb Directory Scanner",
            description: "Web content scanner",
            command: `dirb http://${target} /usr/share/dirb/wordlists/common.txt`,
            category: "web"
          },
          {
            name: "WaybackURLs Historical URLs",
            description: "Fetch URLs from Wayback Machine",
            command: `waybackurls ${target}`,
            category: "web"
          },
          {
            name: "GAU Get All URLs",
            description: "Get URLs from multiple sources",
            command: `gau ${target}`,
            category: "web"
          },
          {
            name: "Hakrawler Web Crawler",
            description: "Fast web crawler for gathering URLs",
            command: `hakrawler -url http://${target} -depth 3`,
            category: "web"
          },
          {
            name: "Gospider Web Crawler",
            description: "Web spider written in Go",
            command: `gospider -s http://${target} -c 10 -d 3`,
            category: "web"
          },
          {
            name: "Paramspider Parameter Discovery",
            description: "Parameter mining tool",
            command: `paramspider -d ${target}`,
            category: "web"
          },
          {
            name: "Arjun Parameter Discovery",
            description: "HTTP parameter discovery",
            command: `arjun -u http://${target}`,
            category: "web"
          },
          {
            name: "HTTProbe URL Validation",
            description: "Check if URLs are alive",
            command: `echo ${target} | httprobe`,
            category: "web"
          },
          {
            name: "Meg HTTP Request Tool",
            description: "Fetch many paths for many hosts",
            command: `meg /usr/share/wordlists/common.txt hosts.txt`,
            category: "web"
          },
          {
            name: "Unfurl URL Analysis",
            description: "Pull out bits of URLs provided on stdin",
            command: `cat urls.txt | unfurl domains`,
            category: "web"
          },
          {
            name: "HTTPx HTTP Toolkit",
            description: "Fast and multi-purpose HTTP toolkit",
            command: `httpx -l hosts.txt -ports 80,443,8080,8443 -title -tech-detect`,
            category: "web"
          },
          {
            name: "Aquatone Screenshot Tool",
            description: "Tool for visual inspection of websites",
            command: `cat hosts.txt | aquatone -ports 80,443,8000,8080,8443`,
            category: "web"
          },
          {
            name: "Eyewitness Web Screenshot",
            description: "Take screenshots of websites",
            command: `eyewitness --web -f hosts.txt`,
            category: "web"
          },
          {
            name: "Wfuzz Web Fuzzer",
            description: "Web content fuzzer",
            command: `wfuzz -c -z file,/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --hc 404 http://${target}/FUZZ`,
            category: "web"
          },
          {
            name: "Linkfinder JS Endpoint Discovery",
            description: "Discover endpoints in JavaScript files",
            command: `linkfinder -i http://${target} -o cli`,
            category: "web"
          },
          {
            name: "JSParser Endpoint Extraction",
            description: "Extract endpoints from JavaScript files",
            command: `jsparser -u http://${target}`,
            category: "web"
          },
          {
            name: "Burp Suite Pro Scan",
            description: "Professional web vulnerability scanner",
            command: `burpsuite --project-file=scan.burp --unpause-spider-and-scanner`,
            category: "web"
          },
          {
            name: "ZAP Baseline Scan",
            description: "OWASP ZAP baseline security scan",
            command: `zap-baseline.py -t http://${target}`,
            category: "web"
          },
          {
            name: "ZAP Full Scan",
            description: "OWASP ZAP comprehensive security scan",
            command: `zap-full-scan.py -t http://${target}`,
            category: "web"
          },
          {
            name: "Skipfish Web Scanner",
            description: "Active web application security reconnaissance",
            command: `skipfish -o output_dir http://${target}`,
            category: "web"
          },
          {
            name: "W3af Web Scanner",
            description: "Web application attack and audit framework",
            command: `w3af_console -s scan_profile.w3af`,
            category: "web"
          },
          {
            name: "Arachni Web Scanner",
            description: "Feature-full modular web scanner",
            command: `arachni http://${target}`,
            category: "web"
          },
          {
            name: "WebScarab Security Testing",
            description: "Framework for web application security testing",
            command: `webscarab`,
            category: "web"
          },
          {
            name: "Vega Web Scanner",
            description: "Open source web security scanner",
            command: `vega`,
            category: "web"
          },
          {
            name: "Grabber Web Scanner",
            description: "Small web application scanner",
            command: `grabber -s 0 -u http://${target}`,
            category: "web"
          },
          {
            name: "Wapiti Web Scanner",
            description: "Web application vulnerability scanner",
            command: `wapiti -u http://${target}`,
            category: "web"
          },
          {
            name: "Paros Proxy Scanner",
            description: "Java-based HTTP/HTTPS proxy",
            command: `paros`,
            category: "web"
          },
          {
            name: "Ratproxy Web Scanner",
            description: "Passive web application security assessment",
            command: `ratproxy -w output.log -v http://${target}`,
            category: "web"
          },
          {
            name: "Websecurify Scanner",
            description: "Web security testing framework",
            command: `websecurify ${target}`,
            category: "web"
          },
          {
            name: "Uniscan Web Scanner",
            description: "Remote file include and SQL injection scanner",
            command: `uniscan -u http://${target} -qweds`,
            category: "web"
          },
          {
            name: "Jsky Web Scanner",
            description: "Web application security scanner",
            command: `jsky -u http://${target}`,
            category: "web"
          },
          {
            name: "Katana Web Crawler",
            description: "Next-generation crawling and spidering framework",
            command: `katana -u http://${target} -d 3 -jc -kf robotstxt,sitemapxml`,
            category: "web"
          },
          {
            name: "Crawler4j Java Crawler",
            description: "Java-based web crawler",
            command: `crawler4j -u http://${target}`,
            category: "web"
          },
          {
            name: "Photon Web Crawler",
            description: "Fast web crawler with data extraction",
            command: `photon -u http://${target} -l 3 -t 50`,
            category: "web"
          }
        ]
      },
      {
        name: "Vulnerability Scanning",
        description: "Automated vulnerability detection",
        commands: [
          {
            name: "Nuclei Vulnerability Scan",
            description: "Fast vulnerability scanner using templates",
            command: `nuclei -u http://${target} -t ~/nuclei-templates/`,
            category: "vuln"
          },
          {
            name: "Nuclei Critical Severity",
            description: "Scan for critical vulnerabilities only",
            command: `nuclei -u http://${target} -severity critical`,
            category: "vuln"
          },
          {
            name: "Nuclei High Severity",
            description: "Scan for high severity vulnerabilities",
            command: `nuclei -u http://${target} -severity high,critical`,
            category: "vuln"
          },
          {
            name: "Nuclei CVE Templates",
            description: "Scan using CVE templates",
            command: `nuclei -u http://${target} -t ~/nuclei-templates/cves/`,
            category: "vuln"
          },
          {
            name: "Nmap Vulnerability Scripts",
            description: "NSE vulnerability detection scripts",
            command: `nmap --script vuln ${target}`,
            category: "vuln"
          },
          {
            name: "Nmap HTTP Vulnerabilities",
            description: "HTTP-specific vulnerability scripts",
            command: `nmap --script http-vuln* ${target}`,
            category: "vuln"
          },
          {
            name: "SQLMap SQL Injection Test",
            description: "Automated SQL injection testing",
            command: `sqlmap -u "http://${target}/page?param=value" --batch --dbs`,
            category: "vuln"
          },
          {
            name: "SQLMap Crawl and Test",
            description: "Crawl and test all forms",
            command: `sqlmap -u http://${target} --crawl=3 --batch`,
            category: "vuln"
          },
          {
            name: "NoSQLMap NoSQL Injection",
            description: "NoSQL injection testing tool",
            command: `nosqlmap -t http://${target} --verb GET`,
            category: "vuln"
          },
          {
            name: "Wpscan WordPress Scanner",
            description: "WordPress vulnerability scanner",
            command: `wpscan --url http://${target} --enumerate u,p,t,tt`,
            category: "vuln"
          },
          {
            name: "Wpscan Aggressive Mode",
            description: "Aggressive WordPress scanning",
            command: `wpscan --url http://${target} --enumerate u,p,t,tt --aggressive-mode`,
            category: "vuln"
          },
          {
            name: "Droopescan CMS Scanner",
            description: "Plugin-based scanner for CMS",
            command: `droopescan scan drupal -u http://${target}`,
            category: "vuln"
          },
          {
            name: "Joomscan Joomla Scanner",
            description: "Joomla vulnerability scanner",
            command: `joomscan -u http://${target}`,
            category: "vuln"
          },
          {
            name: "XSStrike XSS Scanner",
            description: "Advanced XSS detection suite",
            command: `xsstrike -u http://${target}`,
            category: "vuln"
          },
          {
            name: "Dalfox XSS Scanner",
            description: "Fast XSS scanner and parameter analysis",
            command: `dalfox url http://${target}`,
            category: "vuln"
          },
          {
            name: "SSRF-Sheriff SSRF Scanner",
            description: "Server-Side Request Forgery scanner",
            command: `ssrf-sheriff -d ${target}`,
            category: "vuln"
          },
          {
            name: "Nessus CLI Scan",
            description: "Professional vulnerability scanner",
            command: `nessuscli scan -T nessus_default_policy ${target}`,
            category: "vuln"
          },
          {
            name: "OpenVAS Scan",
            description: "Open source vulnerability scanner",
            command: `openvas-cli -X '<create_target><name>${target}</name><hosts>${target}</hosts></create_target>'`,
            category: "vuln"
          },
          {
            name: "Gau + Nuclei Pipeline",
            description: "Get URLs and scan with nuclei",
            command: `gau ${target} | nuclei -t ~/nuclei-templates/`,
            category: "vuln"
          },
          {
            name: "Jaeles Vulnerability Scanner",
            description: "Powerful vulnerability scanner",
            command: `jaeles scan -u http://${target}`,
            category: "vuln"
          },
          {
            name: "Commix Command Injection",
            description: "Command injection exploitation tool",
            command: `commix --url="http://${target}/page?param=value"`,
            category: "vuln"
          },
          {
            name: "XXEinjector XXE Testing",
            description: "Tool for automatic exploitation of XXE vulnerability",
            command: `xxeinjector --host=${target} --path=/test --file=/etc/passwd`,
            category: "vuln"
          },
          {
            name: "LFISuite Local File Inclusion",
            description: "Totally Automatic LFI Exploiter and Scanner",
            command: `lfisuite -u http://${target}/page?file=`,
            category: "vuln"
          },
          {
            name: "Tplmap Template Injection",
            description: "Server-Side Template Injection and Code Injection Detection",
            command: `tplmap -u "http://${target}/page?name=test"`,
            category: "vuln"
          },
          {
            name: "Retire.js JavaScript Vulnerabilities",
            description: "Scanner detecting use of vulnerable JavaScript libraries",
            command: `retire --outputformat json --outputpath retire-output.json http://${target}`,
            category: "vuln"
          },
          {
            name: "CSRF Scanner",
            description: "Cross-Site Request Forgery vulnerability scanner",
            command: `csrf-scanner -u http://${target}`,
            category: "vuln"
          },
          {
            name: "CRLF Injection Scanner",
            description: "Carriage Return Line Feed injection testing",
            command: `crlf-scanner -u http://${target}`,
            category: "vuln"
          },
          {
            name: "Host Header Injection",
            description: "Test for host header injection vulnerabilities",
            command: `ffuf -w host-headers.txt -H "Host: FUZZ" -u http://${target}`,
            category: "vuln"
          },
          {
            name: "Open Redirect Scanner",
            description: "Test for open redirect vulnerabilities",
            command: `openredirect -u http://${target}`,
            category: "vuln"
          },
          {
            name: "SSTI Scanner",
            description: "Server-Side Template Injection scanner",
            command: `tplmap -u http://${target}?param=test`,
            category: "vuln"
          },
          {
            name: "Clickjacking Test",
            description: "Test for clickjacking vulnerabilities",
            command: `curl -I http://${target} | grep -i x-frame-options`,
            category: "vuln"
          },
          {
            name: "CORS Misconfiguration",
            description: "Test for CORS misconfiguration",
            command: `cors-scanner -u http://${target}`,
            category: "vuln"
          },
          {
            name: "HTTP Security Headers",
            description: "Analyze HTTP security headers",
            command: `securityheaders ${target}`,
            category: "vuln"
          },
          {
            name: "Race Condition Scanner",
            description: "Test for race condition vulnerabilities",
            command: `race-condition -u http://${target}`,
            category: "vuln"
          },
          {
            name: "Web Cache Poisoning",
            description: "Test for web cache poisoning",
            command: `cache-poison -u http://${target}`,
            category: "vuln"
          },
          {
            name: "Deserialization Scanner",
            description: "Test for insecure deserialization",
            command: `deserialize-scanner -u http://${target}`,
            category: "vuln"
          },
          {
            name: "JWT Security Scanner",
            description: "JSON Web Token security testing",
            command: `jwt-tool -u http://${target}`,
            category: "vuln"
          },
          {
            name: "GraphQL Vulnerability Scanner",
            description: "GraphQL-specific vulnerability testing",
            command: `graphql-cop -t http://${target}/graphql`,
            category: "vuln"
          },
          {
            name: "API Security Scanner",
            description: "REST API security testing",
            command: `apisec-scanner -u http://${target}/api`,
            category: "vuln"
          },
          {
            name: "LDAP Injection Scanner",
            description: "LDAP injection vulnerability testing",
            command: `ldap-scanner -u http://${target}`,
            category: "vuln"
          },
          {
            name: "XPath Injection Scanner",
            description: "XPath injection vulnerability testing",
            command: `xpath-scanner -u http://${target}`,
            category: "vuln"
          },
          {
            name: "File Upload Scanner",
            description: "File upload vulnerability testing",
            command: `upload-scanner -u http://${target}/upload`,
            category: "vuln"
          },
          {
            name: "Business Logic Scanner",
            description: "Business logic flaw detection",
            command: `business-logic -u http://${target}`,
            category: "vuln"
          },
          {
            name: "Memory Corruption Scanner",
            description: "Buffer overflow and memory corruption testing",
            command: `memory-scanner -t ${target}`,
            category: "vuln"
          }
        ]
      },
      {
        name: "SSL/TLS Testing",
        description: "SSL certificate and security testing",
        commands: [
          {
            name: "SSLScan Certificate Analysis",
            description: "SSL/TLS configuration scanner",
            command: `sslscan ${target}`,
            category: "ssl"
          },
          {
            name: "testssl.sh Comprehensive Test",
            description: "Comprehensive SSL/TLS tester",
            command: `testssl.sh ${target}`,
            category: "ssl"
          },
          {
            name: "testssl.sh Vulnerabilities Only",
            description: "Test only for SSL/TLS vulnerabilities",
            command: `testssl.sh --vulnerable ${target}`,
            category: "ssl"
          },
          {
            name: "OpenSSL Certificate Check",
            description: "Check SSL certificate details",
            command: `echo | openssl s_client -connect ${target}:443 -servername ${target} 2>/dev/null | openssl x509 -text`,
            category: "ssl"
          },
          {
            name: "OpenSSL Cipher Test",
            description: "Test supported ciphers",
            command: `nmap --script ssl-enum-ciphers -p 443 ${target}`,
            category: "ssl"
          },
          {
            name: "SSLyze SSL Analyzer",
            description: "Fast and powerful SSL/TLS scanning library",
            command: `sslyze ${target}`,
            category: "ssl"
          },
          {
            name: "SSL Labs API Test",
            description: "Test using SSL Labs API",
            command: `curl "https://api.ssllabs.com/api/v3/analyze?host=${target}"`,
            category: "ssl"
          },
          {
            name: "Certificate Transparency Check",
            description: "Check certificate transparency logs",
            command: `curl "https://crt.sh/?q=${target}&output=json"`,
            category: "ssl"
          }
        ]
      },
      {
        name: "Advanced Enumeration",
        description: "Service-specific enumeration",
        commands: [
          {
            name: "SMB Enumeration",
            description: "SMB shares and service enumeration",
            command: `enum4linux -a ${target}`,
            category: "enum"
          },
          {
            name: "SMBMap Share Enumeration",
            description: "SMB share drive enumeration",
            command: `smbmap -H ${target}`,
            category: "enum"
          },
          {
            name: "SMBClient Connection Test",
            description: "Test SMB connection",
            command: `smbclient -L ${target}`,
            category: "enum"
          },
          {
            name: "SNMP Enumeration",
            description: "SNMP service enumeration",
            command: `snmpwalk -c public -v1 ${target}`,
            category: "enum"
          },
          {
            name: "SNMP Brute Force",
            description: "Brute force SNMP community strings",
            command: `onesixtyone -c /usr/share/wordlists/metasploit/snmp_default_pass.txt ${target}`,
            category: "enum"
          },
          {
            name: "FTP Anonymous Check",
            description: "Check for anonymous FTP access",
            command: `nmap --script ftp-anon ${target}`,
            category: "enum"
          },
          {
            name: "FTP Bounce Attack",
            description: "Test for FTP bounce attack",
            command: `nmap --script ftp-bounce ${target}`,
            category: "enum"
          },
          {
            name: "SSH Service Enumeration",
            description: "SSH service information gathering",
            command: `nmap --script ssh-hostkey,ssh-auth-methods ${target}`,
            category: "enum"
          },
          {
            name: "SSH User Enumeration",
            description: "Enumerate SSH users",
            command: `nmap --script ssh-brute ${target}`,
            category: "enum"
          },
          {
            name: "HTTP Methods Enumeration",
            description: "Enumerate HTTP methods",
            command: `nmap --script http-methods ${target}`,
            category: "enum"
          },
          {
            name: "RPC Enumeration",
            description: "RPC service enumeration",
            command: `rpcinfo -p ${target}`,
            category: "enum"
          },
          {
            name: "NFS Enumeration",
            description: "NFS share enumeration",
            command: `showmount -e ${target}`,
            category: "enum"
          },
          {
            name: "LDAP Enumeration",
            description: "LDAP service enumeration",
            command: `ldapsearch -x -h ${target} -s base`,
            category: "enum"
          },
          {
            name: "Active Directory Enumeration",
            description: "Windows AD enumeration",
            command: `enum4linux-ng ${target}`,
            category: "enum"
          },
          {
            name: "Kerberos Enumeration",
            description: "Kerberos service enumeration",
            command: `nmap -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm=domain ${target}`,
            category: "enum"
          },
          {
            name: "Telnet Enumeration",
            description: "Telnet service enumeration",
            command: `nmap -p 23 --script telnet-ntlm-info ${target}`,
            category: "enum"
          },
          {
            name: "VNC Enumeration",
            description: "VNC service enumeration",
            command: `nmap -p 5900 --script vnc-info ${target}`,
            category: "enum"
          },
          {
            name: "RDP Enumeration",
            description: "Remote Desktop Protocol enumeration",
            command: `nmap -p 3389 --script rdp-enum-encryption,rdp-vuln-ms12-020 ${target}`,
            category: "enum"
          },
          {
            name: "SMTP Enumeration",
            description: "SMTP service enumeration",
            command: `smtp-user-enum -M VRFY -U users.txt -t ${target}`,
            category: "enum"
          },
          {
            name: "POP3 Enumeration",
            description: "POP3 service enumeration",
            command: `nmap -p 110 --script pop3-capabilities ${target}`,
            category: "enum"
          },
          {
            name: "IMAP Enumeration",
            description: "IMAP service enumeration",
            command: `nmap -p 143 --script imap-capabilities ${target}`,
            category: "enum"
          },
          {
            name: "DNS Server Enumeration",
            description: "DNS server enumeration",
            command: `nmap -p 53 --script dns-service-discovery ${target}`,
            category: "enum"
          },
          {
            name: "DHCP Enumeration",
            description: "DHCP service enumeration",
            command: `nmap -p 67,68 --script dhcp-discover ${target}`,
            category: "enum"
          },
          {
            name: "Finger Service Enumeration",
            description: "Finger protocol enumeration",
            command: `finger @${target}`,
            category: "enum"
          },
          {
            name: "TFTP Enumeration",
            description: "Trivial File Transfer Protocol enumeration",
            command: `nmap -p 69 --script tftp-enum ${target}`,
            category: "enum"
          },
          {
            name: "X11 Enumeration",
            description: "X Window System enumeration",
            command: `nmap -p 6000-6063 --script x11-access ${target}`,
            category: "enum"
          },
          {
            name: "Oracle Listener Enumeration",
            description: "Oracle database listener enumeration",
            command: `tnscmd10g version -h ${target}`,
            category: "enum"
          },
          {
            name: "MSSQL Instance Enumeration",
            description: "Microsoft SQL Server instance discovery",
            command: `sqsh -S ${target} -U sa -P`,
            category: "enum"
          },
          {
            name: "Cassandra Enumeration",
            description: "Apache Cassandra database enumeration",
            command: `nmap -p 9042 --script cassandra-info ${target}`,
            category: "enum"
          },
          {
            name: "Elasticsearch Enumeration",
            description: "Elasticsearch cluster enumeration",
            command: `curl http://${target}:9200/_cluster/health`,
            category: "enum"
          },
          {
            name: "InfluxDB Enumeration",
            description: "InfluxDB time-series database enumeration",
            command: `curl http://${target}:8086/query?q=SHOW+DATABASES`,
            category: "enum"
          }
        ]
      },
      {
        name: "Exploitation & Payloads",
        description: "Advanced exploitation and payload generation",
        commands: [
          {
            name: "Metasploit Search",
            description: "Search for exploits in Metasploit",
            command: `msfconsole -q -x "search ${target}; exit"`,
            category: "exploit"
          },
          {
            name: "Searchsploit Exploit Database",
            description: "Search exploit database",
            command: `searchsploit ${target}`,
            category: "exploit"
          },
          {
            name: "MSFvenom Payload Generator",
            description: "Generate payloads with msfvenom",
            command: `msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=${target} LPORT=4444 -f elf > payload.elf`,
            category: "exploit"
          },
          {
            name: "Empire PowerShell Post-Exploitation",
            description: "PowerShell post-exploitation agent",
            command: `empire --rest --user empireadmin --pass password123`,
            category: "exploit"
          },
          {
            name: "Covenant C2 Framework",
            description: ".NET command and control framework",
            command: `covenant --username admin --computername ${target}`,
            category: "exploit"
          },
          {
            name: "Sliver C2 Framework",
            description: "Open source cross-platform adversary emulation/red team framework",
            command: `sliver-server`,
            category: "exploit"
          },
          {
            name: "Cobalt Strike Beacon",
            description: "Generate Cobalt Strike beacon",
            command: `cs-beacon-generate --payload windows/beacon_https --lhost ${target} --lport 443`,
            category: "exploit"
          },
          {
            name: "Social Engineer Toolkit",
            description: "Open-source penetration testing framework",
            command: `setoolkit`,
            category: "exploit"
          },
          {
            name: "BeEF Browser Exploitation",
            description: "Browser Exploitation Framework",
            command: `beef-xss`,
            category: "exploit"
          },
          {
            name: "Exploit-DB Search",
            description: "Search Exploit Database online",
            command: `curl -s "https://www.exploit-db.com/search?q=${target}"`,
            category: "exploit"
          },
          {
            name: "Armitage Team Server",
            description: "Graphical cyber attack management tool",
            command: `armitage`,
            category: "exploit"
          },
          {
            name: "Canvas Exploitation Framework",
            description: "Comprehensive exploitation framework",
            command: `canvas`,
            category: "exploit"
          },
          {
            name: "Core Impact Testing",
            description: "Commercial penetration testing tool",
            command: `core-impact`,
            category: "exploit"
          },
          {
            name: "Immunity Debugger",
            description: "Exploit development and debugging",
            command: `immunity-debugger`,
            category: "exploit"
          },
          {
            name: "GDB Enhanced",
            description: "Enhanced GNU debugger for exploit development",
            command: `gdb-peda`,
            category: "exploit"
          },
          {
            name: "ROPgadget Tool",
            description: "Return-oriented programming gadget finder",
            command: `ropgadget --binary binary_file`,
            category: "exploit"
          },
          {
            name: "Ropper ROP Tool",
            description: "Display ROP/JOP gadgets for binaries",
            command: `ropper --file binary_file`,
            category: "exploit"
          },
          {
            name: "Pwntools Framework",
            description: "CTF and exploit development framework",
            command: `python3 exploit.py`,
            category: "exploit"
          },
          {
            name: "Exploit Pack",
            description: "Penetration testing framework",
            command: `exploit-pack`,
            category: "exploit"
          },
          {
            name: "Veil Evasion Framework",
            description: "Generate payloads that bypass AV",
            command: `veil-evasion`,
            category: "exploit"
          },
          {
            name: "TheFatRat Backdoor Generator",
            description: "Generate backdoors and payloads",
            command: `fatrat`,
            category: "exploit"
          },
          {
            name: "Shellter AV Evasion",
            description: "Dynamic shellcode injection tool",
            command: `shellter`,
            category: "exploit"
          }
        ]
      },
      {
        name: "Content Discovery",
        description: "Hidden content and file discovery",
        commands: [
          {
            name: "Robots.txt Check",
            description: "Check robots.txt file",
            command: `curl http://${target}/robots.txt`,
            category: "content"
          },
          {
            name: "Sitemap.xml Check",
            description: "Check sitemap.xml file",
            command: `curl http://${target}/sitemap.xml`,
            category: "content"
          },
          {
            name: "Common Files Check",
            description: "Check for common files",
            command: `gobuster dir -u http://${target} -w /usr/share/wordlists/dirb/common.txt -x php,txt,html,js,css`,
            category: "content"
          },
          {
            name: "Backup Files Discovery",
            description: "Search for backup files",
            command: `gobuster dir -u http://${target} -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x bak,backup,old,tmp`,
            category: "content"
          },
          {
            name: "Configuration Files",
            description: "Search for configuration files",
            command: `gobuster dir -u http://${target} -w /usr/share/wordlists/dirb/common.txt -x conf,config,ini,yaml,yml`,
            category: "content"
          },
          {
            name: "Source Code Discovery",
            description: "Look for exposed source code",
            command: `gobuster dir -u http://${target} -w /usr/share/wordlists/dirb/common.txt -x zip,tar,gz,rar`,
            category: "content"
          },
          {
            name: "Admin Panel Discovery",
            description: "Search for admin panels",
            command: `gobuster dir -u http://${target} -w /usr/share/wordlists/dirb/common.txt -s '200,204,301,302,307,403'`,
            category: "content"
          },
          {
            name: "DotDotPwn Directory Traversal",
            description: "Directory traversal fuzzer",
            command: `dotdotpwn -m http -h ${target} -x 8080 -f /etc/passwd -k "root" -d 3`,
            category: "content"
          },
          {
            name: "Dirble Directory Scanner",
            description: "Fast directory scanning and scraping tool",
            command: `dirble http://${target}`,
            category: "content"
          },
          {
            name: "Recursebuster Recursive Fuzzing",
            description: "Rapid content discovery tool",
            command: `recursebuster -u http://${target}`,
            category: "content"
          },
          {
            name: "Breacher Admin Panel Finder",
            description: "Advanced admin panel finder",
            command: `breacher -u http://${target}`,
            category: "content"
          },
          {
            name: "Git Disclosure Scanner",
            description: "Search for exposed .git directories",
            command: `gitdorker -tf GITHUB_TOKENS -q ${target} -d dorks/`,
            category: "content"
          },
          {
            name: "SVN Disclosure Scanner",
            description: "Search for exposed .svn directories",
            command: `svn-extractor http://${target}/.svn/`,
            category: "content"
          },
          {
            name: "DS_Store File Scanner",
            description: "Search for exposed .DS_Store files",
            command: `curl http://${target}/.DS_Store`,
            category: "content"
          },
          {
            name: "Vim Swap File Scanner",
            description: "Search for vim swap files",
            command: `gobuster dir -u http://${target} -w /usr/share/wordlists/dirb/common.txt -x swp,swo,tmp,vim`,
            category: "content"
          },
          {
            name: "Log File Discovery",
            description: "Search for log files",
            command: `gobuster dir -u http://${target} -w /usr/share/wordlists/dirb/common.txt -x log,logs,txt`,
            category: "content"
          },
          {
            name: "Database File Discovery",
            description: "Search for database files",
            command: `gobuster dir -u http://${target} -w /usr/share/wordlists/dirb/common.txt -x sql,db,sqlite,mdb`,
            category: "content"
          },
          {
            name: "Credential File Discovery",
            description: "Search for credential files",
            command: `gobuster dir -u http://${target} -w /usr/share/wordlists/dirb/common.txt -x htpasswd,passwd,shadow`,
            category: "content"
          },
          {
            name: "Docker File Discovery",
            description: "Search for Docker-related files",
            command: `gobuster dir -u http://${target} -w /usr/share/wordlists/dirb/common.txt -x dockerfile,docker-compose.yml`,
            category: "content"
          },
          {
            name: "IDE Config Discovery",
            description: "Search for IDE configuration files",
            command: `gobuster dir -u http://${target} -w /usr/share/wordlists/dirb/common.txt -x idea,vscode,sublime`,
            category: "content"
          },
          {
            name: "Environment File Discovery",
            description: "Search for environment files",
            command: `gobuster dir -u http://${target} -w /usr/share/wordlists/dirb/common.txt -x env,environment`,
            category: "content"
          },
          {
            name: "API Documentation Discovery",
            description: "Search for API documentation files",
            command: `gobuster dir -u http://${target} -w /usr/share/wordlists/api-docs.txt`,
            category: "content"
          },
          {
            name: "WordPress Content Discovery",
            description: "WordPress-specific file discovery",
            command: `wpscan --url http://${target} --enumerate ap,at,cb,dbe`,
            category: "content"
          },
          {
            name: "PHP Info Discovery",
            description: "Search for PHP info pages",
            command: `gobuster dir -u http://${target} -w /usr/share/wordlists/dirb/common.txt -x php | grep phpinfo`,
            category: "content"
          },
          {
            name: "Test File Discovery",
            description: "Search for test and debug files",
            command: `gobuster dir -u http://${target} -w /usr/share/wordlists/dirb/common.txt -x test,debug,dev`,
            category: "content"
          }
        ]
      },
      {
        name: "API Testing",
        description: "REST API and GraphQL testing",
        commands: [
          {
            name: "API Endpoint Discovery",
            description: "Discover API endpoints",
            command: `gobuster dir -u http://${target} -w /usr/share/wordlists/api/api-endpoints.txt`,
            category: "api"
          },
          {
            name: "GraphQL Introspection",
            description: "GraphQL schema introspection",
            command: `curl -X POST http://${target}/graphql -H "Content-Type: application/json" -d '{"query":"{__schema{types{name}}}"}'`,
            category: "api"
          },
          {
            name: "REST API Fuzzing",
            description: "Fuzz REST API endpoints",
            command: `ffuf -u http://${target}/api/FUZZ -w /usr/share/wordlists/api/api-endpoints.txt`,
            category: "api"
          },
          {
            name: "Swagger/OpenAPI Discovery",
            description: "Look for API documentation",
            command: `curl http://${target}/swagger.json`,
            category: "api"
          },
          {
            name: "API Version Discovery",
            description: "Discover API versions",
            command: `ffuf -u http://${target}/api/FUZZ -w /usr/share/wordlists/api/api-versions.txt`,
            category: "api"
          },
          {
            name: "REST API Testing Suite",
            description: "Comprehensive REST API security testing",
            command: `restler-fuzzer --restler_grammar grammar.json --target_ip ${target}`,
            category: "api"
          },
          {
            name: "GraphQL Voyager",
            description: "GraphQL schema visualization and analysis",
            command: `graphql-voyager http://${target}/graphql`,
            category: "api"
          },
          {
            name: "API Fuzzing with RESTler",
            description: "Intelligent REST API fuzzing",
            command: `restler test --grammar_file grammar.json --target_ip ${target}`,
            category: "api"
          },
          {
            name: "Postman Newman Testing",
            description: "API testing with Postman collections",
            command: `newman run collection.json --environment env.json`,
            category: "api"
          },
          {
            name: "Insomnia API Testing",
            description: "API client for testing REST APIs",
            command: `insomnia-core test collection.json`,
            category: "api"
          },
          {
            name: "API Rate Limiting Test",
            description: "Test API rate limiting mechanisms",
            command: `rate-limit-test -u http://${target}/api -r 1000`,
            category: "api"
          },
          {
            name: "API Authorization Bypass",
            description: "Test for API authorization bypass",
            command: `auth-bypass -u http://${target}/api`,
            category: "api"
          },
          {
            name: "API Parameter Pollution",
            description: "Test for HTTP parameter pollution",
            command: `param-pollution -u http://${target}/api`,
            category: "api"
          },
          {
            name: "SOAP API Testing",
            description: "SOAP web service security testing",
            command: `soap-scanner -w http://${target}/service.wsdl`,
            category: "api"
          },
          {
            name: "gRPC Security Testing",
            description: "gRPC service security assessment",
            command: `grpcurl -plaintext ${target}:50051 list`,
            category: "api"
          },
          {
            name: "WebSocket Security Test",
            description: "WebSocket connection security testing",
            command: `websocket-hammer ws://${target}/ws`,
            category: "api"
          }
        ]
      },
      {
        name: "Cloud Security",
        description: "Cloud service enumeration and testing",
        commands: type === 'domain' ? [
          {
            name: "AWS S3 Bucket Discovery",
            description: "Look for S3 buckets related to domain",
            command: `aws s3 ls s3://${target} --no-sign-request`,
            category: "cloud"
          },
          {
            name: "Google Cloud Storage",
            description: "Check for Google Cloud Storage buckets",
            command: `gsutil ls gs://${target}`,
            category: "cloud"
          },
          {
            name: "Azure Blob Storage",
            description: "Check for Azure storage accounts",
            command: `az storage blob list --container-name ${target}`,
            category: "cloud"
          },
          {
            name: "CloudFlare Bypass",
            description: "Try to find real IP behind CloudFlare",
            command: `dig ${target} +short`,
            category: "cloud"
          },
          {
            name: "CDN Detection",
            description: "Detect CDN usage",
            command: `whatweb http://${target} | grep -i cdn`,
            category: "cloud"
          }
        ] : []
      },
      {
        name: "Database Testing",
        description: "Database service testing and enumeration",
        commands: [
          {
            name: "MySQL Enumeration",
            description: "MySQL service enumeration",
            command: `nmap --script mysql-enum ${target}`,
            category: "database"
          },
          {
            name: "PostgreSQL Enumeration",
            description: "PostgreSQL service enumeration",
            command: `nmap --script pgsql-brute ${target}`,
            category: "database"
          },
          {
            name: "MSSQL Enumeration",
            description: "Microsoft SQL Server enumeration",
            command: `nmap --script ms-sql-info ${target}`,
            category: "database"
          },
          {
            name: "MongoDB Enumeration",
            description: "MongoDB service enumeration",
            command: `nmap --script mongodb-info ${target}`,
            category: "database"
          },
          {
            name: "Redis Enumeration",
            description: "Redis service enumeration",
            command: `nmap --script redis-info ${target}`,
            category: "database"
          },
          {
            name: "Oracle DB Enumeration",
            description: "Oracle database enumeration",
            command: `nmap --script oracle-enum-users ${target}`,
            category: "database"
          }
        ]
      },
      {
        name: "Mobile & IoT",
        description: "Mobile applications and IoT device testing",
        commands: [
          {
            name: "Android APK Analysis",
            description: "Static analysis of Android APK",
            command: `apktool d app.apk`,
            category: "mobile"
          },
          {
            name: "iOS IPA Analysis",
            description: "iOS application analysis",
            command: `otool -L application.ipa`,
            category: "mobile"
          },
          {
            name: "IoT Device Discovery",
            description: "Discover IoT devices on network",
            command: `nmap -sU -p 53,67,68,123,161,162,1900,5353 ${target}`,
            category: "iot"
          },
          {
            name: "UPnP Device Discovery",
            description: "Universal Plug and Play discovery",
            command: `nmap --script upnp-info ${target}`,
            category: "iot"
          },
          {
            name: "MQTT Broker Discovery",
            description: "Find MQTT brokers",
            command: `nmap -p 1883,8883 ${target}`,
            category: "iot"
          },
          {
            name: "CoAP Protocol Discovery",
            description: "Constrained Application Protocol discovery",
            command: `nmap -sU -p 5683 ${target} --script coap-resources`,
            category: "iot"
          },
          {
            name: "Modbus Protocol Scan",
            description: "Industrial protocol scanning",
            command: `nmap -p 502 ${target} --script modbus-discover`,
            category: "iot"
          },
          {
            name: "BLE Scanner",
            description: "Bluetooth Low Energy scanner",
            command: `hcitool lescan`,
            category: "iot"
          },
          {
            name: "RTL-SDR RF Analysis",
            description: "Radio frequency analysis",
            command: `rtl_sdr -s 2048000 -f 433000000 capture.dat`,
            category: "iot"
          },
          {
            name: "Frida Mobile Analysis",
            description: "Dynamic instrumentation toolkit",
            command: `frida -U -l script.js com.example.app`,
            category: "mobile"
          },
          {
            name: "MobSF Mobile Security",
            description: "Mobile Security Framework",
            command: `python manage.py runserver`,
            category: "mobile"
          },
          {
            name: "Objection iOS/Android Testing",
            description: "Runtime mobile exploration",
            command: `objection -g com.example.app explore`,
            category: "mobile"
          },
          {
            name: "JADX APK Decompiler",
            description: "Dex to Java decompiler",
            command: `jadx -d output app.apk`,
            category: "mobile"
          },
          {
            name: "Dex2jar APK Analysis",
            description: "Convert Android dex files to jar",
            command: `dex2jar app.apk`,
            category: "mobile"
          },
          {
            name: "QARK Android Scanner",
            description: "Quick Android Review Kit",
            command: `qark --apk app.apk`,
            category: "mobile"
          },
          {
            name: "MobSec Android Analysis",
            description: "Mobile security testing framework",
            command: `mobsec-android app.apk`,
            category: "mobile"
          },
          {
            name: "iMazing iOS Analysis",
            description: "iOS device management and analysis",
            command: `imazing-cli analyze app.ipa`,
            category: "mobile"
          },
          {
            name: "Clutch iOS Decryption",
            description: "iOS app decryption tool",
            command: `clutch -d com.example.app`,
            category: "mobile"
          },
          {
            name: "Class-dump iOS Analysis",
            description: "Generate class declarations for iOS apps",
            command: `class-dump app`,
            category: "mobile"
          },
          {
            name: "Hopper iOS Disassembler",
            description: "Reverse engineering tool for iOS",
            command: `hopper -l iOS app`,
            category: "mobile"
          },
          {
            name: "Radare2 Mobile Analysis",
            description: "Reverse engineering framework",
            command: `r2 app.apk`,
            category: "mobile"
          },
          {
            name: "Android SDK Tools",
            description: "Android development and analysis tools",
            command: `adb shell dumpsys package com.example.app`,
            category: "mobile"
          },
          {
            name: "Drozer Android Testing",
            description: "Security testing framework for Android",
            command: `drozer console connect`,
            category: "mobile"
          },
          {
            name: "AndroBugs Scanner",
            description: "Android vulnerability scanner",
            command: `androbugs -f app.apk`,
            category: "mobile"
          },
          {
            name: "MARA Mobile Analysis",
            description: "Mobile Application Reverse engineering and Analysis",
            command: `mara-tool app.apk`,
            category: "mobile"
          },
          {
            name: "ZigBee Scanner",
            description: "ZigBee IoT protocol scanner",
            command: `zbstumbler -c 11`,
            category: "iot"
          },
          {
            name: "LoRaWAN Scanner",
            description: "LoRaWAN IoT protocol analysis",
            command: `lorawan-scanner -f 868000000`,
            category: "iot"
          },
          {
            name: "Thread Protocol Scanner",
            description: "Thread mesh networking protocol scanner",
            command: `thread-scanner`,
            category: "iot"
          },
          {
            name: "Matter Protocol Scanner",
            description: "Matter/Thread IoT protocol scanner",
            command: `matter-scanner`,
            category: "iot"
          },
          {
            name: "Bluetooth Classic Scanner",
            description: "Bluetooth Classic device enumeration",
            command: `btscanner`,
            category: "iot"
          },
          {
            name: "NFC Scanner",
            description: "Near Field Communication scanner",
            command: `nfclist`,
            category: "iot"
          },
          {
            name: "RFID Scanner",
            description: "Radio Frequency Identification scanner",
            command: `rfidiot-scan`,
            category: "iot"
          }
        ]
      },
      {
        name: "Information Gathering",
        description: "OSINT and passive reconnaissance",
        commands: type === 'domain' ? [
          {
            name: "Whois Domain Information",
            description: "Domain registration information",
            command: `whois ${target}`,
            category: "osint"
          },
          {
            name: "TheHarvester Email Discovery",
            description: "Email addresses and subdomain discovery",
            command: `theharvester -d ${target} -l 500 -b google`,
            category: "osint"
          },
          {
            name: "Shodan Search",
            description: "Search Shodan for target information",
            command: `shodan host ${target}`,
            category: "osint"
          },
          {
            name: "Certificate Search",
            description: "Search certificate transparency logs",
            command: `curl "https://crt.sh/?q=%.${target}&output=json"`,
            category: "osint"
          },
          {
            name: "GitHub Dorking",
            description: "Search GitHub for sensitive information",
            command: `github-search -d ${target}`,
            category: "osint"
          },
          {
            name: "Social Media Search",
            description: "Social media reconnaissance",
            command: `sherlock ${target}`,
            category: "osint"
          },
          {
            name: "DNS History",
            description: "Check DNS history",
            command: `curl "https://api.securitytrails.com/v1/history/${target}/dns"`,
            category: "osint"
          },
          {
            name: "Recon-ng Framework",
            description: "Full-featured reconnaissance framework",
            command: `recon-ng -r recon.resource`,
            category: "osint"
          },
          {
            name: "SpiderFoot OSINT Automation",
            description: "Automated OSINT collection",
            command: `spiderfoot -l 127.0.0.1:5001`,
            category: "osint"
          },
          {
            name: "Maltego Data Mining",
            description: "Interactive data mining tool",
            command: `maltego`,
            category: "osint"
          },
          {
            name: "IntelX Search",
            description: "Search engine and data archive",
            command: `intelx -search ${target}`,
            category: "osint"
          },
          {
            name: "TweetDeck OSINT",
            description: "Twitter intelligence gathering",
            command: `twint -s "${target}" -o tweets.txt`,
            category: "osint"
          },
          {
            name: "EmailHarvester Email Discovery",
            description: "Email harvesting tool",
            command: `emailharvester -d ${target}`,
            category: "osint"
          },
          {
            name: "Google Dorking",
            description: "Google search engine reconnaissance",
            command: `googler "site:${target} filetype:pdf"`,
            category: "osint"
          },
          {
            name: "Bing Dorking",
            description: "Bing search engine reconnaissance",
            command: `bing-search "site:${target} filetype:doc"`,
            category: "osint"
          },
          {
            name: "DuckDuckGo OSINT",
            description: "DuckDuckGo search reconnaissance",
            command: `ddg-search "site:${target}"`,
            category: "osint"
          },
          {
            name: "Archive.org Wayback",
            description: "Internet Archive historical data",
            command: `wayback-machine ${target}`,
            category: "osint"
          },
          {
            name: "LinkedIn OSINT",
            description: "LinkedIn reconnaissance",
            command: `linkedin-enum ${target}`,
            category: "osint"
          },
          {
            name: "Facebook OSINT",
            description: "Facebook page reconnaissance",
            command: `facebook-enum ${target}`,
            category: "osint"
          },
          {
            name: "Instagram OSINT",
            description: "Instagram profile reconnaissance",
            command: `instagram-enum ${target}`,
            category: "osint"
          },
          {
            name: "Twitter OSINT",
            description: "Twitter account reconnaissance",
            command: `twitter-enum ${target}`,
            category: "osint"
          },
          {
            name: "Pipl People Search",
            description: "People search engine reconnaissance",
            command: `pipl-search ${target}`,
            category: "osint"
          },
          {
            name: "Have I Been Pwned",
            description: "Check for breached accounts",
            command: `hibp-check ${target}`,
            category: "osint"
          },
          {
            name: "DeHashed Credential Search",
            description: "Search for leaked credentials",
            command: `dehashed-search ${target}`,
            category: "osint"
          },
          {
            name: "Breach Directory Search",
            description: "Search data breach directories",
            command: `breach-search ${target}`,
            category: "osint"
          },
          {
            name: "Pastebin OSINT",
            description: "Search Pastebin for sensitive data",
            command: `pastebin-search ${target}`,
            category: "osint"
          },
          {
            name: "GitHub Code Search",
            description: "Search GitHub for code and secrets",
            command: `github-code-search ${target}`,
            category: "osint"
          },
          {
            name: "GitLab OSINT",
            description: "GitLab repository reconnaissance",
            command: `gitlab-search ${target}`,
            category: "osint"
          },
          {
            name: "Bitbucket OSINT",
            description: "Bitbucket repository reconnaissance",
            command: `bitbucket-search ${target}`,
            category: "osint"
          },
          {
            name: "Docker Hub Search",
            description: "Docker Hub repository search",
            command: `docker search ${target}`,
            category: "osint"
          },
          {
            name: "NPM Package Search",
            description: "NPM registry reconnaissance",
            command: `npm search ${target}`,
            category: "osint"
          },
          {
            name: "PyPI Package Search",
            description: "Python Package Index search",
            command: `pip search ${target}`,
            category: "osint"
          }
        ] : [
          {
            name: "Shodan IP Search",
            description: "Search Shodan for IP information",
            command: `shodan host ${target}`,
            category: "osint"
          },
          {
            name: "IP Geolocation",
            description: "Get IP geolocation information",
            command: `curl "http://ip-api.com/json/${target}"`,
            category: "osint"
          },
          {
            name: "IP Reputation Check",
            description: "Check IP reputation",
            command: `curl "https://api.abuseipdb.com/api/v2/check?ipAddress=${target}"`,
            category: "osint"
          }
        ]
      },
      {
        name: "Wireless Testing",
        description: "WiFi and wireless network testing",
        commands: [
          {
            name: "WiFi Network Discovery",
            description: "Discover WiFi networks",
            command: `iwlist scan | grep ESSID`,
            category: "wireless"
          },
          {
            name: "Bluetooth Device Discovery",
            description: "Discover Bluetooth devices",
            command: `hcitool scan`,
            category: "wireless"
          },
          {
            name: "Aircrack-ng WEP Crack",
            description: "Crack WEP encryption",
            command: `aircrack-ng -b ${target} capture.cap`,
            category: "wireless"
          },
          {
            name: "Reaver WPS Attack",
            description: "WPS PIN brute force attack",
            command: `reaver -i wlan0 -b ${target} -vv`,
            category: "wireless"
          },
          {
            name: "Airmon-ng Monitor Mode",
            description: "Enable monitor mode for wireless testing",
            command: `airmon-ng start wlan0`,
            category: "wireless"
          },
          {
            name: "Airodump-ng Packet Capture",
            description: "Capture wireless packets",
            command: `airodump-ng wlan0mon`,
            category: "wireless"
          },
          {
            name: "Aireplay-ng Deauth Attack",
            description: "Deauthentication attack",
            command: `aireplay-ng -0 5 -a ${target} wlan0mon`,
            category: "wireless"
          },
          {
            name: "Hashcat WiFi Cracking",
            description: "GPU-accelerated password cracking",
            command: `hashcat -m 2500 capture.hccapx wordlist.txt`,
            category: "wireless"
          },
          {
            name: "John WiFi Cracking",
            description: "John the Ripper WiFi password cracking",
            command: `john --wordlist=wordlist.txt wifi.hash`,
            category: "wireless"
          },
          {
            name: "Cowpatty WPA Cracking",
            description: "WPA pre-shared key cracking",
            command: `cowpatty -r capture.cap -f wordlist.txt -s ESSID`,
            category: "wireless"
          },
          {
            name: "Pyrit WPA Cracking",
            description: "GPU-accelerated WPA cracking",
            command: `pyrit -r capture.cap -i wordlist.txt attack_passthrough`,
            category: "wireless"
          },
          {
            name: "Wifite Automated Cracking",
            description: "Automated wireless auditing tool",
            command: `wifite`,
            category: "wireless"
          },
          {
            name: "Bully WPS Cracking",
            description: "WPS brute force tool",
            command: `bully -b ${target} wlan0mon`,
            category: "wireless"
          },
          {
            name: "Wash WPS Scanner",
            description: "WPS-enabled access point scanner",
            command: `wash -i wlan0mon`,
            category: "wireless"
          },
          {
            name: "Kismet Wireless Detector",
            description: "Wireless network detector",
            command: `kismet`,
            category: "wireless"
          },
          {
            name: "Wireshark Packet Analysis",
            description: "Network protocol analyzer",
            command: `wireshark`,
            category: "wireless"
          },
          {
            name: "WiFi Pineapple Framework",
            description: "Rogue access point framework",
            command: `pineapple-framework`,
            category: "wireless"
          }
        ]
      },
      {
        name: "Post-Exploitation",
        description: "Post-exploitation and persistence",
        commands: [
          {
            name: "Network Mapping",
            description: "Map internal network",
            command: `nmap -sn 192.168.1.0/24`,
            category: "postexploit"
          },
          {
            name: "ARP Scan",
            description: "ARP scan for live hosts",
            command: `arp-scan -l`,
            category: "postexploit"
          },
          {
            name: "Process Enumeration",
            description: "Enumerate running processes",
            command: `ps aux`,
            category: "postexploit"
          },
          {
            name: "Service Enumeration",
            description: "Enumerate running services",
            command: `systemctl list-unit-files --type=service`,
            category: "postexploit"
          },
          {
            name: "User Enumeration",
            description: "Enumerate system users",
            command: `cat /etc/passwd`,
            category: "postexploit"
          },
          {
            name: "Privilege Escalation Check",
            description: "Check for privilege escalation vectors",
            command: `find / -perm -u=s -type f 2>/dev/null`,
            category: "postexploit"
          },
          {
            name: "LinEnum Linux Enumeration",
            description: "Linux enumeration script",
            command: `./LinEnum.sh`,
            category: "postexploit"
          },
          {
            name: "LinPEAS Privilege Escalation",
            description: "Linux privilege escalation awesome script",
            command: `./linpeas.sh`,
            category: "postexploit"
          },
          {
            name: "WinPEAS Windows Enumeration",
            description: "Windows privilege escalation script",
            command: `winpeas.exe`,
            category: "postexploit"
          },
          {
            name: "PowerUp Windows PrivEsc",
            description: "PowerShell privilege escalation framework",
            command: `powershell -ep bypass -c ". .\\PowerUp.ps1; Invoke-AllChecks"`,
            category: "postexploit"
          },
          {
            name: "Sherlock Windows PrivEsc",
            description: "PowerShell script for privilege escalation",
            command: `powershell -ep bypass -c ". .\\Sherlock.ps1; Find-AllVulns"`,
            category: "postexploit"
          },
          {
            name: "Watson Windows PrivEsc",
            description: ".NET privilege escalation enumeration",
            command: `watson.exe`,
            category: "postexploit"
          },
          {
            name: "Unix PrivEsc Check",
            description: "Unix privilege escalation checker",
            command: `./unix-privesc-check standard`,
            category: "postexploit"
          },
          {
            name: "LSE Linux Enumeration",
            description: "Linux smart enumeration script",
            command: `./lse.sh -l 2`,
            category: "postexploit"
          },
          {
            name: "PEASS-ng Suite",
            description: "Privilege escalation awesome scripts suite",
            command: `./peass-ng.sh`,
            category: "postexploit"
          },
          {
            name: "GTFOBins Lookup",
            description: "Living off the land binaries lookup",
            command: `gtfobins search`,
            category: "postexploit"
          },
          {
            name: "LOLBAS Windows Binaries",
            description: "Living Off The Land Binaries And Scripts",
            command: `lolbas-search`,
            category: "postexploit"
          },
          {
            name: "Persistence Establishment",
            description: "Establish persistent access",
            command: `persistence-toolkit`,
            category: "postexploit"
          },
          {
            name: "Lateral Movement Scanner",
            description: "Scan for lateral movement opportunities",
            command: `lateral-movement-scan`,
            category: "postexploit"
          },
          {
            name: "Credential Dumping",
            description: "Extract credentials from memory",
            command: `mimikatz.exe`,
            category: "postexploit"
          }
        ]
      },
      {
        name: "Evasion & Steganography",
        description: "Anti-detection and data hiding techniques",
        commands: [
          {
            name: "Proxychains Traffic Routing",
            description: "Route traffic through proxy chains",
            command: `proxychains nmap -sT ${target}`,
            category: "evasion"
          },
          {
            name: "Tor Network Routing",
            description: "Route traffic through Tor network",
            command: `torify curl http://${target}`,
            category: "evasion"
          },
          {
            name: "MAC Address Spoofing",
            description: "Change MAC address for anonymity",
            command: `macchanger -r eth0`,
            category: "evasion"
          },
          {
            name: "Steghide Image Steganography",
            description: "Hide data in image files",
            command: `steghide embed -cf image.jpg -ef secret.txt`,
            category: "steganography"
          },
          {
            name: "Outguess Steganography",
            description: "Statistical steganography tool",
            command: `outguess -k "password" -d hidden.txt image.jpg`,
            category: "steganography"
          },
          {
            name: "DNS Tunneling",
            description: "Exfiltrate data via DNS queries",
            command: `iodine -f -c -P password 192.168.1.1 tunnel.${target}`,
            category: "evasion"
          },
          {
            name: "HTTP Tunneling",
            description: "HTTP tunnel for traffic evasion",
            command: `httptunnel -s 8888 -d ${target}:22`,
            category: "evasion"
          },
          {
            name: "Domain Fronting",
            description: "Hide destination using CDN",
            command: `curl -H "Host: ${target}" https://cloudfront.amazonaws.com`,
            category: "evasion"
          },
          {
            name: "VPN Tunnel Setup",
            description: "Establish VPN tunnel for anonymity",
            command: `openvpn config.ovpn`,
            category: "evasion"
          },
          {
            name: "SSH Tunnel Creation",
            description: "Create SSH tunnel for port forwarding",
            command: `ssh -L 8080:${target}:80 user@proxy`,
            category: "evasion"
          },
          {
            name: "SOCKS Proxy Setup",
            description: "SOCKS proxy for traffic routing",
            command: `ssh -D 8080 user@proxy`,
            category: "evasion"
          },
          {
            name: "Ptunnel ICMP Tunnel",
            description: "ICMP tunnel for firewall bypass",
            command: `ptunnel -p ${target}`,
            category: "evasion"
          },
          {
            name: "Udptunnel UDP Encapsulation",
            description: "UDP tunnel for traffic encapsulation",
            command: `udptunnel -s 8080 ${target} 80`,
            category: "evasion"
          },
          {
            name: "Stunnel SSL Wrapper",
            description: "SSL/TLS wrapper for network traffic",
            command: `stunnel stunnel.conf`,
            category: "evasion"
          },
          {
            name: "Socat Network Relay",
            description: "Multipurpose network relay tool",
            command: `socat TCP-LISTEN:8080,fork TCP:${target}:80`,
            category: "evasion"
          },
          {
            name: "Netsh Port Forwarding",
            description: "Windows netsh port forwarding",
            command: `netsh interface portproxy add v4tov4 listenport=8080 connectaddress=${target} connectport=80`,
            category: "evasion"
          },
          {
            name: "Chisel Tunnel",
            description: "Fast TCP/UDP tunnel over HTTP",
            command: `chisel server -p 8080 --reverse`,
            category: "evasion"
          },
          {
            name: "Stegosaurus Image Steganography",
            description: "Advanced steganography tool",
            command: `stegosaurus hide -f file.txt -i image.png -o output.png`,
            category: "steganography"
          },
          {
            name: "OpenStego Steganography",
            description: "Open source steganography application",
            command: `openstego embed -mf message.txt -cf cover.png -sf stego.png`,
            category: "steganography"
          },
          {
            name: "StegSolve Image Analysis",
            description: "Steganography solver tool",
            command: `stegsolve image.png`,
            category: "steganography"
          },
          {
            name: "Binwalk Firmware Analysis",
            description: "Firmware analysis and extraction tool",
            command: `binwalk -e firmware.bin`,
            category: "steganography"
          },
          {
            name: "Foremost File Recovery",
            description: "File recovery based on file headers",
            command: `foremost -i image.dd`,
            category: "steganography"
          },
          {
            name: "Exiftool Metadata Analysis",
            description: "Read and write meta information",
            command: `exiftool image.jpg`,
            category: "steganography"
          },
          {
            name: "Strings File Analysis",
            description: "Extract printable strings from files",
            command: `strings -a file.bin`,
            category: "steganography"
          },
          {
            name: "Hexdump Binary Analysis",
            description: "Hexadecimal dump of binary files",
            command: `hexdump -C file.bin`,
            category: "steganography"
          }
        ]
      },
      {
        name: "Reporting & Documentation",
        description: "Generate reports and documentation",
        commands: [
          {
            name: "Nmap XML Output",
            description: "Generate XML report with nmap",
            command: `nmap -sC -sV -oX scan_results.xml ${target}`,
            category: "reporting"
          },
          {
            name: "Nuclei JSON Output",
            description: "Generate JSON report with nuclei",
            command: `nuclei -u http://${target} -json -o nuclei_results.json`,
            category: "reporting"
          },
          {
            name: "Gobuster Output to File",
            description: "Save gobuster results to file",
            command: `gobuster dir -u http://${target} -w /usr/share/wordlists/dirb/common.txt -o gobuster_results.txt`,
            category: "reporting"
          },
          {
            name: "Screenshot Tool",
            description: "Take screenshots of web applications",
            command: `cutycapt --url=http://${target} --out=screenshot.png`,
            category: "reporting"
          },
          {
            name: "HTML Report Generator",
            description: "Generate comprehensive HTML reports",
            command: `nmap-report-generator -i scan_results.xml -o report.html`,
            category: "reporting"
          },
          {
            name: "PDF Report Generator",
            description: "Convert scan results to PDF",
            command: `scan-to-pdf --input nuclei_results.json --output report.pdf`,
            category: "reporting"
          },
          {
            name: "CSV Export Tool",
            description: "Export results to CSV format",
            command: `results-to-csv --input scan_data.json --output results.csv`,
            category: "reporting"
          },
          {
            name: "Metasploit Report",
            description: "Generate Metasploit workspace reports",
            command: `msfconsole -x "workspace -a ${target}; db_export -f xml report.xml; exit"`,
            category: "reporting"
          }
        ]
      }
    ];

    return categories.filter(category => category.commands.length > 0);
  };

  const commandCategories = target && targetType ? generateCommands(target, targetType) : [];

  return (
    <div className="min-h-screen bg-black p-4 md:p-8 text-white">
      <div className="max-w-7xl mx-auto space-y-8">
        {/* Header */}
        <div className="text-center space-y-8 relative">
          <div className="absolute inset-0 bg-gradient-to-r from-cyan-500/5 to-purple-500/5 rounded-3xl blur-3xl"></div>
          <div className="relative z-10">
            <div className="flex items-center justify-center mb-6">
              <div className="h-16 w-16 bg-gradient-to-br from-cyan-400 to-purple-600 rounded-2xl flex items-center justify-center shadow-2xl">
                <Shield className="h-8 w-8 text-white" />
              </div>
            </div>
            <h1 className="text-4xl md:text-6xl font-bold bg-gradient-to-r from-cyan-400 via-blue-500 to-purple-600 bg-clip-text text-transparent mb-4">
              RunbookX
            </h1>
            <div className="flex items-center justify-center gap-2 mb-6">
              <div className="h-1 w-16 bg-gradient-to-r from-cyan-400 to-purple-600 rounded-full"></div>
              <div className="h-1 w-8 bg-gradient-to-r from-purple-600 to-pink-500 rounded-full"></div>
              <div className="h-1 w-16 bg-gradient-to-r from-cyan-400 to-purple-600 rounded-full"></div>
            </div>
            <p className="text-xl text-gray-300 max-w-4xl mx-auto leading-relaxed mb-8">
              eXploit-ready runbooks for professional reconnaissance and penetration testing
            </p>
            <div className="flex flex-wrap items-center justify-center gap-8 text-sm text-gray-400">
              <div className="flex items-center gap-3 bg-black/80 px-4 py-2 rounded-full border border-gray-800">
                <Code className="h-4 w-4 text-green-400" />
                <span>350+ Commands</span>
              </div>
              <div className="flex items-center gap-3 bg-black/80 px-4 py-2 rounded-full border border-gray-800">
                <Shield className="h-4 w-4 text-cyan-400" />
                <span>Real-world Tested</span>
              </div>
              <div className="flex items-center gap-3 bg-black/80 px-4 py-2 rounded-full border border-gray-800">
                <Target className="h-4 w-4 text-purple-400" />
                <span>Professional Grade</span>
              </div>
            </div>
          </div>
        </div>

        {/* Target Input */}
        <Card className="max-w-3xl mx-auto bg-gray-950 border-gray-800 shadow-2xl">
          <CardHeader className="pb-6">
            <CardTitle className="text-2xl text-cyan-400 flex items-center gap-3">
              <div className="h-10 w-10 bg-gradient-to-br from-cyan-400 to-blue-600 rounded-lg flex items-center justify-center">
                <Target className="h-5 w-5 text-white" />
              </div>
              Target Configuration
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-6">
            <div className="space-y-3">
              <Label htmlFor="target" className="text-gray-300 text-sm font-medium flex items-center gap-2">
                <Search className="h-4 w-4 text-cyan-400" />
                Target (IP Address or Domain)
              </Label>
              <div className="relative">
                <Input
                  id="target"
                  type="text"
                  placeholder="example.com or 192.168.1.1"
                  value={target}
                  onChange={(e) => handleTargetChange(e.target.value)}
                  className="text-lg bg-gray-950 border-gray-800 text-white placeholder-gray-500 focus:border-cyan-400 focus:ring-2 focus:ring-cyan-400/20 transition-all duration-200 pl-4 pr-12 h-12 rounded-xl"
                />
                <div className="absolute right-3 top-1/2 transform -translate-y-1/2">
                  <div className="h-8 w-8 bg-gradient-to-br from-cyan-400/20 to-purple-400/20 rounded-full flex items-center justify-center">
                    <Target className="h-4 w-4 text-cyan-400" />
                  </div>
                </div>
              </div>
            </div>
            
            {targetType && (
              <div className="p-4 bg-gradient-to-r from-cyan-500/10 to-blue-500/10 rounded-xl border border-cyan-500/30 backdrop-blur-sm">
                <div className="flex items-center gap-3">
                  <div className="h-10 w-10 bg-gradient-to-br from-cyan-400 to-blue-600 rounded-lg flex items-center justify-center">
                    <Check className="h-5 w-5 text-white" />
                  </div>
                  <div>
                    <p className="text-sm text-cyan-400 font-semibold">
                      Target Detected: {targetType === 'ip' ? 'IP Address' : 'Domain Name'}
                    </p>
                    <p className="text-xs text-gray-400 mt-1">
                      Commands optimized for {targetType === 'ip' ? 'network infrastructure' : 'domain reconnaissance'}
                    </p>
                  </div>
                </div>
              </div>
            )}

            {target && !targetType && (
              <div className="p-4 bg-gradient-to-r from-red-500/10 to-orange-500/10 rounded-xl border border-red-500/30 backdrop-blur-sm">
                <div className="flex items-center gap-3">
                  <div className="h-10 w-10 bg-gradient-to-br from-red-400 to-orange-600 rounded-lg flex items-center justify-center">
                    <Shield className="h-5 w-5 text-white" />
                  </div>
                  <div>
                    <p className="text-sm text-red-400 font-semibold">Invalid Target Format</p>
                    <p className="text-xs text-gray-400 mt-1">
                      Please enter a valid IP address (e.g., 192.168.1.1) or domain name (e.g., example.com)
                    </p>
                  </div>
                </div>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Command Categories */}
        {commandCategories.length > 0 && (
          <div className="space-y-6">
            <div className="text-center space-y-4">
              <h2 className="text-3xl font-bold bg-gradient-to-r from-purple-400 via-pink-500 to-cyan-400 bg-clip-text text-transparent">
                Generated Commands
              </h2>
              <div className="flex items-center justify-center gap-2">
                <div className="h-px w-16 bg-gradient-to-r from-transparent to-purple-400"></div>
                <div className="h-2 w-2 bg-purple-400 rounded-full animate-pulse"></div>
                <div className="h-px w-32 bg-gradient-to-r from-purple-400 to-cyan-400"></div>
                <div className="h-2 w-2 bg-cyan-400 rounded-full animate-pulse"></div>
                <div className="h-px w-16 bg-gradient-to-r from-cyan-400 to-transparent"></div>
              </div>
              <p className="text-gray-400 text-sm">
                Professional-grade commands ready for execution
              </p>
            </div>
            <div className="grid gap-6 md:grid-cols-1 lg:grid-cols-2">
              {commandCategories.map((category, categoryIndex) => (
                <Card key={categoryIndex} className="h-fit bg-gray-950 border-gray-800 hover:border-gray-700 hover:bg-gray-900 transition-all duration-300 group shadow-xl hover:shadow-2xl hover:shadow-cyan-500/10">
                  <CardHeader className="pb-4">
                    <CardTitle className="text-xl text-cyan-400 flex items-center gap-3 group-hover:text-cyan-300 transition-colors">
                      <div className="h-8 w-8 bg-gradient-to-br from-cyan-400/20 to-blue-600/20 rounded-lg flex items-center justify-center">
                        {category.name === 'Network Reconnaissance' && <Search className="h-4 w-4 text-cyan-400" />}
                        {category.name === 'DNS Enumeration' && <Search className="h-4 w-4 text-cyan-400" />}
                        {category.name === 'Web Application Testing' && <Code className="h-4 w-4 text-cyan-400" />}
                        {category.name === 'Vulnerability Scanning' && <Shield className="h-4 w-4 text-cyan-400" />}
                        {category.name === 'SSL/TLS Testing' && <Lock className="h-4 w-4 text-cyan-400" />}
                        {category.name === 'Advanced Enumeration' && <Search className="h-4 w-4 text-cyan-400" />}
                        {category.name === 'Exploitation & Payloads' && <Shield className="h-4 w-4 text-cyan-400" />}
                        {category.name === 'Content Discovery' && <FileText className="h-4 w-4 text-cyan-400" />}
                        {category.name === 'API Testing' && <Code className="h-4 w-4 text-cyan-400" />}
                        {category.name === 'Cloud Security' && <Cloud className="h-4 w-4 text-cyan-400" />}
                        {category.name === 'Database Testing' && <Database className="h-4 w-4 text-cyan-400" />}
                        {category.name === 'Mobile & IoT' && <Smartphone className="h-4 w-4 text-cyan-400" />}
                        {category.name === 'Information Gathering' && <Search className="h-4 w-4 text-cyan-400" />}
                        {category.name === 'Wireless Testing' && <Wifi className="h-4 w-4 text-cyan-400" />}
                        {category.name === 'Post-Exploitation' && <Shield className="h-4 w-4 text-cyan-400" />}
                        {category.name === 'Evasion & Steganography' && <Lock className="h-4 w-4 text-cyan-400" />}
                        {category.name === 'Reporting & Documentation' && <FileText className="h-4 w-4 text-cyan-400" />}
                      </div>
                      {category.name}
                      <div className="ml-auto text-xs bg-gray-800 px-2 py-1 rounded-full text-gray-400">
                        {category.commands.length} commands
                      </div>
                    </CardTitle>
                    <p className="text-sm text-gray-400 group-hover:text-gray-300 transition-colors leading-relaxed">
                      {category.description}
                    </p>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    {category.commands.map((cmd, cmdIndex) => (
                      <div key={cmdIndex} className="space-y-3 p-4 border border-gray-800 rounded-xl bg-gray-900 hover:bg-gray-800 transition-all duration-300 group/cmd hover:border-gray-700">
                        <div className="flex justify-between items-start gap-3">
                          <div className="flex-1 min-w-0 space-y-2">
                            <div className="flex items-center gap-2">
                              <div className="h-2 w-2 bg-green-400 rounded-full animate-pulse"></div>
                              <h4 className="font-semibold text-white group-hover/cmd:text-cyan-100 transition-colors text-sm">
                                {cmd.name}
                              </h4>
                            </div>
                            <p className="text-xs text-gray-400 group-hover/cmd:text-gray-300 transition-colors leading-relaxed">
                              {cmd.description}
                            </p>
                          </div>
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => copyToClipboard(cmd.command, `${category.name}-${cmd.name}`)}
                            className="shrink-0 border-gray-700 bg-gray-800 text-cyan-400 hover:bg-cyan-500/20 hover:text-cyan-300 hover:border-cyan-500 transition-all duration-200 min-w-[80px] h-8"
                          >
                            {copiedCommand === `${category.name}-${cmd.name}` ? (
                              <span className="flex items-center gap-1">
                                <Check className="h-3 w-3 text-green-400" />
                                Copied!
                              </span>
                            ) : (
                              <span className="flex items-center gap-1">
                                <Copy className="h-3 w-3" />
                                Copy
                              </span>
                            )}
                          </Button>
                        </div>
                        <div className="relative">
                          <pre
                            ref={(el) => commandRefs.current[`${category.name}-${cmd.name}`] = el}
                            className="text-xs bg-gray-950 p-4 rounded-lg border border-gray-800 overflow-x-auto text-green-400 font-mono leading-relaxed hover:bg-gray-900 transition-colors group-hover/cmd:border-gray-700"
                          >
                            {cmd.command}
                          </pre>
                          <div className="absolute top-2 right-2 opacity-0 group-hover/cmd:opacity-100 transition-opacity">
                            <div className="text-xs text-gray-400 bg-gray-900 px-2 py-1 rounded">
                              Terminal Ready
                            </div>
                          </div>
                        </div>
                      </div>
                    ))}
                  </CardContent>
                </Card>
              ))}
            </div>
          </div>
        )}

        {/* Usage Instructions */}
        <Card className="max-w-5xl mx-auto bg-gray-950 border-gray-800 shadow-2xl">
          <CardHeader className="pb-6">
            <CardTitle className="text-2xl text-purple-400 flex items-center gap-3">
              <div className="h-10 w-10 bg-gradient-to-br from-purple-400 to-pink-600 rounded-lg flex items-center justify-center">
                <FileText className="h-5 w-5 text-white" />
              </div>
              Usage Instructions
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-8">
            <div className="grid md:grid-cols-2 gap-8">
              <div className="space-y-4">
                <div className="flex items-center gap-3">
                  <div className="h-8 w-8 bg-gradient-to-br from-cyan-400 to-blue-600 rounded-lg flex items-center justify-center">
                    <Search className="h-4 w-4 text-white" />
                  </div>
                  <h3 className="font-semibold text-cyan-400 text-lg">Getting Started</h3>
                </div>
                <div className="space-y-3 pl-9">
                  <div className="flex items-start gap-3 p-3 bg-gray-750 rounded-lg">
                    <Target className="h-4 w-4 text-cyan-400 mt-0.5 flex-shrink-0" />
                    <p className="text-sm text-gray-300 leading-relaxed">Enter your target IP address or domain name</p>
                  </div>
                  <div className="flex items-start gap-3 p-3 bg-gray-750 rounded-lg">
                    <Code className="h-4 w-4 text-cyan-400 mt-0.5 flex-shrink-0" />
                    <p className="text-sm text-gray-300 leading-relaxed">Commands will be automatically generated based on target type</p>
                  </div>
                  <div className="flex items-start gap-3 p-3 bg-gray-750 rounded-lg">
                    <Copy className="h-4 w-4 text-cyan-400 mt-0.5 flex-shrink-0" />
                    <p className="text-sm text-gray-300 leading-relaxed">Click "Copy" to copy commands to clipboard</p>
                  </div>
                  <div className="flex items-start gap-3 p-3 bg-gray-750 rounded-lg">
                    <FileText className="h-4 w-4 text-cyan-400 mt-0.5 flex-shrink-0" />
                    <p className="text-sm text-gray-300 leading-relaxed">Run commands in your preferred terminal</p>
                  </div>
                </div>
              </div>
              
              <div className="space-y-4">
                <div className="flex items-center gap-3">
                  <div className="h-8 w-8 bg-gradient-to-br from-purple-400 to-pink-600 rounded-lg flex items-center justify-center">
                    <Shield className="h-4 w-4 text-white" />
                  </div>
                  <h3 className="font-semibold text-purple-400 text-lg">Important Notes</h3>
                </div>
                <div className="space-y-3 pl-9">
                  <div className="flex items-start gap-3 p-3 bg-gray-750 rounded-lg">
                    <Shield className="h-4 w-4 text-purple-400 mt-0.5 flex-shrink-0" />
                    <p className="text-sm text-gray-300 leading-relaxed">Only test on systems you own or have permission to test</p>
                  </div>
                  <div className="flex items-start gap-3 p-3 bg-gray-750 rounded-lg">
                    <Code className="h-4 w-4 text-purple-400 mt-0.5 flex-shrink-0" />
                    <p className="text-sm text-gray-300 leading-relaxed">Some tools may require installation (nmap, gobuster, etc.)</p>
                  </div>
                  <div className="flex items-start gap-3 p-3 bg-gray-750 rounded-lg">
                    <FileText className="h-4 w-4 text-purple-400 mt-0.5 flex-shrink-0" />
                    <p className="text-sm text-gray-300 leading-relaxed">Adjust wordlist paths based on your system</p>
                  </div>
                  <div className="flex items-start gap-3 p-3 bg-gray-750 rounded-lg">
                    <Shield className="h-4 w-4 text-purple-400 mt-0.5 flex-shrink-0" />
                    <p className="text-sm text-gray-300 leading-relaxed">Use appropriate rate limiting to avoid detection</p>
                  </div>
                </div>
              </div>
            </div>
            
            <div className="p-6 bg-gradient-to-r from-yellow-500/10 via-orange-500/10 to-red-500/10 rounded-xl border border-yellow-500/30">
              <div className="flex items-start gap-4">
                <div className="h-12 w-12 bg-gradient-to-br from-yellow-400 to-orange-600 rounded-lg flex items-center justify-center flex-shrink-0">
                  <Shield className="h-6 w-6 text-white" />
                </div>
                <div>
                  <h4 className="text-yellow-400 font-semibold mb-2">Legal Disclaimer</h4>
                  <p className="text-sm text-yellow-200/90 leading-relaxed">
                    This tool is intended for <strong>authorized security testing and educational purposes only</strong>. 
                    Always ensure you have proper written authorization before testing any systems. Unauthorized access to computer systems is illegal and may result in criminal charges.
                  </p>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};

export default BugBountyToolkit;
