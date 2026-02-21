# 1. Information Gathering & Vulnerability Scanning

## Table of Contents

- [Reconnaissance Overview](#reconnaissance-overview)
- [Passive Reconnaissance](#passive-reconnaissance)
- [Active Reconnaissance](#active-reconnaissance)
- [Vulnerability Scanning](#vulnerability-scanning)
- [Prioritizing Findings](#prioritizing-findings)
- [Quick Reference Commands](#quick-reference-commands)

---

## Reconnaissance Overview

```
┌───────────────────────────────────────────────────┐
│              RECONNAISSANCE                       │
├────────────────────┬──────────────────────────────┤
│      PASSIVE       │          ACTIVE              │
│                    │                              │
│  No direct contact │  Sends probes to target      │
│  with target       │                              │
│                    │                              │
│  • OSINT           │  • Port scanning             │
│  • DNS lookups     │  • Service enumeration       │
│  • Cert inspection │  • Vulnerability scanning    │
│  • Packet sniffing │  • Packet crafting           │
│                    │                              │
│  Low risk of       │  Can crash fragile devices   │
│  detection         │  Likely to be logged/detected│
└────────────────────┴──────────────────────────────┘
```

---

## Passive Reconnaissance

> **No direct interaction with the target.** Uses third-party sources, listening, and public data. Unlikely to be detected.

### Methods

| Method | Description |
|---|---|
| Domain Enumeration | Discover subdomains, DNS records, ownership |
| Packet Inspection | Sniff traffic without generating any |
| OSINT | Open-source intelligence from public sources |
| Eavesdropping | Passively capture network communications |

### Tools

#### General Recon

| Tool | Purpose | Example |
|---|---|---|
| `recon-ng` | Modular OSINT framework | `recon-ng` → `marketplace search` → `modules load` |
| `spiderfoot` | Automated OSINT collection | `spiderfoot -l 127.0.0.1:5001` (web UI) |
| `theHarvester` | Gather emails, subdomains, IPs | `theHarvester -d target.com -b google` |

#### DNS

| Tool | Purpose | Example |
|---|---|---|
| `whois` | Domain registration info | `whois target.com` |
| `nslookup` | DNS record lookup | `nslookup -type=any target.com` |
| `dnsrecon` | DNS enumeration & zone transfer | `dnsrecon -d target.com -t std` |
| `dig` | Detailed DNS queries | `dig target.com ANY +noall +answer` |
| `dnsenum` | DNS enum + brute force subdomains | `dnsenum target.com` |

#### SSL/TLS & Cryptographic Flaws

During recon, inspecting SSL certificates can reveal:
- Organization name & subdomains
- Certificate serial number & validity
- OCSP / CRL URIs
- Weak cipher suites & misconfigurations

| Tool | Purpose | Example |
|---|---|---|
| `sslscan` | Query SSL ciphers supported | `sslscan target.com` |
| `sslyze` | Analyze SSL configuration | `sslyze target.com` |
| `ssldump` | Decode SSL traffic | `ssldump -i eth0 -d` |
| `sslh` | Multiplex services on port 443 | Config-based |
| `sslsplit` | MitM on SSL connections | `sslsplit -l 8080` |
| [crt.sh](https://crt.sh) | Certificate transparency search | `https://crt.sh/?q=target.com` |

#### Password Dumps & Breaches

| Tool / Site | Type |
|---|---|
| `h8mail` | CLI — email breach lookup |
| [haveibeenpwned.com](https://haveibeenpwned.com) | Web — check email breaches |
| [breachdirectory.com](https://breachdirectory.com) | Web — breach search |
| [WhatBreach](https://github.com/Ekultek/WhatBreach) | CLI — breach lookup |
| [LeakLooker](https://github.com/woj-ciech/LeakLooker) | Exposed database search |
| [Buster](https://github.com/sham00n/buster) | Email OSINT |
| [PwnDB](https://github.com/davidtavarez/pwndb) | Tor-based breach search |

#### Email Harvesting

| Tool / Site | Example |
|---|---|
| `emailharvester` | `emailharvester -d target.com -e google` |
| `spiderfoot` | Automated via modules |
| `theHarvester` | `theHarvester -d target.com -b all` |

#### File Metadata

| Tool | Purpose | Example |
|---|---|---|
| `exiftool` | Extract metadata from files | `exiftool document.pdf` |
| `metagoofil` | Extract metadata from public docs | `metagoofil -d target.com -t pdf -o output/` |

#### Google Dorking

Use advanced Google operators to find exposed information:

| Operator | Purpose | Example |
|---|---|---|
| `site:` | Limit to domain | `site:target.com` |
| `filetype:` | Search by file type | `filetype:pdf site:target.com` |
| `intitle:` | Search page titles | `intitle:"index of" site:target.com` |
| `inurl:` | Search in URL | `inurl:admin site:target.com` |
| `cache:` | View cached version | `cache:target.com` |

> **Resource:** [Google Hacking Database (GHDB)](https://exploit-db.com/google-hacking-database)

#### Shodan

```bash
# Install CLI
pip install shodan
shodan init YOUR_API_KEY

# Search examples
shodan search "apache" --fields ip_str,port,org
shodan host 1.2.3.4
shodan count "port:22 country:US"
```

#### Packet Inspection / Eavesdropping

| Tool | Purpose | Example |
|---|---|---|
| `wireshark` | GUI packet analyzer | GUI-based |
| `tcpdump` | CLI packet capture | `tcpdump -i eth0 -w capture.pcap` |
| `tshark` | CLI Wireshark | `tshark -i eth0 -f "port 80"` |

---

## Active Reconnaissance

> **Sends probes directly to the target.** More information, but higher risk of detection. Can crash fragile devices — adjust settings accordingly.

### Methods

```
Active Recon Methods
├── Host Enumeration
├── Network Enumeration
├── User Enumeration
├── Group Enumeration
├── Network Share Enumeration
├── Web Page / Web App Enumeration
├── Application Enumeration
├── Service Enumeration
└── Packet Crafting
```

### Nmap

#### Port Status

| Status | Target Response | Meaning |
|---|---|---|
| **Open** | TCP SYN-ACK | Service is listening |
| **Closed** | TCP RST | No service on port |
| **Filtered** | No response / ICMP unreachable | Port is firewalled |

#### Scan Types

| Flag | Scan Type | Description |
|---|---|---|
| `-sT` | TCP Connect | Full 3-way handshake (noisy, no root needed) |
| `-sS` | TCP SYN (Stealth) | Half-open scan (default with root) |
| `-sU` | UDP Scan | Scan UDP ports (slow) |
| `-sF` | TCP FIN | Stealthy — sends FIN flag only |
| `-sn` | Host Discovery (Ping) | No port scan, just find live hosts |
| `-sV` | Service Version | Detect service/version on open ports |
| `-sA` | ACK Scan | Map firewall rules |
| `-O` | OS Detection | Fingerprint operating system |

#### Timing Options

```
Speed ──────────────────────────────────────────────►
T0          T1          T2          T3          T4          T5
Paranoid    Sneaky      Polite      Normal      Aggressive  Insane
IDS evasion IDS evasion Low BW      Default     Fast net    Very fast
                        10x slower              May overwhelm May miss ports
```

#### Essential Nmap Commands

```bash
# Host discovery on a subnet
nmap -sn 10.10.10.0/24

# Quick scan top 100 ports
nmap -F 10.10.10.5

# Full port scan with service detection
nmap -sS -sV -p- 10.10.10.5

# Aggressive scan (OS, version, scripts, traceroute)
nmap -A 10.10.10.5

# Scan with vulnerability scripts
sudo nmap -sV --script vulners --script-args mincvss=4.0 10.10.10.5

# Scan specific ports
nmap -p 80,443,8080 10.10.10.5

# Output to all formats
nmap -sV -oA scan_results 10.10.10.5

# Stealth scan with timing
nmap -sS -T2 -f 10.10.10.5       # -f fragments packets

# Scan through a proxy / decoy
nmap -D RND:5 10.10.10.5          # 5 random decoy IPs
```

> **Tip:** Always save output (`-oA`) for later review. Use `-sV` often — version info is key for finding vulns.

### Enumeration Tools

| Target | Tool | Command Example |
|---|---|---|
| SMB Shares | `enum4linux` | `enum4linux -a 10.10.10.5` |
| SMB | `smbclient` | `smbclient -L //10.10.10.5 -N` |
| SNMP | `snmpwalk` | `snmpwalk -v2c -c public 10.10.10.5` |
| Web Apps | `nikto` | `nikto -h http://10.10.10.5` |
| Web Dirs | `gobuster` | `gobuster dir -u http://10.10.10.5 -w /usr/share/wordlists/dirb/common.txt` |
| Web Dirs | `dirb` | `dirb http://10.10.10.5` |
| DNS Zone Transfer | `dig` | `dig axfr @ns.target.com target.com` |
| LDAP | `ldapsearch` | `ldapsearch -x -H ldap://10.10.10.5 -b "dc=target,dc=com"` |
| NetBIOS | `nbtscan` | `nbtscan 10.10.10.0/24` |

### Packet Crafting

| Tool | Purpose | Example |
|---|---|---|
| `scapy` | Python packet manipulation | Interactive: `scapy` |
| `hping3` | TCP/IP packet assembler | `hping3 -S -p 80 10.10.10.5` |

---

## Vulnerability Scanning

### How Automated Scanners Work

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌───────────────┐
│  1. DISCOVER │───►│  2. IDENTIFY │───►│  3. CORRELATE│───►│  4. REPORT    │
│              │    │              │    │              │    │               │
│ Host & port  │    │ Probe open   │    │ Match against│    │ List suspected│
│ enumeration  │    │ ports for    │    │ known vuln   │    │ vulns (may    │
│ (e.g. Nmap)  │    │ software +   │    │ database     │    │ include false │
│              │    │ version info │    │              │    │ positives)    │
└──────────────┘    └──────────────┘    └──────────────┘    └───────────────┘
```

### Types of Vulnerability Scans

| Type | Description |
|---|---|
| **Unauthenticated** | External view — scans without credentials |
| **Authenticated** | Uses valid credentials — deeper, more accurate results |
| **Discovery** | Lightweight — identify hosts and services only |
| **Full** | Comprehensive — all checks enabled |
| **Stealth** | Low footprint — avoid detection |
| **Compliance** | Check against standards (PCI-DSS, HIPAA, etc.) |

### Vulnerability Scanning Tools

| Tool | Type | Start Command |
|---|---|---|
| **OpenVAS / GVM** | Full scanner (GUI) | `sudo gvm-start` / verify: `sudo gvm-check-setup` |
| **Nmap + vulners** | Script-based | `sudo nmap -sV --script vulners --script-args mincvss=4.0 TARGET` |
| **Nikto** | Web vuln scanner | `nikto -h http://TARGET` |
| **Nessus** | Commercial scanner | Web UI (port 8834) |
| **WPScan** | WordPress scanner | `wpscan --url http://TARGET` |

### Vulnerability Research Sources

| Source | URL | Focus |
|---|---|---|
| **CVE** | [cve.mitre.org](https://cve.mitre.org) | Common Vulnerabilities & Exposures catalog |
| **NVD (NIST)** | [nvd.nist.gov](https://nvd.nist.gov) | Detailed vuln data + CVSS scores |
| **US-CERT** | [us-cert.cisa.gov](https://us-cert.cisa.gov) | Alerts & advisories |
| **CWE** | [cwe.mitre.org](https://cwe.mitre.org) | Common Weakness Enumeration |
| **CVSS** | [first.org/cvss](https://first.org/cvss) | Vulnerability scoring system |
| **CAPEC** | [capec.mitre.org](https://capec.mitre.org) | Attack pattern catalog |
| **JPCERT** | [jpcert.or.jp](https://www.jpcert.or.jp/english/) | Japanese CERT advisories |
| **Exploit-DB** | [exploit-db.com](https://exploit-db.com) | Public exploits database |

---

## Prioritizing Findings

When you have scan results, use these criteria to triage:

```
                    ┌─────────────────────────┐
                    │   VULNERABILITY FOUND   │
                    └────────────┬────────────┘
                                 │
              ┌──────────────────┼──────────────────┐
              ▼                  ▼                   ▼
     ┌────────────────┐ ┌────────────────┐ ┌─────────────────┐
     │   SEVERITY?    │ │  ASSET VALUE?  │ │ EXPLOITABILITY? │
     │                │ │                │ │                 │
     │ • CVSS score   │ │ • Critical?    │ │ • Attack vector │
     │ • Impact       │ │ • Business     │ │ • Public exploit│
     │                │ │   importance   │ │   available?    │
     └───────┬────────┘ └───────┬────────┘ └───────┬─────────┘
             │                  │                   │
             └──────────────────┼───────────────────┘
                                ▼
                    ┌───────────────────────────┐
                    │  PRIORITIZATION MATRIX    │
                    │                           │
                    │  1. How severe?           │
                    │  2. How many systems?     │
                    │  3. Auto vs manual found? │
                    │  4. Asset criticality?    │
                    │  5. Attack vector viable? │
                    │  6. Mitigation available? │
                    └───────────────────────────┘
```

### Checklist

- [ ] What is the **severity** (CVSS score)?
- [ ] How many **systems** are affected?
- [ ] How was it **detected** (automated vs manual)?
- [ ] What is the **value** of the affected device?
- [ ] Is the device **critical** to business/infrastructure?
- [ ] Is the **attack vector** applicable to the environment?
- [ ] Is there a **workaround or mitigation** available?

---

## Quick Reference Commands

```bash
# ─── PASSIVE ───────────────────────────────────────
whois target.com                                    # Domain info
nslookup -type=any target.com                       # DNS records
dig target.com ANY +noall +answer                   # DNS query
dnsrecon -d target.com -t std                       # DNS enum
theHarvester -d target.com -b google                # Email/subdomain harvest
sslscan target.com                                  # SSL cipher check
exiftool document.pdf                               # File metadata
h8mail -t user@target.com                           # Breach lookup
shodan host 1.2.3.4                                 # Shodan lookup
tcpdump -i eth0 -w capture.pcap                     # Packet capture

# ─── ACTIVE ────────────────────────────────────────
nmap -sn 10.10.10.0/24                              # Host discovery
nmap -sS -sV -p- -oA full_scan 10.10.10.5          # Full stealth scan
nmap -A -T4 10.10.10.5                              # Aggressive scan
nmap -sV --script vulners 10.10.10.5                # Vuln scan via Nmap
enum4linux -a 10.10.10.5                            # SMB enumeration
gobuster dir -u http://10.10.10.5 -w /usr/share/wordlists/dirb/common.txt
nikto -h http://10.10.10.5                          # Web vuln scan

# ─── VULN SCANNING ────────────────────────────────
sudo gvm-check-setup                                # Verify GVM/OpenVAS
sudo gvm-start                                      # Start GVM/OpenVAS
wpscan --url http://target.com                      # WordPress scan
```
