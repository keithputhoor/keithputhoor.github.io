const PROJECTS = [
  {
    id: "PROJ-01",
    category: 1,
    categoryName: "Cybersecurity, Networking & Academic Projects",
    subjectBadge: "SOC Automation",
    visibility: "Public Repo",
    title: "AI-Assisted SOC Alert Triage Pipeline",
    repoUrl: "https://github.com/keithputhoor/soc-ai-alert-triage",
    overview: "An automated Security Operations Center (SOC) alert ingestion and LLM-assisted triage pipeline built for an OPNsense (FreeBSD) perimeter firewall. Streams real-time Suricata IDS telemetry via a custom zero-dependency Python daemon over Tailscale to an n8n orchestration workflow and a local Ollama LLM server.",
    highlights: [
      "Tails /var/log/suricata/eve.json in real time and tracks file inodes (os.stat().st_ino) to survive FreeBSD newsyslog rotations without dropping alerts.",
      "Filters alert noise at the edge by forwarding only Severity 1 (High) and Severity 2 (Medium) Suricata signatures over encrypted Tailscale/LAN transport.",
      "Persists across OPNsense firmware reboots via a native FreeBSD /usr/local/etc/rc.syshook.d/start/ startup script."
    ],
    pipeline: "OPNsense (Suricata IDS) → eve.json → suricata_shipper.py (Daemon) → Tailscale / LAN HTTP POST → n8n Webhook → Local Ollama LLM → Alert Notification",
    stack: ["OPNsense (FreeBSD)", "Suricata IDS", "Python 3", "n8n", "Ollama", "Tailscale"],
    snippets: [
      {
        filename: "src/suricata_shipper.py",
        lang: "python",
        code: `#!/usr/local/bin/python3
import time
import json
import urllib.request
import os

EVE_LOG_PATH = "/var/log/suricata/eve.json"
N8N_WEBHOOK_URL = "http://100.x.y.z:5678/webhook/soc-alert"  # Routed via Tailscale/LAN
MIN_SEVERITY = 2  # Filter: 1 (High), 2 (Medium)

def tail_eve_log(filepath):
    with open(filepath, "r") as f:
        f.seek(0, os.SEEK_END)
        inode = os.fstat(f.fileno()).st_ino
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                try:
                    if os.stat(filepath).st_ino != inode:
                        f.close()
                        f = open(filepath, "r")
                        inode = os.fstat(f.fileno()).st_ino
                except FileNotFoundError:
                    pass
                continue
            yield line

def ship_alert(payload):
    req = urllib.request.Request(
        N8N_WEBHOOK_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status
    except Exception as e:
        print(f"[ERROR] Webhook delivery failed: {e}")

def main():
    for raw_line in tail_eve_log(EVE_LOG_PATH):
        try:
            event = json.loads(raw_line)
            if event.get("event_type") == "alert":
                severity = event.get("alert", {}).get("severity", 3)
                if severity <= MIN_SEVERITY:
                    ship_alert({
                        "timestamp": event.get("timestamp"),
                        "src_ip": event.get("src_ip"),
                        "dest_ip": event.get("dest_ip"),
                        "proto": event.get("proto"),
                        "signature": event["alert"].get("signature"),
                        "category": event["alert"].get("category"),
                        "severity": severity
                    })
        except json.JSONDecodeError:
            continue

if __name__ == "__main__":
    main()`
      },
      {
        filename: "freebsd/99-suricata-shipper",
        lang: "sh",
        code: `#!/bin/sh
nohup /usr/local/bin/python3 /root/scripts/suricata_shipper.py >/var/log/suricata_shipper.log 2>&1 &`
      }
    ],
    logs: [
      {
        title: "Issue 1: Suricata Dropping Packets & Missing Signatures on OPNsense",
        detail: "Root Cause: Network Interface Card (NIC) hardware offloading features were coalescing packets before Suricata could inspect the raw stream. Fix: Disabled Hardware CRC, Hardware TSO (TCP Segmentation Offload), and Hardware LRO (Large Receive Offload) in OPNsense (Interfaces -> Settings)."
      },
      {
        title: "Issue 2: suricata_shipper.py Dying on SSH Disconnect & Log Rotation",
        detail: "Root Cause: Launching the script over a standard shell killed the process on exit, and when Suricata rotated eve.json, the Python file handle stayed attached to the old inode. Fix: Added inode comparison (os.stat(filepath).st_ino != inode) inside the log-tailing loop to reopen the file upon rotation, and placed a startup daemon script in FreeBSD's /usr/local/etc/rc.syshook.d/start/99-suricata-shipper using nohup."
      },
      {
        title: "Issue 3: Alert Floods & Webhook Timeouts to n8n / Ollama",
        detail: "Root Cause: Forwarding every low-priority informational event overwhelmed the local Ollama LLM queue and caused HTTP timeout errors across the subnet/Tailscale bridge. Fix: Filtered events strictly to event_type == \"alert\" with severity <= 2 inside the shipper script before firing the HTTP POST request to the n8n webhook."
      }
    ]
  },
  {
    id: "PROJ-02",
    category: 1,
    categoryName: "Cybersecurity, Networking & Academic Projects",
    subjectBadge: "Ethical Hacking",
    visibility: "Private Academic Repo",
    title: "Enterprise Vulnerability Assessment & Remediation Simulation",
    repoUrl: "https://github.com/keithputhoor/Ethical-Hacking-Portfolio/tree/main/enterprise-vulnerability-remediation",
    overview: "End-to-end credentialed and unauthenticated vulnerability assessment across isolated enterprise lab subnets using Tenable Nessus, paired with active exploitation verification in Metasploit and Wireshark, service hardening for Redis (CVSS 9.8) and Ruby Rack, and ISO/IEC 27001 control mapping.",
    highlights: [
      "Compared unauthenticated banner scans against SSH-credentialed dpkg inspection in Tenable Nessus to eliminate Debian/Ubuntu backport false positives.",
      "Remediated an exposed Redis instance (CVSS 9.8 Critical) by binding strictly to loopback (127.0.0.1 -::1), enforcing requirepass, and renaming dangerous commands (FLUSHALL, CONFIG).",
      "Patched Ruby Rack middleware traversal/ReDoS vulnerabilities and validated socket closure via ss -tulnp and Nmap NSE scripts."
    ],
    pipeline: "Authenticated & Unauthenticated Subnet Scanning (Tenable Nessus) → Metasploit & Wireshark Exploitation Verification → Redis & Ruby Rack Remediation → ISO/IEC 27001 Control Mapping",
    stack: ["Tenable Nessus", "Wireshark", "Metasploit", "Kali Linux", "Redis", "Ruby Rack"],
    snippets: [
      {
        filename: "enterprise-vulnerability-remediation/redis.conf",
        lang: "conf",
        code: `# 1. /etc/redis/redis.conf - Remediating Unprotected Redis Instance (CVSS 9.8)
# Bind strictly to loopback interface instead of 0.0.0.0
bind 127.0.0.1 -::1
protected-mode yes

# Enforce strong authentication and disable dangerous administrative commands
requirepass "<64-Char-Cryptographic-Secret>"
rename-command FLUSHALL ""
rename-command FLUSHDB ""
rename-command CONFIG "REDIS_ADMIN_CONFIG_89A1"`
      },
      {
        filename: "enterprise-vulnerability-remediation/remediate_verify.sh",
        lang: "bash",
        code: `#!/bin/bash
# Upgrade vulnerable Rack gems to patch directory traversal / ReDoS CVEs
bundle update rack

# Verify open listening sockets and confirm Redis is no longer exposed on 0.0.0.0:6379
ss -tulnp | grep -E '6379|3000'
nmap -sV -p 6379 --script redis-info 192.168.10.0/24`
      }
    ],
    logs: [
      {
        title: "Issue 1: High False-Positive Count on Unauthenticated Scans",
        detail: "Root Cause: Initial unauthenticated Tenable Nessus scans relied purely on service banners (flagging backported Debian packages as vulnerable). Fix: Configured credentialed SSH scans in Nessus so the scanner could query local package trees (dpkg -l) directly, eliminating banner-based false positives."
      },
      {
        title: "Issue 2: Exposed Unauthenticated Redis Instance (CVSS 9.8) & Ruby Rack Flaws",
        detail: "Root Cause: Target services were bound to 0.0.0.0 without authentication or command restrictions, allowing remote code execution / memory dumping via Metasploit verification. Fix: Bound Redis strictly to loopback (bind 127.0.0.1 -::1), enabled protected-mode yes, enforced requirepass, renamed destructive commands (FLUSHALL, CONFIG), and updated vulnerable Ruby rack gems via bundle update rack. Verified closure with ss -tulnp and Wireshark packet captures."
      }
    ]
  },
  {
    id: "PROJ-03",
    category: 1,
    categoryName: "Cybersecurity, Networking & Academic Projects",
    subjectBadge: "AI & Cybersecurity",
    visibility: "Private Academic Repo",
    title: "PDF Malware Detection & Behavioral Sanitization Engine",
    repoUrl: "https://github.com/keithputhoor/AI-and-Cybersecurity-Portfolio/tree/main/project-pdf-malware-detection",
    overview: "A machine learning PDF malware detector and active Content Disarm & Reconstruction (CDR) sanitizer developed for Artificial Intelligence and Cybersecurity. Uses a 100-tree Random Forest classifier trained on CIC-PDF-Malware-2022 to score structural PDF features and automatically rebuilds high-risk PDFs without executable triggers.",
    highlights: [
      "Extracts 20+ static lexical and structural indicators (/JS, /JavaScript, /OpenAction, /Acroform, /Launch, xref, trailer) without executing the file.",
      "Achieves high precision using 5-fold stratified cross-validation on the CIC-PDF-Malware-2022 dataset.",
      "Surgically reconstructs flagged PDFs (>50% risk) using PyPDF by copying only visual page objects into a clean container and stripping /OpenAction and /Names hooks."
    ],
    pipeline: "Input PDF Stream → Static Lexical & Trailer Extraction (/JS, /OpenAction, /Acroform, xref) → Random Forest Classifier (CIC-PDF-Malware-2022) → Surgical PyPDF Content Disarm & Reconstruction (CDR)",
    stack: ["Python 3", "Scikit-Learn (Random Forest)", "PyPDF", "Pandas / NumPy", "CIC-PDF-Malware-2022"],
    snippets: [
      {
        filename: "project-pdf-malware-detection/pdf_malware_detector.py",
        lang: "python",
        code: `from pypdf import PdfReader, PdfWriter
import os, time

KEYWORDS = ['obj', 'endobj', 'stream', 'endstream', 'xref', 'trailer',
            'startxref', '/Encrypt', '/ObjStm', '/JS', '/JavaScript',
            '/AA', '/OpenAction', '/Acroform', '/JBIG2Decode',
            '/RichMedia', '/Launch', '/EmbeddedFile', '/XFA', '/URI']

def extract_detection_features(input_path, all_model_columns):
    features = {}
    with open(input_path, "rb") as f:
        raw_text = f.read().decode('latin-1', errors='ignore')
        for key in KEYWORDS:
            clean_key = key.lstrip('/')
            features[clean_key] = raw_text.count(key)

    reader = PdfReader(input_path)
    features['isEncrypted'] = 1 if reader.is_encrypted else 0
    root = reader.trailer.get("/Root")
    if root:
        features['OpenAction'] = 1 if "/OpenAction" in root else features.get('OpenAction', 0)
        features['Acroform'] = 1 if "/Acroform" in root else features.get('Acroform', 0)

    return {col: features.get(col, 0.0) for col in all_model_columns}

def sanitize_pdf_structure(input_path, output_path):
    reader = PdfReader(input_path)
    writer = PdfWriter()
    # Copy only visual page trees, leaving behind orphan streams & /OpenAction hooks
    for page in reader.pages:
        writer.add_page(page)
    with open(output_path, "wb") as out_f:
        writer.write(out_f)
    return True`
      }
    ],
    logs: [
      {
        title: "Handling False Positives Caused by Empty Object Obfuscation Patterns",
        detail: "During live testing on benign academic papers (e.g., SSRN preprints), the Random Forest classifier assigned a 66% malicious probability because PDF generators created thousands of empty objects—a structural ratio that mimics malware obfuscation. Rather than deleting the file, the Content Disarm & Reconstruction (CDR) engine rebuilt the page tree into a fresh PDF container, stripping orphan objects and /OpenAction triggers while keeping the document readable."
      },
      {
        title: "Random Forest vs. Deep Neural Networks on Tabular PDF Telemetry",
        detail: "Selected a 100-tree Random Forest ensemble with 5-fold stratified cross-validation over black-box neural networks so security analysts can inspect exact feature importance (such as anomalous /JS or multiple trailer counts) without GPU overhead."
      }
    ]
  },
  {
    id: "PROJ-04",
    category: 1,
    categoryName: "Cybersecurity, Networking & Academic Projects",
    subjectBadge: "Network Security",
    visibility: "Private Academic Repo",
    title: "CloudCafe Multi-Site Enterprise Network Security Architecture",
    repoUrl: "https://github.com/keithputhoor/Network-Security-Portfolio/tree/main/project-cloudcafe-enterprise-network",
    overview: "Full enterprise defense-in-depth network architecture designed in Cisco Packet Tracer for a multi-site organization connecting Site-A HQ (R1) and Site-B Remote Branch (R3) over an untrusted WAN backbone (R2).",
    highlights: [
      "Segmented HQ into 7 departmental 802.1Q VLANs (Kitchen, IT Management, Admin, Delivery, Marketing, Customer Care, and DMZ Web/DNS).",
      "Enforced Extended ACL 100 (restricting diagnostic ICMP strictly to IT workstations) and Extended ACL 102 (permitting only HTTPS TCP/443 to the DMZ Web Server).",
      "Configured a Site-to-Site IPsec VPN (ESP AES/SHA) across R1 and R3, a stateful Cisco IOS Zone-Based Policy Firewall (ZPF), and VLAN 200 WPA2-Enterprise 802.1X RADIUS wireless authentication."
    ],
    pipeline: "7 Departmental 802.1Q VLANs (Site-A HQ R1) → Extended ACLs 100 & 102 → Zone-Based Policy Firewall (ZPF) → Site-to-Site IPsec VPN (ESP AES/SHA) → Site-B Branch (R3) & 802.1X RADIUS WLAN",
    stack: ["Cisco IOS", "Packet Tracer", "Site-to-Site IPsec VPN", "Zone-Based Firewall (ZPF)", "802.1X WPA2-Enterprise RADIUS", "Extended ACLs"],
    snippets: [
      {
        filename: "hq-router-r1-security.ios (Extended ACLs & IPsec VPN)",
        lang: "ios",
        code: `! 1. Extended ACL 100: Restrict network diagnostic ICMP strictly to IT Management hosts
access-list 100 permit icmp 192.168.20.2 0.0.0.0 any
access-list 100 permit icmp 192.168.20.3 0.0.0.0 any
access-list 100 deny icmp any any

! 2. Extended ACL 102: Enforce HTTPS-only (TCP 443) access to DMZ Web Server
access-list 102 permit tcp any host 192.168.70.3 eq 443
access-list 102 deny ip any any

! 3. Site-to-Site IPsec VPN (Site-A HQ R1 10.1.1.2 <-> Site-B Branch R3 10.2.2.2)
crypto isakmp policy 10
 encr aes
 hash sha
 authentication pre-share
 group 2
crypto isakmp key <VPN_SHARED_SECRET> address 10.2.2.2
crypto ipsec transform-set VPN-SET esp-aes esp-sha-hmac`
      }
    ],
    logs: [
      {
        title: "Granular Inter-VLAN Isolation Without Breaking Management Diagnostics",
        detail: "Applied Extended ACL 100 across departmental subinterfaces (Fa0/0.10 through Fa0/0.60) so only designated IT management workstations (192.168.20.2 and 192.168.20.3) can initiate ICMP probes across VLANs while blocking lateral movement from Kitchen, Delivery, or Guest subnets."
      },
      {
        title: "Securing Branch Office Traffic Across an Untrusted ISP Backbone",
        detail: "Configured an IPsec ESP tunnel between Site-A HQ (R1) and the Site-B branch (R3) across intermediary router R2, paired with a stateful Zone-Based Policy Firewall (IN-2-OUT-ZPAIR) and VLAN 200 WPA2-Enterprise RADIUS authentication."
      }
    ]
  },
  {
    id: "PROJ-05",
    category: 1,
    categoryName: "Cybersecurity, Networking & Academic Projects",
    subjectBadge: "Ethical Hacking",
    visibility: "Private Academic Repo",
    title: "OWASP Juice Shop Web Application Penetration Test",
    repoUrl: "https://github.com/keithputhoor/Ethical-Hacking-Portfolio/tree/main/project-owasp-juiceshop-pentest",
    overview: "Web application penetration test performed against an isolated OWASP Juice Shop instance on Kali Linux using Burp Suite Community Edition for passive spidering, REST API parameter enumeration, and OWASP Top 10 exploitation.",
    highlights: [
      "Routed Chromium traffic through Burp Suite Proxy (127.0.0.1:8080) on an isolated Host-Only network (192.168.56.101) to enumerate hidden /rest/ and /api/ endpoints.",
      "Identified and exploited SQL Injection (OWASP A03:2021) on POST /rest/user/login to bypass authentication.",
      "Mapped Reflected XSS on GET /rest/products/search?q= and Broken Access Control / IDOR (OWASP A01:2021) on administrative configuration routes."
    ],
    pipeline: "Kali Linux Chromium Client → Burp Suite Interception Proxy (127.0.0.1:8080) → Passive REST API Enumeration (/rest/ & /api/) → SQLi Auth Bypass & Reflected XSS Verification",
    stack: ["Kali Linux", "Burp Suite", "OWASP Juice Shop", "SQL Injection (SQLi)", "Reflected XSS", "OWASP Top 10"],
    snippets: [
      {
        filename: "burpsuite-intercepted-login-sqli.http",
        lang: "http",
        code: `POST /rest/user/login HTTP/1.1
Host: localhost:3000
Content-Type: application/json
User-Agent: Mozilla/5.0 (X11; Linux x86_64)

{
  "email": "' OR 1=1--",
  "password": "test"
}`
      }
    ],
    logs: [
      {
        title: "Isolating Dynamic REST Endpoints From SPA Asset Noise",
        detail: "Angular single-page applications generate hundreds of static bundle and SVG requests. Configured Burp Suite HTTP history MIME/extension filters to hide static assets and isolate high-value JSON endpoints (/rest/user/login, /rest/products/search, /rest/admin/application-configuration)."
      },
      {
        title: "Host-Only Virtual Network Containment",
        detail: "Configured VirtualBox Adapter 1 as Host-Only (192.168.56.101) and verified zero external WAN routing before conducting active injection testing."
      }
    ]
  },
  {
    id: "PROJ-06",
    category: 1,
    categoryName: "Cybersecurity, Networking & Academic Projects",
    subjectBadge: "Ethical Hacking",
    visibility: "Private Academic Repo",
    title: "Wireshark TLS Decryption & Network Packet Forensics",
    repoUrl: "https://github.com/keithputhoor/Ethical-Hacking-Portfolio/tree/main/labs/Lab-03-Wireshark-Packet-Capture-and-TLS-Decryption",
    overview: "Deep-packet inspection and cryptographic session analysis of captured HTTPS traffic (tls_capture_1.pcapng) using Wireshark and pre-master secret key logs (sslkeys.log).",
    highlights: [
      "Analyzed TCP 3-way handshakes (SYN, SYN-ACK, ACK) and TLS Client Hello / Server Hello cipher-suite negotiation frames.",
      "Configured Wireshark TLS protocol preferences with SSLKEYLOGFILE (sslkeys.log) to decrypt TLS application data streams in real time.",
      "Applied display filters (tls, tcp.srcport == 443, len > 1024) to isolate decrypted HTTP/2 headers and extract sensitive payload artifacts."
    ],
    pipeline: "Raw PCAPNG Capture (tls_capture_1.pcapng) + Pre-Master Secret Log (sslkeys.log) → Wireshark TLS Dissector → Decrypted HTTP Headers & Payload Extraction",
    stack: ["Wireshark", "TLS 1.2 / 1.3", "SSLKEYLOGFILE", "PCAPNG Forensics", "TCP/IP Analysis"],
    snippets: [
      {
        filename: "wireshark-display-filters.txt",
        lang: "text",
        code: `# Isolate TLS handshake & encrypted frames on port 443
tls or ssl
tcp.srcport == 443 or udp.srcport == 443

# Filter large payload frames (> 1024 bytes)
frame.len > 1024

# Inspect decrypted HTTP request/response streams after loading sslkeys.log
http or http2`
      }
    ],
    logs: [
      {
        title: "Decrypting Ephemeral Diffie-Hellman (ECDHE) TLS Sessions",
        detail: "Modern TLS sessions use ephemeral key exchange (Forward Secrecy), meaning static server private keys cannot decrypt captured PCAPs. Loaded the session pre-master secrets (CLIENT_RANDOM) from sslkeys.log under Edit -> Preferences -> Protocols -> TLS to reconstruct decrypted HTTP streams."
      }
    ]
  },
  {
    id: "PROJ-07",
    category: 1,
    categoryName: "Cybersecurity, Networking & Academic Projects",
    subjectBadge: "AI & Cybersecurity",
    visibility: "Private Academic Repo",
    title: "Multivariate Gaussian Network Anomaly & NSL-KDD Intrusion Detection",
    repoUrl: "https://github.com/keithputhoor/AI-and-Cybersecurity-Portfolio/tree/main/labs/Lab-06-Gaussian-Network-Anomaly-Detection",
    overview: "Unsupervised statistical network anomaly detection and supervised multi-class intrusion detection on network traffic telemetry (network-logs.csv and the NSL-KDD benchmark dataset).",
    highlights: [
      "Modeled baseline network throughput and latency distributions using Multivariate Gaussian density estimation (μ, σ²) to flag anomalous sessions where p(x) < ε.",
      "Trained and evaluated multi-class classifiers on the NSL-KDD dataset (Labs 9–10) to distinguish normal traffic from DoS, Probe, R2L, and U2R attack vectors.",
      "Compared Support Vector Machines (SVM), Perceptrons, and Decision Trees across cybersecurity datasets."
    ],
    pipeline: "Network Telemetry (network-logs.csv / NSL-KDD) → Feature Normalization & Gaussian Parameter Estimation (μ, σ²) → Probability Thresholding (p(x) < ε) & Attack Classification",
    stack: ["Python 3", "NumPy", "Pandas", "Scikit-Learn", "Matplotlib", "NSL-KDD Dataset"],
    snippets: [
      {
        filename: "gaussian_anomaly_detection.py",
        lang: "python",
        code: `import numpy as np
import pandas as pd

def estimate_gaussian(X):
    """Computes the mean (mu) and variance (sigma2) of each network feature."""
    mu = np.mean(X, axis=0)
    sigma2 = np.var(X, axis=0)
    return mu, sigma2

def multivariate_gaussian(X, mu, sigma2):
    """Computes the probability density function of the multivariate Gaussian distribution."""
    k = len(mu)
    if sigma2.ndim == 1:
        sigma2 = np.diag(sigma2)
    X_centered = X - mu
    norm_const = 1.0 / ((2 * np.pi) ** (k / 2) * np.linalg.det(sigma2) ** 0.5)
    exp_term = np.exp(-0.5 * np.sum(X_centered @ np.linalg.pinv(sigma2) * X_centered, axis=1))
    return norm_const * exp_term`
      }
    ],
    logs: [
      {
        title: "Selecting Optimal Anomaly Threshold (ε) Without Over-Flagging Bursty Traffic",
        detail: "Calibrated the probability density threshold ε using validation F1-scores so legitimate bandwidth spikes were not misclassified as Denial-of-Service anomalies."
      }
    ]
  },
  {
    id: "PROJ-08",
    category: 1,
    categoryName: "Cybersecurity, Networking & Academic Projects",
    subjectBadge: "Security Labs",
    visibility: "Private Academic Repo",
    title: "ARP Cache Poisoning MITM & Burp Suite HTTP Parameter Tampering",
    repoUrl: "https://github.com/keithputhoor/Network-Security-Portfolio/tree/main/labs/Lab-04-HTTP-Request-Interception-BurpSuite",
    overview: "Practical offensive and defensive network interception labs demonstrating Layer-2 ARP cache poisoning on Ubuntu/Kali virtual networks and Layer-7 HTTP parameter manipulation using Burp Suite and Wireshark.",
    highlights: [
      "Executed bidirectional ARP spoofing between Kali Linux and an Ubuntu target VM while enabling kernel IP forwarding to inspect transit packets in Wireshark.",
      "Intercepted e-commerce HTTP POST requests in Burp Suite Proxy to demonstrate server-side price/product-ID parameter tampering vulnerabilities.",
      "Documented switch-level Dynamic ARP Inspection (DAI) and server-side input validation controls to mitigate both attack vectors."
    ],
    pipeline: "Layer-2 ARP Cache Poisoning (arpspoof + IP Forwarding) & Layer-7 Burp Suite Proxy Intercept → Wireshark PCAP Verification → DAI & Server-Side Validation Remediation",
    stack: ["Kali Linux", "Burp Suite", "Wireshark", "arpspoof", "Ubuntu VM", "PCAP Analysis"],
    snippets: [
      {
        filename: "arp-mitm-commands.sh",
        lang: "bash",
        code: `# 1. Inspect baseline ARP table and interfaces before MITM
ip addr
arp -a

# 2. Enable kernel IPv4 packet forwarding on Kali Linux so target traffic isn't dropped
echo 1 > /proc/sys/net/ipv4/ip_forward

# 3. Poison target and gateway ARP caches simultaneously
arpspoof -i eth0 -t 10.0.2.15 10.0.2.1
arpspoof -i eth0 -t 10.0.2.1 10.0.2.15`
      }
    ],
    logs: [
      {
        title: "Preventing Target Connection Drops During ARP MITM",
        detail: "Without kernel IP forwarding (/proc/sys/net/ipv4/ip_forward = 1), poisoning the victim's ARP cache blackholes their traffic and immediately alerts the user. Enabled IP forwarding prior to launching arpspoof so packets transparently routed through the Kali interface while Wireshark captured the stream."
      }
    ]
  },
  {
    id: "PROJ-09",
    category: 1,
    categoryName: "Cybersecurity, Networking & Academic Projects",
    subjectBadge: "Python Foundations",
    visibility: "Public Repo",
    title: "Python CLI Restaurant Ordering & Menu Summary Tool",
    repoUrl: "https://github.com/keithputhoor/homelab-infrastructure-iac/tree/main/restaurant-analytics-cli",
    overview: "Foundational Python CLI project combining a customer menu-ordering interface with an admin dish-summary script backed by persistent CSV storage (orders.csv), Pandas grouping, and Matplotlib pie charts.",
    highlights: [
      "Provides a contactless customer CLI ordering flow that records itemized transactions to orders.csv using newline=\"\" to prevent blank CRLF rows on Windows.",
      "Includes an authenticated admin summary script that filters empty rows (df.dropna()), casts Quantity/Total columns to numeric types, and groups orders by course.",
      "Generates Matplotlib pie charts visualizing the most frequently ordered dishes across Starters, Main Course, Dessert, and Beverages."
    ],
    pipeline: "Customer CLI Ordering Menu → Persistent CSV Storage (orders.csv) → Admin Login Check → Pandas Course Grouping & Matplotlib Dish Popularity Charts",
    stack: ["Python 3", "CSV File I/O", "Pandas", "Matplotlib"],
    snippets: [
      {
        filename: "restaurant-analytics-cli/restaurant_analytics.py",
        lang: "python",
        code: `import csv
import os
import pandas as pd
import matplotlib.pyplot as plt

CSV_FILE = "orders.csv"

def init_db():
    if not os.path.exists(CSV_FILE):
        with open(CSV_FILE, mode="w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Customer", "Course", "Item", "Quantity", "Unit_Price", "Total"])

def admin_login():
    username = input("Admin Username: ").strip()
    password = input("Admin Password: ").strip()
    return username == "admin" and password == "admin"

def generate_course_pie_chart(course_name):
    df = pd.read_csv(CSV_FILE).dropna()
    df["Quantity"] = df["Quantity"].astype(int)
    df["Total"] = df["Total"].astype(float)
    course_df = df[df["Course"] == course_name]
    if course_df.empty:
        print(f"[INFO] No order records found for course: {course_name}")
        return

    summary = course_df.groupby("Item")["Quantity"].sum()
    plt.figure(figsize=(7, 7))
    plt.pie(
        summary.values,
        labels=summary.index,
        autopct="%1.1f%%",
        startangle=140
    )
    plt.title(f"Most Popular Dishes - {course_name}")
    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    init_db()
    if admin_login():
        for course in ["Starters", "Main Course", "Dessert", "Beverages"]:
            generate_course_pie_chart(course)
    else:
        print("[ACCESS DENIED] Invalid credentials.")`
      }
    ],
    logs: [
      {
        title: "Issue 1: IndexError & Empty Rows Breaking Matplotlib Pie Charts",
        detail: "Root Cause: Writing orders to orders.csv on Windows without newline=\"\" inserted blank CRLF rows between every order, crashing the admin summary parser when iterating over rows. Fix: Enforced open(\"orders.csv\", mode=\"a\", newline=\"\") across the customer ordering module and added empty-row filtering (df.dropna()) before grouping quantities."
      },
      {
        title: "Issue 2: Schema Mismatch During Multi-Module Compilation",
        detail: "Root Cause: Combining the customer ordering menu with the admin login and summary script caused string-concatenation bugs instead of numeric addition when totaling dish quantities. Fix: Explicitly cast the Quantity and Total columns to int/float and standardized the course labels (Starters, Main Course, Dessert, Beverages) so matplotlib.pyplot.pie() rendered accurate percentages."
      }
    ]
  },
  {
    id: "PROJ-10",
    category: 2,
    categoryName: "Homelab, Self-Hosting & Communications",
    subjectBadge: "Proxmox VE & Debian",
    visibility: "Public Repo",
    title: "Proxmox VE Virtualization, Multi-Drive Storage & Media Stack",
    repoUrl: "https://github.com/keithputhoor/homelab-infrastructure-iac/tree/main/proxmox-media-stack",
    overview: "Bare-metal Proxmox VE virtualization environment running isolated Debian Linux VMs and unprivileged LXC containers. Pools Drive 1 (1TB HDD, /mnt/pve/drive_1) and Drive 2 (4TB HDD, /mnt/pve/drive_2) via MergerFS (/mnt/storage) to orchestrate Jellyfin media streaming, automated .srt subtitle synchronization (Bazarr), Kavita document hosting, and n8n automation behind Cloudflare Zero Trust Access.",
    highlights: [
      "Combines Drive 1 (/mnt/pve/drive_1, 1TB HDD) and Drive 2 (/mnt/pve/drive_2, 4TB HDD) into a unified 5TB MergerFS pool (/mnt/storage) with use_ino enabled for instant atomic hardlinks across media_1/ and media_2/ libraries.",
      "Runs Jellyfin, Jellyseerr, Bazarr (.srt subtitle alignment on media_1/media_1.en.srt), Kavita, and n8n on Debian Linux with standardized PUID=1000 / PGID=1000 permissions.",
      "Eliminates WAN port forwarding on the router by exposing public-facing services through Cloudflare Zero Trust Tunnels (cloudflared) with OTP authentication."
    ],
    pipeline: "Proxmox VE Host (Drive 1 [1TB] + Drive 2 [4TB] → MergerFS /mnt/storage) → Unprivileged LXC Bind Mount (mp0) → Docker Compose (Jellyfin, Bazarr Subtitles, Kavita, n8n) → Cloudflare Zero Trust Access",
    stack: ["Proxmox VE", "Debian Linux", "MergerFS", "Docker Compose", "Cloudflare Zero Trust", "LXC"],
    snippets: [
      {
        filename: "proxmox-media-stack/storage-mergerfs-lxc.conf",
        lang: "conf",
        code: `# 1. /etc/fstab on Proxmox Host (UUID Mounts with 'nofail' + MergerFS Pool)
# Drive 1: 1TB HDD (/mnt/pve/drive_1)
# Drive 2: 4TB HDD (/mnt/pve/drive_2)
UUID=<DRIVE_1_1TB_UUID>  /mnt/pve/drive_1   ext4  defaults,nofail,x-systemd.device-timeout=30s  0  2
UUID=<DRIVE_2_4TB_UUID>  /mnt/pve/drive_2   ext4  defaults,nofail,x-systemd.device-timeout=30s  0  2

# MergerFS Pool combining Drive 1 (1TB) and Drive 2 (4TB) into /mnt/storage (5TB Unified)
/mnt/pve/drive_1:/mnt/pve/drive_2  /mnt/storage  fuse.mergerfs  defaults,nonempty,allow_other,use_ino,cache.files=off,moveonenospc=true,category.create=epmfs,dropcacheonclose=true,minfreespace=20G,fsname=mergerfs  0  0

# 2. /etc/pve/lxc/<CTID>.conf (LXC Container Storage Bind Mounts)
mp0: /mnt/storage,mp=/mnt/storage
# Dual-drive bind mount layout:
# mp0: /mnt/pve/drive_2,mp=/mnt/drive_2
# mp1: /mnt/pve/drive_1,mp=/mnt/drive_1

# 3. Sanitized Directory & Subtitle Layout (/mnt/storage)
# /mnt/storage/
# ├── ingest/
# │   └── media_1/
# │       ├── media_1.mp4
# │       └── media_1.en.srt
# ├── library/
# │   ├── media_1/
# │   │   ├── media_1.mp4
# │   │   └── media_1.en.srt
# │   └── media_2/
# │       ├── media_2.mkv
# │       └── media_2.en.srt
# ├── documents/
# └── nas_share/`
      },
      {
        filename: "proxmox-media-stack/docker-compose.yml",
        lang: "yaml",
        code: `version: "3.9"
services:
  jellyfin:
    image: lscr.io/linuxserver/jellyfin:latest
    container_name: jellyfin
    environment:
      - PUID=1000
      - PGID=1000
      - TZ=UTC
    volumes:
      - ./config/jellyfin:/config
      - /mnt/storage/library/media_1:/data/library/media_1
      - /mnt/storage/library/media_2:/data/library/media_2
    devices:
      - /dev/dri:/dev/dri
    ports:
      - "8096:8096"
    restart: unless-stopped

  jellyseerr:
    image: fallenbagel/jellyseerr:latest
    container_name: jellyseerr
    environment:
      - TZ=UTC
    volumes:
      - ./config/jellyseerr:/app/config
    ports:
      - "5055:5055"
    restart: unless-stopped

  bazarr:
    image: lscr.io/linuxserver/bazarr:latest
    container_name: bazarr
    environment:
      - PUID=1000
      - PGID=1000
      - TZ=UTC
    volumes:
      - ./config/bazarr:/config
      - /mnt/storage:/data
    ports:
      - "6767:6767"
    restart: unless-stopped

  kavita:
    image: jvmilazz0/kavita:latest
    container_name: kavita
    environment:
      - TZ=UTC
    volumes:
      - ./config/kavita:/kavita/config
      - /mnt/storage/documents:/documents
    ports:
      - "5000:5000"
    restart: unless-stopped

  n8n:
    image: docker.n8n.io/n8nio/n8n:latest
    container_name: n8n
    environment:
      - TZ=UTC
      - N8N_SECURE_COOKIE=false
    volumes:
      - ./config/n8n:/home/node/.n8n
      - /mnt/storage:/data
    ports:
      - "5678:5678"
    restart: unless-stopped`
      }
    ],
    logs: [
      {
        title: "Issue 1: 4TB Hard Drive (Drive 2) Failing to Register at Boot",
        detail: "Root Cause: Late SATA link initialization on the motherboard caused the 4TB hard drive (/mnt/pve/drive_2) to spin up after Proxmox had already processed early boot mounts. Fix: Configured explicit UUID mounts with nofail and x-systemd.device-timeout=30s mount delays in /etc/fstab so /mnt/pve/drive_2 mounted reliably without dropping Proxmox into emergency mode."
      },
      {
        title: "Issue 2: Jellyfin Missing Media & Container Mount Misalignment (Drive 1 vs Drive 2)",
        detail: "Root Cause: The Jellyfin LXC/Docker environment initially only had a bind mount for Drive 2 (mp0: /mnt/pve/drive_2) and lacked the mount point for the 1TB Drive 1 (mp1: /mnt/pve/drive_1), while staging files on Drive 1 and indexing into Drive 2 caused EXDEV cross-device hardlink failures. Fix: Added both /mnt/pve/drive_1 and /mnt/pve/drive_2 to /etc/pve/lxc/<CTID>.conf (and unified them via MergerFS into /mnt/storage) so media_1/media_1.mp4 and media_1/media_1.en.srt subtitle files link atomically."
      },
      {
        title: "Issue 3: Permission Denied (EACCES) Between Unprivileged LXC and Host Drives",
        detail: "Root Cause: Unprivileged LXC UID mapping (100000+) conflicted with root-owned directories on the ext4 physical drives (Drive 1 and Drive 2). Fix: Standardized container services on PUID=1000 / PGID=1000 and adjusted host directory ownership (chown -R 1000:1000 or 101000:101000 for unprivileged LXC mappings)."
      },
      {
        title: "Issue 4: Zero-Trust External Access Without Port Forwarding",
        detail: "Root Cause: Traditional router port forwarding exposes residential WAN IPs to internet scanners. Fix: Exposed Jellyseerr, Kavita, and Shelfmark under example.com subdomains via Cloudflare Zero Trust Tunnels (cloudflared) protected by Cloudflare Access OTP policies."
      }
    ]
  },
  {
    id: "PROJ-11",
    category: 2,
    categoryName: "Homelab, Self-Hosting & Communications",
    subjectBadge: "GTX 1650 Ti Mobile & LLM",
    visibility: "Public Repo",
    title: "Local AI Inference Server (GTX 1650 Ti Mobile LXC Passthrough)",
    repoUrl: "https://github.com/keithputhoor/homelab-infrastructure-iac/tree/main/local-ai-inference",
    overview: "Self-hosted, GPU-accelerated LLM inference stack running Ollama and Open WebUI inside a Proxmox VE Debian LXC container powered by an NVIDIA GeForce GTX 1650 Ti Mobile. Uses cgroup2 character device passthrough (c 195:* and c 508:* nvidia-uvm), --no-kernel-module user-space drivers, and the NVIDIA Container Toolkit to serve interactive chat and low-latency REST APIs for n8n SOC alert triage.",
    highlights: [
      "Passed the physical NVIDIA GeForce GTX 1650 Ti Mobile (/dev/nvidia0 [c 195:*] and /dev/nvidia-uvm [c 508:*]) from the Proxmox VE host into an unprivileged/nested LXC container.",
      "Installed matching NVIDIA user-space drivers inside the LXC with --no-kernel-module and configured no-cgroups = true in /etc/nvidia-container-runtime/config.toml.",
      "Configured OLLAMA_HOST=0.0.0.0:11434 and OLLAMA_KEEP_ALIVE=5m to serve both Open WebUI (WEBUI_AUTH=true) and automated n8n SOC triage workflows."
    ],
    pipeline: "Proxmox VE Host (GTX 1650 Ti Mobile: c 195:* & c 508:* udev) → LXC Bind Mounts & --no-kernel-module → NVIDIA Container Toolkit (no-cgroups=true) → Ollama (0.0.0.0:11434) & Open WebUI",
    stack: ["Proxmox VE", "GTX 1650 Ti Mobile", "Debian Bookworm", "LXC GPU Passthrough", "NVIDIA Container Toolkit", "Ollama", "Open WebUI"],
    snippets: [
      {
        filename: "local-ai-inference/lxc-gtx1650ti-passthrough.conf",
        lang: "conf",
        code: `# 1. Proxmox Host UVM Persistence (/etc/udev/rules.d/70-nvidia.rules)
KERNEL=="nvidia", RUN+="/bin/bash -c '/usr/bin/nvidia-smi -L && /bin/chmod 666 /dev/nvidia*'"
KERNEL=="nvidia_uvm", RUN+="/bin/bash -c '/usr/bin/nvidia-modprobe -c0 -u && /bin/chmod 666 /dev/nvidia-uvm*'"

# 2. GTX 1650 Ti Mobile Major Device Numbers (ls -la /dev/nvidia*)
# crw-rw-rw- 1 root root 195,   0 /dev/nvidia0
# crw-rw-rw- 1 root root 195, 255 /dev/nvidiactl
# crw-rw-rw- 1 root root 195, 254 /dev/nvidia-modeset
# crw-rw-rw- 1 root root 508,   0 /dev/nvidia-uvm
# crw-rw-rw- 1 root root 508,   1 /dev/nvidia-uvm-tools

# 3. LXC Container Configuration (/etc/pve/lxc/<CTID>.conf)
arch: amd64
features: nesting=1,keyctl=1
lxc.cgroup2.devices.allow: c 195:* rwm
lxc.cgroup2.devices.allow: c 508:* rwm
lxc.cgroup2.devices.allow: c 226:* rwm
lxc.cgroup2.devices.allow: c 10:229 rwm
lxc.mount.entry: /dev/nvidia0 dev/nvidia0 none bind,optional,create=file
lxc.mount.entry: /dev/nvidiactl dev/nvidiactl none bind,optional,create=file
lxc.mount.entry: /dev/nvidia-modeset dev/nvidia-modeset none bind,optional,create=file
lxc.mount.entry: /dev/nvidia-uvm dev/nvidia-uvm none bind,optional,create=file
lxc.mount.entry: /dev/nvidia-uvm-tools dev/nvidia-uvm-tools none bind,optional,create=file
lxc.mount.entry: /dev/dri dev/dri none bind,optional,create=dir
lxc.mount.entry: /dev/fuse dev/fuse none bind,optional,create=file

# 4. Inside LXC: Matching User-Space Driver & Docker Runtime
# ./NVIDIA-Linux-x86_64-<VERSION>.run --no-kernel-module
# nvidia-ctk runtime configure --runtime=docker
# sed -i 's/#no-cgroups = false/no-cgroups = true/g' /etc/nvidia-container-runtime/config.toml
# systemctl restart docker && nvidia-smi`
      },
      {
        filename: "local-ai-inference/docker-compose.ai.yml",
        lang: "yaml",
        code: `version: "3.8"
services:
  ollama:
    image: ollama/ollama:latest
    container_name: ollama
    ports:
      - "11434:11434"
    volumes:
      - ./ollama_data:/root/.ollama
    environment:
      - OLLAMA_HOST=0.0.0.0:11434
      - OLLAMA_KEEP_ALIVE=5m
    deploy:
      resources:
        reservations:
          devices:
            - driver: nvidia
              count: all
              capabilities: [gpu]
    restart: unless-stopped

  open-webui:
    image: ghcr.io/open-webui/open-webui:main
    container_name: open-webui
    ports:
      - "3000:8080"
    environment:
      - OLLAMA_BASE_URL=http://ollama:11434
      - WEBUI_AUTH=true
    volumes:
      - ./open-webui_data:/app/backend/data
    depends_on:
      - ollama
    restart: unless-stopped`
      }
    ],
    logs: [
      {
        title: "Issue 1: Debian Trixie Repository Conflicts Breaking NVIDIA Driver Compilation",
        detail: "Root Cause: Mixed apt repository sources between Debian trixie (testing) and Proxmox VE kernel headers (pve-headers-$(uname -r)) caused dependency conflicts when compiling the NVIDIA DKMS module on the host. Fix: Standardized /etc/apt/sources.list onto aligned Debian Bookworm and Proxmox VE No-Subscription repositories, installed matching pve-headers-$(uname -r), and compiled the host driver cleanly."
      },
      {
        title: "Issue 2: Missing /dev/nvidia-uvm Node & Major Device Number (508) Blocking CUDA in LXC",
        detail: "Root Cause: Even when /dev/nvidia0 (195) was passed through, CUDA workloads (like Ollama) fell back to CPU because /dev/nvidia-uvm (c 508:*) wasn't initialized on the host until nvidia-modprobe -c0 -u was invoked, and the LXC lacked nesting=1 and /dev/fuse. Fix: Added /etc/udev/rules.d/70-nvidia.rules to initialize nvidia-uvm at boot, enabled features: nesting=1,keyctl=1, added lxc.cgroup2.devices.allow: c 508:* rwm, and bind-mounted /dev/nvidia-uvm, /dev/nvidia-uvm-tools, /dev/nvidia-modeset, and /dev/fuse into /etc/pve/lxc/<CTID>.conf."
      },
      {
        title: "Issue 3: Driver Version Mismatch & Kernel Module Conflict Inside LXC",
        detail: "Root Cause: Running a standard apt install nvidia-driver inside the LXC attempted to build kernel modules against a shared host kernel and caused version mismatches (Failed to initialize NVML: Driver/library version mismatch). Fix: Installed the exact matching .run installer inside the LXC using --no-kernel-module and set no-cgroups = true in /etc/nvidia-container-runtime/config.toml so nested Docker containers could access the GTX 1650 Ti Mobile."
      },
      {
        title: "Issue 4: Open WebUI Connection Refused When Querying Ollama",
        detail: "Root Cause: Ollama bound exclusively to 127.0.0.1:11434 inside its container, rejecting requests from adjacent Open WebUI and n8n containers. Fix: Set OLLAMA_HOST=0.0.0.0:11434 and pointed Open WebUI to OLLAMA_BASE_URL=http://ollama:11434."
      }
    ]
  },
  {
    id: "PROJ-12",
    category: 2,
    categoryName: "Homelab, Self-Hosting & Communications",
    subjectBadge: "IoT & Zigbee Mesh",
    visibility: "Public Repo",
    title: "Smart Home Automation",
    repoUrl: "https://github.com/keithputhoor/homelab-infrastructure-iac/tree/main/smart-home-zigbee",
    overview: "Local-only Home Assistant automation stack integrated with Zigbee2MQTT, an Eclipse Mosquitto broker, and a Sonoff SLZB-06p7 PoE/LAN coordinator. Correlates Hobeian ZG-102ZM vibration sensors with mmWave human presence sensors and mains-powered micro-relay routers for zero-cloud security automation.",
    highlights: [
      "Decoupled the Zigbee radio from Proxmox USB passthrough constraints by running a Sonoff SLZB-06p7 PoE coordinator centrally over LAN TCP (tcp://<COORDINATOR_IP>:6638).",
      "Tuned the Zigbee 3.0 mesh to Channel 20 at 20 dBm transmit power and deployed mains-powered micro-relays as mesh routers to penetrate thick concrete apartment walls.",
      "Built multi-sensor state correlation in Home Assistant so vibration tamper alerts only fire when the mmWave presence sensor confirms the room is vacant."
    ],
    pipeline: "Sonoff SLZB-06p7 PoE Coordinator (tcp://<COORDINATOR_IP>:6638, Channel 20 @ 20 dBm) → Zigbee2MQTT → Eclipse Mosquitto Broker → Home Assistant Core (Hobeian ZG-102ZM Vibration + mmWave Presence Correlation)",
    stack: ["Home Assistant", "Zigbee2MQTT", "MQTT", "SLZB-06p7", "YAML Automations"],
    snippets: [
      {
        filename: "smart-home-zigbee/zigbee2mqtt/configuration.yaml",
        lang: "yaml",
        code: `# Zigbee2MQTT configuration.yaml (SLZB-06p7 Network Coordinator)
homeassistant: true
mqtt:
  base_topic: zigbee2mqtt
  server: mqtt://<MQTT_BROKER_IP>:1883
  user: mqtt_user
  password: "<MQTT_SECRET>"
serial:
  port: tcp://<COORDINATOR_IP>:6638
  baudrate: 115200
  adapter: zstack
  disable_led: false
advanced:
  network_key: GENERATE
  pan_id: GENERATE
  channel: 20
  transmit_power: 20
frontend:
  port: 8080`
      },
      {
        filename: "smart-home-zigbee/homeassistant/automations.yaml",
        lang: "yaml",
        code: `# Home Assistant Automation: Hobeian ZG-102ZM Vibration & mmWave Presence Logic
alias: "Security - Tamper & Presence Alert"
description: "Triggers alert when Hobeian ZG-102ZM detects vibration while mmWave reports room vacant"
mode: single
trigger:
  - platform: state
    entity_id: binary_sensor.hobeian_zg_102zm_vibration
    to: "on"
condition:
  - condition: state
    entity_id: binary_sensor.room_mmwave_presence
    state: "off"
action:
  - service: switch.turn_on
    target:
      entity_id: switch.custom_micro_relay_light
  - service: notify.persistent_notification
    data:
      title: "Vibration Anomaly Detected"
      message: "Hobeian ZG-102ZM triggered with no active room occupancy."`
      }
    ],
    logs: [
      {
        title: "Issue 1: Zigbee Signal Dropouts Through Thick Concrete Apartment Walls",
        detail: "Root Cause: High signal attenuation across thick interior concrete walls caused battery-powered end devices (like the Hobeian ZG-102ZM vibration sensor) to drop off the mesh. Fix: Deployed the Sonoff SLZB-06p7 Ethernet/PoE coordinator positioned centrally over LAN (tcp://<COORDINATOR_IP>:6638), boosted transmit power to 20 dBm, switched to Zigbee Channel 20 (avoiding 2.4GHz Wi-Fi interference), and used mains-powered micro-relays as Zigbee mesh routers."
      },
      {
        title: "Issue 2: Hobeian ZG-102ZM Vibration Sensor False Alarms",
        detail: "Root Cause: Tuya ZG-102ZM sensors triggered on minor ambient vibrations or when someone was simply walking around the room. Fix: Calibrated sensitivity inside Zigbee2MQTT and combined the vibration trigger with an mmWave presence sensor state condition in Home Assistant so alerts only fire when vibration occurs while the room is vacant (off)."
      },
      {
        title: "Issue 3: SLZB-06p7 TCP Socket Drops & socat Watchdog",
        detail: "Root Cause: Operating the coordinator over TCP (tcp://<COORDINATOR_IP>:6638) bypasses physical USB passthrough limits in Proxmox, but brief LAN glitches can drop the serial socket. Fix: Configured explicit zstack adapter parameters and TCP keepalive/reconnection settings so Zigbee2MQTT recovers automatically without manual container restarts."
      }
    ]
  }
];

function escapeHtml(str) {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function renderCards() {
  const grid1 = document.getElementById("grid-category-1");
  const grid2 = document.getElementById("grid-category-2");

  PROJECTS.forEach((proj) => {
    const card = document.createElement("article");
    card.className = "project-card";
    card.setAttribute("tabindex", "0");
    card.setAttribute("role", "button");
    card.setAttribute("aria-label", `Inspect case study: ${proj.title}`);

    const tagsHtml = proj.stack
      .map((s) => `<span class="stack-tag">${escapeHtml(s)}</span>`)
      .join("");

    card.innerHTML = `
      <div>
        <div class="card-top">
          <span class="card-id">${escapeHtml(proj.id)}</span>
          <span class="card-subject">${escapeHtml(proj.subjectBadge)}</span>
        </div>
        <h3 class="card-title">${escapeHtml(proj.title)}</h3>
        <p style="font-size: 0.86rem; color: var(--text-secondary); margin-bottom: 0.85rem;">${escapeHtml(proj.overview)}</p>
        <div class="stack-tags">${tagsHtml}</div>
      </div>
      <div class="card-footer">
        <span>[OPEN DETAILED VIEW]</span>
        <span>${escapeHtml(proj.visibility)} &rarr;</span>
      </div>
    `;

    card.addEventListener("click", () => openModal(proj));
    card.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        openModal(proj);
      }
    });

    if (proj.category === 1) {
      grid1.appendChild(card);
    } else {
      grid2.appendChild(card);
    }
  });
}

function openModal(proj) {
  const modal = document.getElementById("case-study-modal");
  document.getElementById("modal-category").textContent = `${proj.id} // ${proj.categoryName} // ${proj.subjectBadge}`;
  document.getElementById("modal-title").textContent = proj.title;

  const repoLink = document.getElementById("modal-repo-link");
  repoLink.href = proj.repoUrl;

  const repoUrlText = document.getElementById("modal-repo-url-text");
  repoUrlText.textContent = proj.repoUrl;

  const visBadge = document.getElementById("modal-visibility-badge");
  visBadge.textContent = proj.visibility;
  visBadge.className = `visibility-badge ${proj.visibility.includes("Private") ? "private" : "public"}`;

  const highlightsHtml = (proj.highlights || [])
    .map((h) => `<li>${escapeHtml(h)}</li>`)
    .join("");

  // Section 1: Overview, Highlights & Architecture
  const archPanel = document.getElementById("tab-arch");
  archPanel.innerHTML = `
    <div class="modal-section-banner">01 // Overview &amp; Architecture</div>
    <div class="panel-section">
      <div class="panel-heading">Project Overview</div>
      <p class="overview-text">${escapeHtml(proj.overview)}</p>
      <ul class="highlights-list">${highlightsHtml}</ul>
    </div>
    <div class="panel-section">
      <div class="panel-heading">Data &amp; Control Pipeline</div>
      <div class="pipeline-box">${escapeHtml(proj.pipeline)}</div>
    </div>
    <div class="panel-section" style="margin-bottom: 0;">
      <div class="panel-heading">Technology Stack &amp; Components</div>
      <div class="stack-tags">
        ${proj.stack.map((s) => `<span class="stack-tag">${escapeHtml(s)}</span>`).join("")}
      </div>
    </div>
  `;

  // Section 2: Code & Configuration
  const codePanel = document.getElementById("tab-code");
  codePanel.innerHTML =
    `<div class="modal-section-banner">02 // Code &amp; Configuration</div>` +
    proj.snippets
      .map(
        (snip, idx) => `
      <div class="code-block-wrapper">
        <div class="code-block-header">
          <span>${escapeHtml(snip.filename)}</span>
          <button class="copy-btn" data-copy-idx="${idx}">Copy Snippet</button>
        </div>
        <pre class="code-content"><code>${escapeHtml(snip.code)}</code></pre>
      </div>
    `
      )
      .join("");

  codePanel.querySelectorAll(".copy-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const idx = Number(btn.getAttribute("data-copy-idx"));
      navigator.clipboard.writeText(proj.snippets[idx].code).then(() => {
        const orig = btn.textContent;
        btn.textContent = "Copied ✓";
        setTimeout(() => (btn.textContent = orig), 1600);
      });
    });
  });

  // Section 3: Engineering & Troubleshooting Log
  const logsPanel = document.getElementById("tab-logs");
  logsPanel.innerHTML =
    `<div class="modal-section-banner">03 // Engineering &amp; Troubleshooting Log</div>` +
    proj.logs
      .map(
        (log) => `
      <div class="log-card">
        <div class="log-title">${escapeHtml(log.title)}</div>
        <div class="log-desc">${escapeHtml(log.detail)}</div>
      </div>
    `
      )
      .join("");

  modal.classList.add("open");
  modal.setAttribute("aria-hidden", "false");
  document.body.style.overflow = "hidden";

  const modalBody = modal.querySelector(".modal-body");
  if (modalBody) {
    modalBody.scrollTop = 0;
  }
  setActiveTabButton("arch");
}

function closeModal() {
  const modal = document.getElementById("case-study-modal");
  modal.classList.remove("open");
  modal.setAttribute("aria-hidden", "true");
  document.body.style.overflow = "";
}

let isProgrammaticScroll = false;
let scrollLockTimer = null;

function setActiveTabButton(tabKey) {
  document.querySelectorAll(".tab-btn").forEach((btn) => {
    const active = btn.getAttribute("data-tab") === tabKey;
    btn.classList.toggle("active", active);
    btn.setAttribute("aria-selected", active ? "true" : "false");
  });
}

function switchTab(tabKey) {
  setActiveTabButton(tabKey);
  const modalBody = document.querySelector("#case-study-modal .modal-body");
  const targetSection = document.getElementById(`tab-${tabKey}`);
  if (!modalBody || !targetSection) return;

  isProgrammaticScroll = true;
  if (scrollLockTimer) clearTimeout(scrollLockTimer);

  const bodyRect = modalBody.getBoundingClientRect();
  const targetRect = targetSection.getBoundingClientRect();
  const offsetTop = targetRect.top - bodyRect.top + modalBody.scrollTop - 12;

  modalBody.scrollTo({
    top: Math.max(0, offsetTop),
    behavior: "smooth"
  });

  scrollLockTimer = setTimeout(() => {
    isProgrammaticScroll = false;
    updateActiveTabOnScroll();
  }, 450);
}

function updateActiveTabOnScroll() {
  if (isProgrammaticScroll) return;
  const modalBody = document.querySelector("#case-study-modal .modal-body");
  if (!modalBody) return;

  // If scrolled to the very top, highlight 01
  if (modalBody.scrollTop <= 12) {
    setActiveTabButton("arch");
    return;
  }
  // If scrolled to the very bottom, highlight 03
  if (modalBody.scrollTop + modalBody.clientHeight >= modalBody.scrollHeight - 12) {
    setActiveTabButton("logs");
    return;
  }

  const bodyRect = modalBody.getBoundingClientRect();
  const sections = [
    { key: "arch", el: document.getElementById("tab-arch") },
    { key: "code", el: document.getElementById("tab-code") },
    { key: "logs", el: document.getElementById("tab-logs") }
  ];

  let bestKey = "arch";
  let maxVisiblePx = -1;

  sections.forEach(({ key, el }) => {
    if (!el) return;
    const rect = el.getBoundingClientRect();
    const visibleTop = Math.max(rect.top, bodyRect.top);
    const visibleBottom = Math.min(rect.bottom, bodyRect.bottom);
    const visibleHeight = Math.max(0, visibleBottom - visibleTop);

    if (visibleHeight > maxVisiblePx) {
      maxVisiblePx = visibleHeight;
      bestKey = key;
    }
  });

  setActiveTabButton(bestKey);
}

document.addEventListener("DOMContentLoaded", () => {
  renderCards();

  document.getElementById("modal-close").addEventListener("click", closeModal);
  document.getElementById("modal-close-bottom").addEventListener("click", closeModal);
  document.getElementById("case-study-modal").addEventListener("click", (e) => {
    if (e.target.id === "case-study-modal") closeModal();
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeModal();
  });

  document.querySelectorAll(".tab-btn").forEach((btn) => {
    btn.addEventListener("click", () => switchTab(btn.getAttribute("data-tab")));
  });

  const modalBody = document.querySelector("#case-study-modal .modal-body");
  if (modalBody) {
    modalBody.addEventListener("scroll", updateActiveTabOnScroll, { passive: true });
  }
});
