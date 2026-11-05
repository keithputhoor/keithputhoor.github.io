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
        title: "NIC Hardware Offloading Breaking Inspection",
        detail: "Suricata initially missed malformed packet streams and dropped throughput when inspecting traffic. Resolved by disabling Hardware CRC, Hardware TSO (TCP Segmentation Offload), and Hardware LRO (Large Receive Offload) under Interfaces -> Settings in OPNsense."
      },
      {
        title: "Daemon Persistence & Log Rotation on FreeBSD",
        detail: "Running the Python shipper interactively terminated on SSH disconnect, and Suricata log rotation broke standard file descriptors. Implemented inode tracking (os.stat().st_ino) inside the Python generator and registered an executable startup script inside /usr/local/etc/rc.syshook.d/start/ using nohup."
      },
      {
        title: "Webhook Routing Across Subnets",
        detail: "Verified packet traversal between the OPNsense BSD host and the containerized n8n endpoint over Tailscale/LAN using curl -X POST probes and local firewall floating rules."
      }
    ]
  },
  {
    id: "PROJ-02",
    category: 1,
    categoryName: "Cybersecurity, Networking & Academic Projects",
    subjectBadge: "CSCI369 Ethical Hacking",
    visibility: "Private Academic Repo",
    title: "Enterprise Vulnerability Assessment & Remediation Simulation",
    repoUrl: "https://github.com/keithputhoor/CSCI369-Ethical-Hacking/tree/main/enterprise-vulnerability-remediation",
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
        title: "Eliminating False Positives via Credentialed Scans",
        detail: "Initial unauthenticated network scans flagged patched backports on Debian/Ubuntu targets as vulnerable based solely on service banners. Configured SSH public-key authentication in Nessus to inspect local package trees (dpkg -l) and accurately filter false positives using CVSS v3 base and temporal metrics."
      },
      {
        title: "Validating Exploitability & Cleartext Exposure",
        detail: "Rather than relying strictly on automated scanner output, captured traffic in Wireshark during simulated exploitation to verify whether credentials and session payloads traversed the wire in cleartext before signing off on post-remediation verification scans."
      }
    ]
  },
  {
    id: "PROJ-03",
    category: 1,
    categoryName: "Cybersecurity, Networking & Academic Projects",
    subjectBadge: "CSIT375 AI & Cybersecurity",
    visibility: "Private Academic Repo",
    title: "PDF Malware Detection & Behavioral Sanitization Engine",
    repoUrl: "https://github.com/keithputhoor/CSIT375-AI-and-Cybersecurity/tree/main/project-pdf-malware-detection",
    overview: "A machine learning PDF malware detector and active Content Disarm & Reconstruction (CDR) sanitizer developed for CSIT375 Artificial Intelligence and Cybersecurity. Uses a 100-tree Random Forest classifier trained on CIC-PDF-Malware-2022 to score structural PDF features and automatically rebuilds high-risk PDFs without executable triggers.",
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
    subjectBadge: "CSCI368 Network Security",
    visibility: "Private Academic Repo",
    title: "CloudCafe Multi-Site Enterprise Network Security Architecture",
    repoUrl: "https://github.com/keithputhoor/CSCI368-Network-Security/tree/main/project-cloudcafe-enterprise-network",
    overview: "Full enterprise defense-in-depth network architecture designed in Cisco Packet Tracer for a multi-site organization connecting Dubai HQ (R1) and an Abu Dhabi Branch (R3) over an untrusted WAN backbone (R2).",
    highlights: [
      "Segmented HQ into 7 departmental 802.1Q VLANs (Kitchen, IT Management, Admin, Delivery, Marketing, Customer Care, and DMZ Web/DNS).",
      "Enforced Extended ACL 100 (restricting diagnostic ICMP strictly to IT workstations) and Extended ACL 102 (permitting only HTTPS TCP/443 to the DMZ Web Server).",
      "Configured a Site-to-Site IPsec VPN (ESP AES/SHA) across R1 and R3, a stateful Cisco IOS Zone-Based Policy Firewall (ZPF), and VLAN 200 WPA2-Enterprise 802.1X RADIUS wireless authentication."
    ],
    pipeline: "7 Departmental 802.1Q VLANs (Dubai HQ R1) → Extended ACLs 100 & 102 → Zone-Based Policy Firewall (ZPF) → Site-to-Site IPsec VPN (ESP AES/SHA) → Abu Dhabi Branch (R3) & 802.1X RADIUS WLAN",
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

! 3. Site-to-Site IPsec VPN (Dubai HQ R1 10.1.1.2 <-> Abu Dhabi Branch R3 10.2.2.2)
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
        detail: "Configured an IPsec ESP tunnel between Dubai HQ (R1) and the Abu Dhabi branch (R3) across intermediary router R2, paired with a stateful Zone-Based Policy Firewall (IN-2-OUT-ZPAIR) and VLAN 200 WPA2-Enterprise RADIUS authentication."
      }
    ]
  },
  {
    id: "PROJ-05",
    category: 1,
    categoryName: "Cybersecurity, Networking & Academic Projects",
    subjectBadge: "CSCI369 Ethical Hacking",
    visibility: "Private Academic Repo",
    title: "OWASP Juice Shop Web Application Penetration Test",
    repoUrl: "https://github.com/keithputhoor/CSCI369-Ethical-Hacking/tree/main/project-owasp-juiceshop-pentest",
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
    subjectBadge: "CSCI369 Ethical Hacking",
    visibility: "Private Academic Repo",
    title: "Wireshark TLS Decryption & Network Packet Forensics",
    repoUrl: "https://github.com/keithputhoor/CSCI369-Ethical-Hacking/tree/main/labs/Lab-03-Wireshark-Packet-Capture-and-TLS-Decryption",
    overview: "Deep-packet inspection and cryptographic session analysis of captured HTTPS traffic (csci369Lab3.pcap.pcapng) using Wireshark and pre-master secret key logs (sslkeys.log).",
    highlights: [
      "Analyzed TCP 3-way handshakes (SYN, SYN-ACK, ACK) and TLS Client Hello / Server Hello cipher-suite negotiation frames.",
      "Configured Wireshark TLS protocol preferences with SSLKEYLOGFILE (sslkeys.log) to decrypt TLS application data streams in real time.",
      "Applied display filters (tls, tcp.srcport == 443, len > 1024) to isolate decrypted HTTP/2 headers and extract sensitive payload artifacts."
    ],
    pipeline: "Raw PCAPNG Capture (csci369Lab3.pcap.pcapng) + Pre-Master Secret Log (sslkeys.log) → Wireshark TLS Dissector → Decrypted HTTP Headers & Payload Extraction",
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
    subjectBadge: "CSIT375 AI & Cybersecurity",
    visibility: "Private Academic Repo",
    title: "Multivariate Gaussian Network Anomaly & NSL-KDD Intrusion Detection",
    repoUrl: "https://github.com/keithputhoor/CSIT375-AI-and-Cybersecurity/tree/main/labs/Lab-06-Gaussian-Network-Anomaly-Detection",
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
    subjectBadge: "CSCI368 & CSCI369 Labs",
    visibility: "Private Academic Repo",
    title: "ARP Cache Poisoning MITM & Burp Suite HTTP Parameter Tampering",
    repoUrl: "https://github.com/keithputhoor/CSCI368-Network-Security/tree/main/labs/Lab-04-HTTP-Request-Interception-BurpSuite",
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
      "Provides a contactless customer CLI ordering flow that records itemized transactions to orders.csv.",
      "Includes an authenticated admin summary script that groups orders by course (Starters, Main Course, Dessert, Beverages) using Pandas.",
      "Generates Matplotlib pie charts visualizing the most frequently ordered dishes per course."
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
    df = pd.read_csv(CSV_FILE)
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
        title: "Merging Separate Customer & Admin CLI Modules",
        detail: "Integrated the customer ordering CLI and the admin menu-summary script by standardizing the CSV column headers (Customer, Course, Item, Quantity, Unit_Price, Total) so orders saved in the customer flow could be read directly by the summary script."
      },
      {
        title: "Fixing Windows CRLF Blank Rows in CSV Output",
        detail: "On Windows/PyCharm, opening orders.csv without newline=\"\" inserted blank lines between rows, which threw IndexError and ValueError when summing quantities. Added newline=\"\" to the CSV writer and cast Quantity values to integers before generating pie charts."
      }
    ]
  },
  {
    id: "PROJ-10",
    category: 2,
    categoryName: "Homelab, Self-Hosting & Communications",
    subjectBadge: "Proxmox VE & Debian",
    visibility: "Public Repo",
    title: "Proxmox VE Virtualization & Media Automation Stack",
    repoUrl: "https://github.com/keithputhoor/homelab-infrastructure-iac/tree/main/proxmox-media-stack",
    overview: "Bare-metal Proxmox VE virtualization environment running isolated Debian Linux VMs and unprivileged LXC containers. Orchestrates a multi-container media, digital library, and workflow automation stack via Docker Compose, secured externally through Cloudflare Zero Trust Access.",
    highlights: [
      "Runs Jellyfin, Jellyseerr, Sonarr, Radarr, Prowlarr, qBittorrent, Kavita, and n8n on Debian Linux with least-privilege PUID/PGID=1000 permissions.",
      "Uses a unified /mnt/media:/data bind-mount architecture across Proxmox and Docker so Sonarr/Radarr execute instant atomic hardlinks instead of slow I/O file copies.",
      "Eliminates WAN port forwarding on the router by exposing public-facing services through Cloudflare Zero Trust Tunnels (cloudflared) with OTP authentication."
    ],
    pipeline: "Proxmox VE Bare-Metal Hypervisor → Isolated Debian VMs & LXC Containers → Unified /mnt/media:/data Hardlink Mount → Docker Compose (*arr Stack, Jellyfin, Kavita, n8n) → Cloudflare Zero Trust Access",
    stack: ["Proxmox VE", "Debian Linux", "Docker Compose", "Cloudflare Zero Trust", "LXC"],
    snippets: [
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
      - /mnt/media/tv:/data/tvshows
      - /mnt/media/movies:/data/movies
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

  sonarr:
    image: lscr.io/linuxserver/sonarr:latest
    container_name: sonarr
    environment:
      - PUID=1000
      - PGID=1000
      - TZ=UTC
    volumes:
      - ./config/sonarr:/config
      - /mnt/media:/data
    ports:
      - "8989:8989"
    restart: unless-stopped

  radarr:
    image: lscr.io/linuxserver/radarr:latest
    container_name: radarr
    environment:
      - PUID=1000
      - PGID=1000
      - TZ=UTC
    volumes:
      - ./config/radarr:/config
      - /mnt/media:/data
    ports:
      - "7878:7878"
    restart: unless-stopped

  prowlarr:
    image: lscr.io/linuxserver/prowlarr:latest
    container_name: prowlarr
    environment:
      - PUID=1000
      - PGID=1000
      - TZ=UTC
    volumes:
      - ./config/prowlarr:/config
    ports:
      - "9696:9696"
    restart: unless-stopped

  qbittorrent:
    image: lscr.io/linuxserver/qbittorrent:latest
    container_name: qbittorrent
    environment:
      - PUID=1000
      - PGID=1000
      - TZ=UTC
      - WEBUI_PORT=8080
    volumes:
      - ./config/qbittorrent:/config
      - /mnt/media/downloads:/data/downloads
    ports:
      - "8080:8080"
      - "6881:6881"
      - "6881:6881/udp"
    restart: unless-stopped

  kavita:
    image: jvmilazz0/kavita:latest
    container_name: kavita
    environment:
      - TZ=UTC
    volumes:
      - ./config/kavita:/kavita/config
      - /mnt/media/books:/manga
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
    ports:
      - "5678:5678"
    restart: unless-stopped`
      }
    ],
    logs: [
      {
        title: "Cross-Container Hardlinks & I/O Bottlenecks",
        detail: "Separate volume mounts (/downloads vs /movies) forced Sonarr and Radarr to perform slow full-file copies instead of instant atomic moves/hardlinks, doubling disk usage. Re-architected the mount tree under a unified /mnt/media:/data parent mount with consistent PUID=1000 and PGID=1000 ownership across Proxmox bind mounts."
      },
      {
        title: "Zero-Trust External Access Without Port Forwarding",
        detail: "Exposed Jellyseerr, Kavita, and Shelfmark under example.com subdomains via Cloudflare Zero Trust Tunnels (cloudflared) protected by Cloudflare Access OTP policies, eliminating public WAN port exposure on the residential router."
      }
    ]
  },
  {
    id: "PROJ-11",
    category: 2,
    categoryName: "Homelab, Self-Hosting & Communications",
    subjectBadge: "GPU Passthrough & LLM",
    visibility: "Public Repo",
    title: "Local AI Inference Server",
    repoUrl: "https://github.com/keithputhoor/homelab-infrastructure-iac/tree/main/local-ai-inference",
    overview: "Self-hosted, GPU-accelerated LLM inference stack running Ollama and Open WebUI inside a Proxmox VE Debian environment via the NVIDIA Container Toolkit. Provides both an authenticated local chat UI and a low-latency REST API for automated n8n SOC alert triage.",
    highlights: [
      "Passed physical NVIDIA GPU character devices (/dev/nvidia*) through Proxmox VE into the Docker runtime using nvidia-container-toolkit.",
      "Configured OLLAMA_KEEP_ALIVE=5m to automatically unload model weights from VRAM after idle periods.",
      "Bound Ollama across the internal Docker bridge network while enforcing WEBUI_AUTH=true on Open WebUI."
    ],
    pipeline: "Proxmox VE Host (NVIDIA GPU Passthrough /dev/nvidia*) → NVIDIA Container Toolkit → Ollama Backend (0.0.0.0:11434) → Open WebUI & n8n REST API",
    stack: ["Proxmox VE", "Debian Linux", "Docker Compose", "NVIDIA Container Toolkit", "Ollama", "Open WebUI"],
    snippets: [
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
        title: "Proxmox GPU Device Passthrough to Containers",
        detail: "Ollama initially defaulted to slow CPU inference because /dev/nvidia* character devices were missing inside the container runtime. Configured nvidia-container-toolkit and verified lxc.cgroup2.devices.allow / device mappings so nvidia-smi properly exposed VRAM inside the container."
      },
      {
        title: "Inter-Container API Refusal (127.0.0.1 vs 0.0.0.0)",
        detail: "Open WebUI and external n8n workflows returned Connection Refused when querying Ollama. Overrode the default loopback binding by setting OLLAMA_HOST=0.0.0.0:11434 and routing Open WebUI over the internal Docker bridge (http://ollama:11434)."
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
    overview: "Local-only Home Assistant automation stack integrated with Zigbee2MQTT, an Eclipse Mosquitto broker, and an SLZB-06p7 PoE/LAN coordinator. Correlates Hobeian ZG-102ZM vibration sensors with mmWave human presence sensors for zero-cloud security automation.",
    highlights: [
      "Decoupled the Zigbee radio from Proxmox USB passthrough constraints by running an SLZB-06p7 PoE coordinator over TCP (tcp://<COORDINATOR_IP>:6638).",
      "Tuned the Zigbee 3.0 mesh to Channel 20 at 20 dBm transmit power to avoid 2.4 GHz Wi-Fi co-channel interference.",
      "Built multi-sensor state correlation in Home Assistant so vibration tamper alerts only fire when the mmWave presence sensor confirms the room is vacant."
    ],
    pipeline: "SLZB-06p7 PoE Coordinator (tcp://<COORDINATOR_IP>:6638, Channel 20) → Zigbee2MQTT → Eclipse Mosquitto Broker → Home Assistant Core (Hobeian ZG-102ZM Vibration + mmWave Presence Correlation)",
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
        title: "SLZB-06p7 TCP Socket Drops & socat Watchdog",
        detail: "Operating the coordinator over TCP (tcp://...:6638) bypasses physical USB passthrough limits in Proxmox, but brief LAN glitches can drop the serial socket. Configured explicit zstack adapter parameters and TCP keepalive/socat reconnection settings so Zigbee2MQTT recovers automatically without manual container restarts."
      },
      {
        title: "Hobeian ZG-102ZM Quirk & Sensitivity Calibration",
        detail: "Tuya-based ZG-102ZM vibration sensors frequently pair as generic unsupported devices or suffer from either missed micro-vibrations or false triggers. Exposed custom Zigbee2MQTT external converters/sensitivity attributes and paired the trigger with an mmWave presence state condition to eliminate false alarms when the room is occupied."
      },
      {
        title: "2.4GHz Wi-Fi / Zigbee Co-Channel Interference",
        detail: "Migrated the Zigbee network to Channel 20 to sit cleanly outside standard 2.4GHz Wi-Fi channels 1 and 6, preventing packet loss on low-power end devices."
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
