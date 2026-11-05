const PROJECTS = [
  {
    id: "PROJ-01",
    category: 1,
    categoryName: "Cybersecurity, Networking & Academic Projects",
    subjectBadge: "SOC Automation",
    title: "AI-Assisted SOC Alert Triage Pipeline",
    repoUrl: "https://github.com/keithputhoor/soc-ai-alert-triage",
    pipeline: "OPNsense (Suricata IDS) → eve.json → suricata_shipper.py (Daemon) → Tailscale / LAN HTTP POST → n8n Webhook → Local Ollama LLM → Alert Notification",
    stack: ["OPNsense (FreeBSD)", "Suricata IDS", "Python 3", "n8n", "Ollama", "Tailscale"],
    snippets: [
      {
        filename: "suricata_shipper.py",
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
        filename: "/usr/local/etc/rc.syshook.d/start/99-suricata-shipper",
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
    title: "Enterprise Vulnerability Assessment & Remediation Simulation",
    repoUrl: "https://github.com/keithputhoor/CSCI369-Ethical-Hacking",
    pipeline: "Authenticated & Unauthenticated Subnet Scanning (Tenable Nessus) → Metasploit & Wireshark Exploitation Verification → Redis & Ruby Rack Remediation → ISO/IEC 27001 Control Mapping",
    stack: ["Tenable Nessus", "Wireshark", "Metasploit", "Linux CLI", "Redis", "Ruby Rack"],
    snippets: [
      {
        filename: "/etc/redis/redis.conf (CVSS 9.8 Remediation)",
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
        filename: "remediate_verify.sh",
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
    title: "PDF Malware Detection & Behavioral Sanitization Engine",
    repoUrl: "https://github.com/keithputhoor/CSIT375-AI-and-Cybersecurity",
    pipeline: "Input PDF Stream → Static Lexical & Trailer Extraction (/JS, /OpenAction, /Acroform, xref) → Random Forest Classifier (CIC-PDF-Malware-2022) → Surgical PyPDF Content Disarm & Reconstruction (CDR)",
    stack: ["Python 3", "Scikit-Learn (Random Forest)", "PyPDF", "Pandas / NumPy", "CIC-PDF-Malware-2022"],
    snippets: [
      {
        filename: "pdf_malware_detector.py (Static Feature Extraction & CDR Sanitizer)",
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
    title: "CloudCafe Multi-Site Enterprise Network Security Architecture",
    repoUrl: "https://github.com/keithputhoor/CSCI368-Network-Security",
    pipeline: "7 Departmental 802.1Q VLANs (Dubai HQ R1) → Extended ACLs 100 & 102 → Zone-Based Policy Firewall (ZPF) → Site-to-Site IPsec VPN (ESP AES/SHA) → Abu Dhabi Branch (R3) & 802.1X RADIUS WLAN",
    stack: ["Cisco IOS", "Packet Tracer", "Site-to-Site IPsec VPN", "Zone-Based Firewall (ZPF)", "802.1X WPA2-Enterprise RADIUS", "Extended ACLs"],
    snippets: [
      {
        filename: "hq-router-r1-security.ios (Extended ACLs & ZPF Policy)",
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
    subjectBadge: "Python Foundations",
    title: "Python CLI Restaurant Ordering & Menu Summary Tool",
    repoUrl: "https://github.com/keithputhoor/homelab-infrastructure-iac/tree/main/restaurant-analytics-cli",
    pipeline: "Customer CLI Ordering Menu → Persistent CSV Storage (orders.csv) → Admin Login Check → Pandas Course Grouping & Matplotlib Dish Popularity Charts",
    stack: ["Python 3", "CSV File I/O", "Pandas", "Matplotlib"],
    snippets: [
      {
        filename: "restaurant_analytics.py",
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
    id: "PROJ-06",
    category: 2,
    categoryName: "Homelab, Self-Hosting & Communications",
    subjectBadge: "Proxmox VE & Zero Trust",
    title: "Proxmox VE Virtualization & Media Automation Stack",
    repoUrl: "https://github.com/keithputhoor/homelab-infrastructure-iac/tree/main/proxmox-media-stack",
    pipeline: "Proxmox VE Bare-Metal Hypervisor → Isolated Linux VMs & LXC Containers → Unified /mnt/media:/data Hardlink Mount → Docker Compose (*arr Stack, Jellyfin, Kavita, n8n) → Cloudflare Zero Trust Access",
    stack: ["Proxmox VE", "Debian Linux", "Docker Compose", "Cloudflare Zero Trust"],
    snippets: [
      {
        filename: "docker-compose.yml",
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
        detail: "Exposed Jellyseerr, Kavita, and Shelfmark under custom subdomains via Cloudflare Zero Trust Tunnels (cloudflared) protected by Cloudflare Access OTP policies, eliminating public WAN port exposure on the residential router."
      }
    ]
  },
  {
    id: "PROJ-07",
    category: 2,
    categoryName: "Homelab, Self-Hosting & Communications",
    subjectBadge: "GPU Passthrough & LLM",
    title: "Local AI Inference Server",
    repoUrl: "https://github.com/keithputhoor/homelab-infrastructure-iac/tree/main/local-ai-inference",
    pipeline: "Proxmox VE Host (NVIDIA GPU Passthrough /dev/nvidia*) → NVIDIA Container Toolkit → Ollama Backend (0.0.0.0:11434) → Open WebUI & n8n REST API",
    stack: ["Proxmox VE", "Docker Compose", "NVIDIA Container Toolkit", "Ollama", "Open WebUI"],
    snippets: [
      {
        filename: "docker-compose.ai.yml",
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
    id: "PROJ-08",
    category: 2,
    categoryName: "Homelab, Self-Hosting & Communications",
    subjectBadge: "IoT & Zigbee Mesh",
    title: "Smart Home Automation",
    repoUrl: "https://github.com/keithputhoor/homelab-infrastructure-iac/tree/main/smart-home-zigbee",
    pipeline: "SLZB-06p7 PoE Coordinator (tcp://<COORDINATOR_IP>:6638, Channel 20) → Zigbee2MQTT → Eclipse Mosquitto Broker → Home Assistant Core (Hobeian ZG-102ZM Vibration + mmWave Presence Correlation)",
    stack: ["Home Assistant", "Zigbee2MQTT", "MQTT", "SLZB-06p7", "YAML Automations"],
    snippets: [
      {
        filename: "zigbee2mqtt/configuration.yaml",
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
        filename: "homeassistant/automations.yaml",
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
        <div class="card-arch">${escapeHtml(proj.pipeline)}</div>
        <div class="stack-tags">${tagsHtml}</div>
      </div>
      <div class="card-footer">
        <span>[INSPECT CASE STUDY]</span>
        <span>3 TABS &rarr;</span>
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
  document.getElementById("modal-category").textContent = `${proj.id} // ${proj.categoryName}`;
  document.getElementById("modal-title").textContent = proj.title;
  const repoLink = document.getElementById("modal-repo-link");
  repoLink.href = proj.repoUrl;

  // Tab 1: Architecture & Specs
  const archPanel = document.getElementById("tab-arch");
  archPanel.innerHTML = `
    <div class="panel-section">
      <div class="panel-heading">Data &amp; Control Pipeline</div>
      <div class="pipeline-box">${escapeHtml(proj.pipeline)}</div>
    </div>
    <div class="panel-section">
      <div class="panel-heading">Technology Stack &amp; Components</div>
      <div class="stack-tags">
        ${proj.stack.map((s) => `<span class="stack-tag">${escapeHtml(s)}</span>`).join("")}
      </div>
    </div>
  `;

  // Tab 2: Code & Configuration
  const codePanel = document.getElementById("tab-code");
  codePanel.innerHTML = proj.snippets
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

  // Tab 3: Engineering & Troubleshooting Log
  const logsPanel = document.getElementById("tab-logs");
  logsPanel.innerHTML = proj.logs
    .map(
      (log) => `
      <div class="log-card">
        <div class="log-title">${escapeHtml(log.title)}</div>
        <div class="log-desc">${escapeHtml(log.detail)}</div>
      </div>
    `
    )
    .join("");

  switchTab("arch");
  modal.classList.add("open");
  modal.setAttribute("aria-hidden", "false");
  document.body.style.overflow = "hidden";
}

function closeModal() {
  const modal = document.getElementById("case-study-modal");
  modal.classList.remove("open");
  modal.setAttribute("aria-hidden", "true");
  document.body.style.overflow = "";
}

function switchTab(tabKey) {
  document.querySelectorAll(".tab-btn").forEach((btn) => {
    const active = btn.getAttribute("data-tab") === tabKey;
    btn.classList.toggle("active", active);
    btn.setAttribute("aria-selected", active ? "true" : "false");
  });
  document.querySelectorAll(".tab-panel").forEach((panel) => {
    panel.classList.toggle("active", panel.id === `tab-${tabKey}`);
  });
}

document.addEventListener("DOMContentLoaded", () => {
  renderCards();

  document.getElementById("modal-close").addEventListener("click", closeModal);
  document.getElementById("case-study-modal").addEventListener("click", (e) => {
    if (e.target.id === "case-study-modal") closeModal();
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeModal();
  });

  document.querySelectorAll(".tab-btn").forEach((btn) => {
    btn.addEventListener("click", () => switchTab(btn.getAttribute("data-tab")));
  });
});
