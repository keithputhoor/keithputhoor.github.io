To build your GitHub portfolio (`keithputhoor.github.io`) in **Google Antigravity**, drop a `PORTFOLIO_SPEC.md` file into your workspace root and instruct the Antigravity agent to generate an interactive, technical case-study portfolio strictly from that specification.

The complete master prompt, architecture breakdown, source code, configuration snippets, and engineering troubleshooting logs for the **six exact projects** you selected are detailed below.

### Antigravity Agent Master Prompt

Paste this into the Antigravity Agent Manager (`/plan`) after saving the project details below into `PORTFOLIO_SPEC.md`:

```text
Read PORTFOLIO_SPEC.md. Build a responsive, dark-themed cybersecurity and systems engineering portfolio website for Keith Puthoor (keithputhoor.github.io / example.com).
Requirements:
1. Strict Scope: Include ONLY the 6 projects defined in PORTFOLIO_SPEC.md grouped into two categories: "Cybersecurity, Networking & Academic Projects" and "Homelab, Self-Hosting & Communications".
2. Interactive Case Studies: Each project card must open a detailed technical drawer/modal containing three tabs:
   - "Architecture & Specs"
   - "Code & Configuration" (with syntax-highlighted copyable code blocks)
   - "Engineering & Troubleshooting Log" (documenting real-world bugs resolved)
3. Aesthetic: Terminal/SOC-inspired minimalist dark UI, clean monospace accents, zero bloat, fast static load for GitHub Pages deployment.

```

## Category 1: Cybersecurity, Networking & Academic Projects

### 1. AI-Assisted SOC Alert Triage Pipeline

* **Architecture:** `OPNsense (Suricata IDS)` $\rightarrow$ `eve.json` $\rightarrow$ `suricata_shipper.py (Daemon)` $\rightarrow$ `Tailscale / LAN HTTP POST` $\rightarrow$ `n8n Webhook` $\rightarrow$ `Local Ollama LLM` $\rightarrow$ `Alert Notification`.
* **Stack:** OPNsense (FreeBSD), Suricata IDS, Python 3, n8n, Ollama, Tailscale.

**Code & Configuration (`suricata_shipper.py` & FreeBSD RC Hook):**

```python
#!/usr/local/bin/python3
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
    main()

```

```sh
# /usr/local/etc/rc.syshook.d/start/99-suricata-shipper
#!/bin/sh
nohup /usr/local/bin/python3 /root/scripts/suricata_shipper.py >/var/log/suricata_shipper.log 2>&1 &

```

**Troubleshooting & Engineering Log:**

* **NIC Hardware Offloading Breaking Inspection:** Suricata initially missed malformed packet streams and dropped throughput when inspecting traffic. Resolved by disabling **Hardware CRC**, **Hardware TSO (TCP Segmentation Offload)**, and **Hardware LRO (Large Receive Offload)** under `Interfaces -> Settings` in OPNsense.
* **Daemon Persistence & Log Rotation on FreeBSD:** Running the Python shipper interactively terminated on SSH disconnect, and Suricata log rotation broke standard file descriptors. Implemented inode tracking (`os.stat().st_ino`) inside the Python generator and registered an executable startup script inside `/usr/local/etc/rc.syshook.d/start/` using `nohup`.
* **Webhook Routing Across Subnets:** Verified packet traversal between the OPNsense BSD host and the containerized n8n endpoint over Tailscale/LAN using `curl -X POST` probes and local firewall floating rules.

### 2. Enterprise Vulnerability Assessment & Remediation Simulation

* **Architecture:** Authenticated and unauthenticated credentialed subnet scanning across isolated virtual lab targets using **Tenable Nessus**, verified with **Metasploit Framework** and **Wireshark** packet captures, mapped to **ISO/IEC 27001** controls.
* **Stack:** Tenable Nessus, Wireshark, Metasploit, Linux CLI, Redis, Ruby Rack.

**Code & Configuration (Remediation & Hardening Snippets):**

```conf
# 1. /etc/redis/redis.conf - Remediating Unprotected Redis Instance (CVSS 9.8)
# Bind strictly to loopback interface instead of 0.0.0.0
bind 127.0.0.1 -::1
protected-mode yes

# Enforce strong authentication and disable dangerous administrative commands
requirepass "<64-Char-Cryptographic-Secret>"
rename-command FLUSHALL ""
rename-command FLUSHDB ""
rename-command CONFIG "REDIS_ADMIN_CONFIG_89A1"

```

```bash
# 2. Ruby Rack Middleware Remediation & Verification Script
#!/bin/bash
# Upgrade vulnerable Rack gems to patch directory traversal / ReDoS CVEs
bundle update rack

# Verify open listening sockets and confirm Redis is no longer exposed on 0.0.0.0:6379
ss -tulnp | grep -E '6379|3000'
nmap -sV -p 6379 --script redis-info 192.168.10.0/24

```

**Troubleshooting & Engineering Log:**

* **Eliminating False Positives via Credentialed Scans:** Initial unauthenticated network scans flagged patched backports on Debian/Ubuntu targets as vulnerable based solely on service banners. Configured SSH public-key authentication in Nessus to inspect local package trees (`dpkg -l`) and accurately filter false positives using CVSS v3 base and temporal metrics.
* **Validating Exploitability & Cleartext Exposure:** Rather than relying strictly on automated scanner output, captured traffic in Wireshark during simulated exploitation to verify whether credentials and session payloads traversed the wire in cleartext before signing off on post-remediation verification scans.

### 3. Restaurant Management System with Data Analysis

* **Architecture:** Two-tier CLI application (Customer Contactless Ordering Module & Admin Analytics Module) backed by persistent CSV storage (`orders.csv`) and `matplotlib`/`pandas` aggregation for course-level popularity visualization.
* **Stack:** Python 3, Pandas, Matplotlib, CSV File I/O.

**Code & Configuration (`restaurant_analytics.py`):**

```python
import csv
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
        print("[ACCESS DENIED] Invalid credentials.")

```

**Troubleshooting & Engineering Log:**

* **Multi-Developer Module Integration:** Compiled and merged separate Customer Menu and Admin Analytics codebases written across different team environments, standardizing the CSV column schema so customer writes matched admin aggregation reads.
* **Blank Row & Type Casting Exceptions in CSV Parsing:** On Windows/PyCharm environments, standard `open()` calls without `newline=""` inserted empty CRLF lines into `orders.csv`, causing `IndexError` and `ValueError` during summation. Enforced `newline=""` on file writers and cast `Quantity` columns explicitly to integers before plotting pie charts.

## Category 2: Homelab, Self-Hosting & Communications

### 4. Proxmox VE Virtualization & Media Automation Stack

* **Architecture:** Proxmox VE bare-metal hypervisor running isolated Linux VMs and unprivileged LXC containers. Media and reading automation orchestrated via Docker Compose (`Jellyfin`, `Jellyseerr`, `Sonarr`, `Radarr`, `Prowlarr`, `qBittorrent`, `Kavita`, `Shelfmark`), integrated with `n8n` and secured externally via **Cloudflare Zero Trust Access**.
* **Stack:** Proxmox VE, Debian Linux, Docker Compose, Cloudflare Zero Trust.

**Code & Configuration (`docker-compose.yml`):**

```yaml
version: "3.9"
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
    restart: unless-stopped

```

**Troubleshooting & Engineering Log:**

* **Cross-Container Hardlinks & I/O Bottlenecks:** Separate volume mounts (`/downloads` vs `/movies`) forced Sonarr and Radarr to perform slow full-file copies instead of instant atomic moves/hardlinks, doubling disk usage. Re-architected the mount tree under a unified `/mnt/media:/data` parent mount with consistent `PUID=1000` and `PGID=1000` ownership across Proxmox bind mounts.
* **Zero-Trust External Access Without Port Forwarding:** Exposed `Jellyseerr`, `Kavita`, and `Shelfmark` under `example.com` subdomains via Cloudflare Zero Trust Tunnels (`cloudflared`) protected by Cloudflare Access OTP policies, eliminating public WAN port exposure on the residential router.

### 5. Local AI Inference Server

* **Architecture:** GPU-accelerated **Ollama** backend paired with **Open WebUI** inside a Proxmox VE environment, serving both interactive local chat and automated API endpoints for n8n and local Python pipelines.
* **Stack:** Proxmox VE, Docker Compose, NVIDIA Container Toolkit, Ollama, Open WebUI.

**Code & Configuration (`docker-compose.ai.yml`):**

```yaml
version: "3.8"
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
    restart: unless-stopped

```

**Troubleshooting & Engineering Log:**

* **Proxmox GPU Device Passthrough to Containers:** Ollama initially defaulted to slow CPU inference because `/dev/nvidia*` character devices were missing inside the container runtime. Configured `nvidia-container-toolkit` and verified `lxc.cgroup2.devices.allow` / device mappings so `nvidia-smi` properly exposed VRAM inside the container.
* **Inter-Container API Refusal (`127.0.0.1` vs `0.0.0.0`):** Open WebUI and external n8n workflows returned `Connection Refused` when querying Ollama. Overrode the default loopback binding by setting `OLLAMA_HOST=0.0.0.0:11434` and routing Open WebUI over the internal Docker bridge (`http://ollama:11434`).

### 6. Smart Home Automation

* **Architecture:** Local **Home Assistant** instance integrated with **Zigbee2MQTT** and an Eclipse Mosquitto broker, coordinating an **SLZB-06p7** PoE/LAN network coordinator, mmWave presence sensors, **Hobeian ZG-102ZM** vibration sensors, and custom micro-relays.
* **Stack:** Home Assistant, Zigbee2MQTT, MQTT, SLZB-06p7, YAML Automations.

**Code & Configuration (`configuration.yaml` & HA Automation):**

```yaml
# Zigbee2MQTT configuration.yaml (SLZB-06p7 Network Coordinator)
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
  port: 8080

```

```yaml
# Home Assistant Automation: Hobeian ZG-102ZM Vibration & mmWave Presence Logic
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
      message: "Hobeian ZG-102ZM triggered with no active room occupancy."

```

**Troubleshooting & Engineering Log:**

* **SLZB-06p7 TCP Socket Drops & `socat` Watchdog:** Operating the coordinator over TCP (`tcp://...:6638`) bypasses physical USB passthrough limits in Proxmox, but brief LAN glitches can drop the serial socket. Configured explicit `zstack` adapter parameters and TCP keepalive/socat reconnection settings so Zigbee2MQTT recovers automatically without manual container restarts.
* **Hobeian ZG-102ZM Quirk & Sensitivity Calibration:** Tuya-based ZG-102ZM vibration sensors frequently pair as generic unsupported devices or suffer from either missed micro-vibrations or false triggers. Exposed custom Zigbee2MQTT external converters/sensitivity attributes and paired the trigger with an mmWave presence state condition to eliminate false alarms when the room is occupied.
* **2.4GHz Wi-Fi / Zigbee Co-Channel Interference:** Migrated the Zigbee network to **Channel 20** to sit cleanly outside standard 2.4GHz Wi-Fi channels 1 and 6, preventing packet loss on low-power end devices.

