#!/bin/bash
# Secure Deployment Script for Local Ollama Instance
# Author: Keith | DevSecOps Portfolio

set -e

echo "[*] Starting Secure Ollama Deployment..."

# 1. Define strict network boundaries (Example IP tables rule formulation)
ALLOWED_SUBNET="192.168.10.0/24"
OLLAMA_PORT="11434"

echo "[*] Configuring host firewall to restrict API access to $ALLOWED_SUBNET..."
# (In production, replace with ufw or firewall-cmd specifics)
# sudo iptables -A INPUT -p tcp -s $ALLOWED_SUBNET --dport $OLLAMA_PORT -j ACCEPT
# sudo iptables -A INPUT -p tcp --dport $OLLAMA_PORT -j DROP

# 2. Deploy Ollama via Docker with GPU support and resource constraints
echo "[*] Pulling and deploying Ollama Docker container..."
docker run -d \
  --gpus=all \
  -v ollama_data:/root/.ollama \
  -p 127.0.0.1:$OLLAMA_PORT:11434 \
  --name ollama_secure_node \
  --restart always \
  --pids-limit 100 \
  --security-opt no-new-privileges:true \
  ollama/ollama

# Wait for service to initialize
echo "[*] Waiting for Ollama API to initialize..."
sleep 5

# 3. Pull required models (Llama-3 for general logic, SQLCoder for internal DB queries, etc.)
echo "[*] Pulling Llama-3 model locally..."
docker exec -it ollama_secure_node ollama run llama3 --keepalive 5m

echo "[+] Deployment Complete."
echo "API is accessible locally at http://127.0.0.1:11434"
echo "Ensure reverse proxy handles authentication before exposing."
