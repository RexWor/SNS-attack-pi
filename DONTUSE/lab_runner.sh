#!/bin/bash

# --- CONFIGURATION ---
ROBOT_IP="192.168.0.194"
CONTROLLER_IP="192.168.0.78"
QUEUE_NUM=1

# --- SAFETY CLEANUP ---
# This runs automatically when you press Ctrl+C or the script exits
cleanup() {
    echo -e "\n[!] Cleaning up lab environment..."
    # Flush the FORWARD chain to remove the NFQueue rules
    sudo iptables -F FORWARD
    # Disable IP forwarding
    sudo sysctl -w net.ipv4.ip_forward=0 > /dev/null
    echo "[*] iptables flushed and IP forwarding disabled. Network restored."
    exit 0
}
trap cleanup SIGINT SIGTERM

echo "=========================================================="
echo "          SOC LAB: HIGH-SPEED INLINE MitM                 "
echo "=========================================================="

# 1. Enable IP Forwarding
echo "[+] Enabling IP Forwarding..."
sudo sysctl -w net.ipv4.ip_forward=1 > /dev/null

# 2. Configure NetfilterQueue in iptables
echo "[+] Building iptables Netfilter queues..."
sudo iptables -I FORWARD -s "$CONTROLLER_IP" -d "$ROBOT_IP" -j NFQUEUE --queue-num "$QUEUE_NUM"
sudo iptables -I FORWARD -s "$ROBOT_IP" -d "$CONTROLLER_IP" -j NFQUEUE --queue-num "$QUEUE_NUM"

# 3. Launch the Python Interceptor
echo "[+] Launching Python Packet Manipulator..."
# Since you used apt, we can just call python3 globally with sudo
sudo python3 nfq_mitm.py

# Fallback cleanup just in case
cleanup