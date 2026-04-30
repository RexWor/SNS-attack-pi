from scapy.all import sniff
import struct

INTERFACE = "wlan0"
TARGET_STRING = b"pinky/base_footprint"

def decode_live(pkt):
    raw_bytes = bytes(pkt)
    
    # Only process packets containing our target frame
    if TARGET_STRING in raw_bytes:
        string_index = raw_bytes.find(TARGET_STRING)
        float_start = string_index + 24
        
        if len(raw_bytes) >= float_start + 56:
            try:
                values = struct.unpack('<7d', raw_bytes[float_start : float_start + 56])
                print("-" * 40)
                print("[*] LIVE ODOMETRY INTERCEPTED:")
                print(f"    Position X: {values[0]: .4f} m")
                print(f"    Position Y: {values[1]: .4f} m")
            except:
                pass

print(f"[*] Sniffing live ROS2 traffic on {INTERFACE}...")
sniff(iface=INTERFACE, prn=decode_live, store=0)