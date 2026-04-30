from scapy.all import sniff, IP, UDP
import struct

CONTROLLER_IP = "192.168.0.16"
WRITER_ID = b"\x00\x00\x11\x03"
MARKER = b"\x00\x01\x00\x00" # The start of the 48-byte speed data

def process_packet(pkt):
    # Only look at UDP packets coming from the Controller
    if IP in pkt and UDP in pkt and pkt[IP].src == CONTROLLER_IP:
        payload = bytes(pkt[UDP].payload)
        
        # Look for the cmd_vel Writer ID
        if WRITER_ID in payload:
            idx = payload.find(WRITER_ID)
            
            # Find the encapsulation marker that comes shortly after the ID
            marker_idx = payload.find(MARKER, idx)
            
            if marker_idx != -1:
                # The 48 bytes of data start 4 bytes after the marker
                data_start = marker_idx + 4
                data_bytes = payload[data_start : data_start + 48]
                
                if len(data_bytes) == 48:
                    vals = struct.unpack('<dddddd', data_bytes)
                    
                    # Only print if it is actively moving
                    if abs(vals[0]) > 0.001 or abs(vals[5]) > 0.001:
                        print(f"[*] LIVE MOVEMENT -> Forward: {vals[0]:.4f} m/s | Turn: {vals[5]:.4f} rad/s")

print("[*] Starting Live Monitor on wlan0...")
# Sniffing on port 7413 (Update the interface if yours is eth0 or wlan1)
sniff(iface="wlan0", filter="udp port 7413", prn=process_packet, store=False)
