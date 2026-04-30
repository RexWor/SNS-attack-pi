from scapy.all import sniff
import struct

TARGET_STRING = b"pinky/base_footprint"

def decode_nuclear(pkt):
    # Cast the ENTIRE packet (headers, payload, everything) to raw bytes.
    # This completely bypasses Scapy's dissectors!
    raw_bytes = bytes(pkt)
    
    # Search the raw binary of the entire frame
    if TARGET_STRING in raw_bytes:
        print(f"\n[DEBUG] Target string found! Total frame size: {len(raw_bytes)} bytes")
        
        # Find the exact memory index of the string
        string_index = raw_bytes.find(TARGET_STRING)
        float_start = string_index + 24
        
        # Check if the packet is long enough to hold the 7 floats
        if len(raw_bytes) >= float_start + 56:
            try:
                # Unpack 7 Little-Endian doubles
                values = struct.unpack('<7d', raw_bytes[float_start : float_start + 56])
                
                print("-" * 40)
                print("[*] ODOMETRY DECODED:")
                print(f"    Position X: {values[0]: .4f} m")
                print(f"    Position Y: {values[1]: .4f} m")
                print(f"    Heading Z:  {values[5]: .4f}")
                print(f"    Heading W:  {values[6]: .4f}")
            except Exception as e:
                print(f"[!] Struct unpack error: {e}")
        else:
            print(f"[!] Error: Packet too short. Need {float_start + 56} bytes.")

# --- START UP ---
print("[*] Booting up Nuclear Decoder...")
print("[*] Reading mitm_capture.pcap...")

sniff(offline="mitm_capture_stopped.pcap", prn=decode_nuclear, store=0)

print("[*] PCAP processing complete.")