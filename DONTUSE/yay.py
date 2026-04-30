'''
import struct
import binascii

# The raw hex string from Wireshark
hex_str = "010000003316bc69375bd5270b00000070696e6b792f6f646f6d00001500000070696e6b792f626173655f666f6f747072696e740000000082038339cfe0e83fe95082da5fe7ed3f00000000000000000000000000000000000000000000000015927f6de821d5bf6846b2cd8834ee3f"

# Convert hex string to raw bytes
raw_bytes = binascii.unhexlify(hex_str)

# In this specific packet, the floats start at byte 56
offset = 56

# Unpack 7 consecutive Little-Endian doubles ('<7d')
# 3 for Translation (x, y, z), 4 for Rotation (x, y, z, w)
values = struct.unpack('<7d', raw_bytes[offset:offset + 56])

print(f"Translation X: {values[0]:.3f} m")
print(f"Translation Y: {values[1]:.3f} m")
print(f"Rotation Z:    {values[5]:.3f}")
print(f"Rotation W:    {values[6]:.3f}")
'''
########################################################

from scapy.all import sniff, IP, UDP, Raw
import struct

# --- SETTINGS ---
INTERFACE = "wlan0"  # Ensure this is the interface viewing the robot traffic
TARGET_STRING = b"pinky/base_footprint"

def decode_live_packet(pkt):
    # 1. Ensure the packet has a raw data payload
    if pkt.haslayer(Raw):
        payload = pkt[Raw].load
        
        # 2. Check if it's an RTPS packet containing our target coordinate frame
        if payload.startswith(b'RTPS') and TARGET_STRING in payload:
            
            # 3. Find exactly where the string starts in the byte array
            string_index = payload.find(TARGET_STRING)
            
            # 4. Calculate where the floats begin.
            # "pinky/base_footprint" is 20 bytes long. 
            # In your hex analysis, there were 4 bytes of null padding (00 00 00 00) after it.
            # 20 + 4 = 24 bytes to jump forward.
            float_start = string_index + 24
            
            # 5. Ensure the packet is long enough to avoid an "out of bounds" crash
            # 7 doubles * 8 bytes each = 56 bytes needed
            if len(payload) >= float_start + 56:
                try:
                    # Unpack the 7 Little-Endian doubles ('<7d')
                    values = struct.unpack('<7d', payload[float_start : float_start + 56])
                    
                    # Extract the values
                    trans_x = values[0]
                    trans_y = values[1]
                    rot_z   = values[5]
                    rot_w   = values[6]
                    
                    # Clear the screen (optional, gives a cool dashboard effect)
                    # print("\033[H\033[J", end="") 
                    
                    print("-" * 40)
                    print("[*] LIVE ODOMETRY DECODED:")
                    print(f"    Position X: {trans_x: .4f} m")
                    print(f"    Position Y: {trans_y: .4f} m")
                    print(f"    Heading Z:  {rot_z: .4f}")
                    print(f"    Heading W:  {rot_w: .4f}")
                    
                except Exception as e:
                    print(f"[!] Decode error: {e}")

# --- START UP ---
print(f"[*] Starting live ROS2 decoding on {INTERFACE}...")
print("[*] Waiting for robot movement data... (Press Ctrl+C to stop)")

# Start sniffing! 
# store=0 ensures the Pi doesn't run out of RAM by saving old packets.

sniff(iface=INTERFACE, filter="udp", prn=decode_live_packet, store=0)
#sniff(offline="mitm_capture_stopped.pcap", prn=decode_live_packet, store=0)

'''

'''