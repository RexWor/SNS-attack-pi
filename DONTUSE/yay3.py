import struct

TARGET_STRING = b"pinky/base_footprint"

print("[*] Booting up Bare Metal Forensic Decoder...")

try:
    # Open the file as raw binary ('rb')
    with open("mitm_capture_stopped.pcap", "rb") as f:
        content = f.read()
except FileNotFoundError:
    print("[!] mitm_capture.pcap not found in this directory.")
    exit()

print(f"[*] Loaded {len(content)} bytes of raw network data.")

# Find every occurrence of the string in the file
start_idx = 0
count = 0

while True:
    # Search for the string
    idx = content.find(TARGET_STRING, start_idx)
    if idx == -1:
        break # No more strings found
        
    # Jump 24 bytes forward to bypass the string and the null padding
    float_start = idx + 24
    
    if len(content) >= float_start + 56:
        try:
            # Unpack the 7 Little-Endian doubles
            values = struct.unpack('<7d', content[float_start : float_start + 56])
            
            print("-" * 40)
            print(f"[*] ODOMETRY CAPTURE #{count + 1} DECODED:")
            print(f"    Position X: {values[0]: .4f} m")
            print(f"    Position Y: {values[1]: .4f} m")
            print(f"    Heading Z:  {values[5]: .4f}")
            print(f"    Heading W:  {values[6]: .4f}")
            
            count += 1
        except Exception as e:
            pass
            
    # Move the search index forward so we find the next packet
    start_idx = idx + 1
    
    # Let's just print the first 5 so it doesn't flood your terminal
    if count >= 5:
        break

print(f"\n[*] Successfully extracted {count} sets of coordinates.")