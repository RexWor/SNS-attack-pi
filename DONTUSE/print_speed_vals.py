import subprocess
import struct

def extract_speeds_from_hex(hex_str):
    """
    Scans a hex string for the Writer ID and extracts all movement data.
    """
    writer_id = "00001103"
    results = []
    
    # A single UDP packet might contain multiple RTPS messages
    start_pos = 0
    while True:
        idx = hex_str.find(writer_id, start_pos)
        if idx == -1:
            break
        
        # The 48 bytes of speed data starts 12 bytes (24 hex chars) after the Writer ID
        # 00001103 + 8 chars (SN) + 8 chars (Flags/Encapsulation) = 24 chars offset
        data_start = idx + 24 + 8 # +8 to skip the 00010000 encapsulation
        data_hex = hex_str[data_start : data_start + 96]
        
        if len(data_hex) == 96:
            try:
                raw_bytes = bytes.fromhex(data_hex)
                vals = struct.unpack('<dddddd', raw_bytes)
                results.append(vals)
            except:
                pass
        
        start_pos = idx + 8 # Move to next possible message
    return results

def run_analysis(file_path):
    print(f"[*] Analyzing {file_path}...")
    
    cmd = [
        "tshark", "-r", file_path,
        "-Y", "rtps.sm.wrEntityId == 0x00001103",
        "-T", "fields", "-e", "udp.payload"
    ]
    
    try:
        output = subprocess.check_output(cmd).decode('utf-8').strip().split('\n')
    except Exception as e:
        print(f"Error running tshark: {e}")
        return

    moving_packets = 0
    total_packets = len(output)

    print(f"[*] Scanned {total_packets} packets. Looking for movement...")
    print("-" * 50)

    for i, line in enumerate(output):
        all_speeds = extract_speeds_from_hex(line.replace(':', ''))
        
        for speeds in all_speeds:
            # Check if Linear X or Angular Z is non-zero
            if abs(speeds[0]) > 0.001 or abs(speeds[5]) > 0.001:
                moving_packets += 1
                if moving_packets <= 10: # Only print the first 10 moving packets
                    print(f"Packet #{i+1} (Moving):")
                    print(f"  Linear X (Forward):  {speeds[0]:.4f} m/s")
                    print(f"  Angular Z (Turning): {speeds[5]:.4f} rad/s")
                    print("-" * 30)

    if moving_packets == 0:
        print("[!] All packets were 0.0. No movement found in this specific file.")
    else:
        print(f"[*] Success! Found {moving_packets} movement packets out of {total_packets} total.")

if __name__ == "__main__":
    run_analysis("/home/kali/Documents/pcapfiles/mitm_capture_backwards.pcap")
