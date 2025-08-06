from scapy.all import sniff, IP, TCP, UDP, Raw

def process_packet(packet):
    if IP in packet:
        print("\n📦 Packet:")
        print(f"  Source IP      : {packet[IP].src}")
        print(f"  Destination IP : {packet[IP].dst}")
        print(f"  Protocol       : {packet[IP].proto}")

        if TCP in packet:
            print(f"  TCP Port Src   : {packet[TCP].sport}")
            print(f"  TCP Port Dst   : {packet[TCP].dport}")
        elif UDP in packet:
            print(f"  UDP Port Src   : {packet[UDP].sport}")
            print(f"  UDP Port Dst   : {packet[UDP].dport}")

        if Raw in packet:
            try:
                payload = packet[Raw].load[:50]
                print(f"  Payload        : {payload}")
            except:
                print("  Payload        : [Unable to decode]")

print("🔴 Sniffing started... Press Ctrl+C to stop.")
sniff(filter="ip", prn=process_packet, store=False)
