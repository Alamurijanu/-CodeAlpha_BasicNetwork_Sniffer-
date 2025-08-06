from scapy.all import sniff, IP, TCP, UDP, Raw

def process_packet(packet):
    if IP in packet:
        print(f"[+] {packet[IP].src} -> {packet[IP].dst} | Protocol: {packet[IP].proto}")
        
        if TCP in packet:
            print(f"    TCP Port: {packet[TCP].sport} -> {packet[TCP].dport}")
        elif UDP in packet:
            print(f"    UDP Port: {packet[UDP].sport} -> {packet[UDP].dport}")
        
        if Raw in packet:
            print(f"    Payload: {bytes(packet[Raw].load)[:50]}")

sniff(prn=process_packet, count=10)