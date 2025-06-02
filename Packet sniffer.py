from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, wrpcap
import os

print("Current working directory:", os.getcwd())
captured_packets = []  # List to store packets for saving

def process_packet(packet):
    captured_packets.append(packet)  # Save packet to list

    print("="*60)
    if IP in packet:
        ip_data = packet[IP]
        print(f"[IP]{ip_data.src} --> {ip_data.dst}")

        if packet.haslayer(TCP):
            print("[Protocol] TCP")
        elif packet.haslayer(UDP):
            print("[Protocol] UDP")
        elif packet.haslayer(ICMP):
            print("[Protocol] ICMP")
        else:
            print("[Protocol] Other")

        if packet.haslayer(Raw):
            payload = packet[Raw].load

            try:

             text = payload.decode('utf-8', errors='replace')
             print(f"[Payload]\n{text}")

             # Append payload text to file
             with open("packets_payload.txt", "a", encoding='utf-8') as f:
                 f.write(f"[IP] {ip_data.src} --> {ip_data.dst}\n")
                 f.write(f"[Protocol] {packet.lastlayer().name}\n")
                 f.write(f"[Payload]\n{text}\n")
                 f.write("="*60 + "\n\n")

            except Exception:
                   with open("packets_payload.txt", "a", encoding="utf-8") as f:
                     f.write(f"[IP] {ip_data.src} --> {ip_data.dst}\n")
                     f.write("[Payload] (Binary Data - could not decode)\n")
                     f.write("="*60 + "\n\n")

    else:
        print("[Info] NON-IP Packet")

print("🔍 Starting packet capture.. Press CTRL+C to stop.")

try:
    sniff(filter="ip", prn=process_packet, store=False, count=10)
except KeyboardInterrupt:
    print("\n✅ Packets saved to 'captured_packets.pcap'for packet analysis and 'packets_payload.txt'--> for readable format")

wrpcap("captured_packets.pcap", captured_packets)
print("\n✅ Packets saved to 'captured_packets.pcap' and 'packets_payload.txt'")