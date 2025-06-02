📡 Packet Sniffer with Scapy

This is a beginner-friendly Python script that captures and analyzes IP packets on a network using the Scapy library.

🧠 Features
- Captures IP packets (TCP, UDP, ICMP)

- Shows source and destination IP addresses

- Detects protocol used (TCP, UDP, ICMP)

- Displays readable payload data (if available)

📦 Requirements
Python 3.6+
Scapy
Npcap (installed with "WinPcap API-compatible Mode")

 Important Note about Npcap:
---------------------------

Npcap is a software driver for Windows that allows programs like this
packet sniffer to capture network traffic. Windows does not allow programs
to capture packets directly for security reasons, so Npcap acts like a bridge
that gives this program permission to see network packets.

If you do not have Npcap installed, this packet sniffer will not work properly.

You can download and install Npcap from:
https://nmap.org/npcap/

Make sure to install it with the option "WinPcap API-compatible Mode" checked
for better compatibility.


🚀 How to Run
Clone this repository:
git clone https://github.com/Ayobanks/packet-sniffer.git
cd "packet sniffer"
Run the script:
python "Packet sniffer.py"
⚠️ Run your terminal as Administrator if you’re on Windows. Scapy needs permission to sniff packets.


💡 Notes
You can modify the filter="ip" to capture other protocols like "tcp" or "icmp".

The script avoids binary payloads that can't be displayed by catching decode errors.

👩🏽‍💻 Author
Bankole Ayomide
