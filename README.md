# PRODIGY_CS_05

Packet Sniffer Tool
A simple yet powerful packet sniffer tool built using Python and Scapy.

Features
Captures network packets in real-time
Displays source and destination IP addresses
Identifies protocols (TCP, UDP, etc.)
Shows payload data for deeper inspection
Installation
First, ensure you have scapy installed. You can install it using pip:

sh
Copy code
pip install scapy
Usage
Run the script with administrative or root privileges to capture network packets:

sh
Copy code
sudo python packet_sniffer.py
Example Output
yaml
Copy code
Starting packet sniffer...
Source IP: 192.168.1.2
Destination IP: 93.184.216.34
Protocol: TCP
Payload: b'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n'

Source IP: 192.168.1.3
Destination IP: 192.168.1.1
Protocol: UDP
Payload: b'\xa1\xb2\xc3\xd4'
Code
python
Copy code
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto
        
        if TCP in packet:
            proto_name = "TCP"
        elif UDP in packet:
            proto_name = "UDP"
        else:
            proto_name = "Other"
        
        print(f"Source IP: {ip_src}")
        print(f"Destination IP: {ip_dst}")
        print(f"Protocol: {proto_name}")
        
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            print(f"Payload: {payload}")
        print("\n")

# Start sniffing
print("Starting packet sniffer...")
sniff(prn=packet_callback, store=0)
Contributing
Feel free to fork the repository, experiment with the code, and contribute to improving the tool! Your feedback and suggestions are most welcome
