#Program to capture network and analyze packet
#display relevant information such as source and destination ip addresses, protocols and payload
#first i installed the scapy library (python -m pip install scapy) on command prompt
from scapy.all import sniff, conf
from scapy.layers.inet import IP, TCP, UDP, ICMP
#This will enable the use of scapy library

conf.L3socket = conf.L3socket # Unabbles L3 socket for packet sniffing

# Function to process captured packets
def packet_callback(packet):
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = ip_layer.proto
      #Relevant information needed in captured packet eg TCP, UDP etc
        if proto == 6:
            proto_name = "TCP"
            payload = bytes(packet[TCP].payload)
        elif proto == 17:
            proto_name = "UDP"
            payload = bytes(packet[UDP].payload)
        elif proto == 1:
            proto_name = "ICMP"
            payload = bytes(packet[ICMP].payload)
        else:
            proto_name = "Other"
            payload = bytes(ip_layer.payload)
        # To diplay source ip, Destination IP,protocola and payload.
        print(f"Source IP: {src_ip}, Destination IP: {dst_ip}, Protocol: {proto_name}")
        print(f"Payload: {payload}\n")

# Start sniffing
print("Starting packet capture...")
sniff(prn=packet_callback, store=0)