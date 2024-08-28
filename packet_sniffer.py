from scapy.all import sniff, IP, TCP, UDP, Raw


# Function to process each packet
def process_packet(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        # Get IP addresses
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = "Unknown"

        # Identify protocol (TCP or UDP)
        if packet.haslayer(TCP):
            protocol = "TCP"
            print(f"TCP Packet: {ip_src}:{packet[TCP].sport} -> {ip_dst}:{packet[TCP].dport}")
        elif packet.haslayer(UDP):
            protocol = "UDP"
            print(f"UDP Packet: {ip_src}:{packet[UDP].sport} -> {ip_dst}:{packet[UDP].dport}")
        else:
            print(f"IP Packet: {ip_src} -> {ip_dst}")

        # Print the payload if available
        if Raw in packet:
            print(f"Payload: {packet[Raw].load}")
        print(f"Protocol: {protocol}")
        print("-" * 50)


# Function to start sniffing packets
def start_sniffing(interface=None):
    print("Starting packet sniffing...")
    sniff(iface=interface, prn=process_packet, store=False)


if __name__ == "__main__":
    # Replace 'eth0' with your interface (e.g., wlan0 for Wi-Fi)
    interface = "eth0"
    start_sniffing(interface)
