from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime

def log_to_file(log_file, message):
    """
    Write a message to the log file with a timestamp.
    """
    with open(log_file, "a") as file:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        file.write(f"[{timestamp}] {message}\n")

def process_tcp_packet(log_file, packet):
    """
    Process and display details for TCP packets.
    """
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    src_port = packet[TCP].sport
    dst_port = packet[TCP].dport
    flags = packet[TCP].flags

    output = f"""
[TCP Packet Captured]
Source IP: {src_ip}
Destination IP: {dst_ip}
Source Port: {src_port}
Destination Port: {dst_port}
Flags: {flags}
"""
    print(output)
    log_to_file(log_file, output)

def process_udp_packet(log_file, packet):
    """
    Process and display details for UDP packets.
    """
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    src_port = packet[UDP].sport
    dst_port = packet[UDP].dport

    output = f"""
[UDP Packet Captured]
Source IP: {src_ip}
Destination IP: {dst_ip}
Source Port: {src_port}
Destination Port: {dst_port}
"""
    print(output)
    log_to_file(log_file, output)

def process_icmp_packet(log_file, packet):
    """
    Process and display details for ICMP packets.
    """
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    icmp_type = packet[ICMP].type
    icmp_code = packet[ICMP].code

    output = f"""
[ICMP Packet Captured]
Source IP: {src_ip}
Destination IP: {dst_ip}
ICMP Type: {icmp_type}
ICMP Code: {icmp_code}
"""
    print(output)
    log_to_file(log_file, output)

def packet_callback(packet, filter_protocol, log_file):
    """
    Callback function to process packets based on the selected protocol.
    """
    if IP in packet:
        if filter_protocol == "tcp" and TCP in packet:
            process_tcp_packet(log_file, packet)
        elif filter_protocol == "udp" and UDP in packet:
            process_udp_packet(log_file, packet)
        elif filter_protocol == "icmp" and ICMP in packet:
            process_icmp_packet(log_file, packet)
        elif filter_protocol == "all":
            if TCP in packet:
                process_tcp_packet(log_file, packet)
            elif UDP in packet:
                process_udp_packet(log_file, packet)
            elif ICMP in packet:
                process_icmp_packet(log_file, packet)

def main():
    """
    Main function to allow protocol filtering and start packet sniffing.
    """
    print("Enter the log file name (e.g., packets_log.txt):")
    log_file = input("File name: ").strip()

    if not log_file:
        log_file = "default_packet_logs.txt"
        print("No file name entered. Using default: default_packet_logs.txt")

    print("\nSelect the protocol to filter:")
    print("1. TCP")
    print("2. UDP")
    print("3. ICMP")
    print("4. ALL (Analyze all protocols)")

    choice = input("Enter your choice (1/2/3/4): ").strip()

    protocol_map = {
        "1": "tcp",
        "2": "udp",
        "3": "icmp",
        "4": "all"
    }

    filter_protocol = protocol_map.get(choice, "all")

    print(f"\nStarting packet capture for protocol: {filter_protocol.upper()}")
    print(f"Logs will be saved in: {log_file}")
    print("Press Ctrl+C to stop.\n")

    try:
        # Start sniffing packets with the chosen protocol filter
        sniff(prn=lambda pkt: packet_callback(pkt, filter_protocol, log_file), store=False)
    except KeyboardInterrupt:
        print("\nPacket capture stopped.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
