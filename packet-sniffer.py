from scapy.all import sniff, Ether, IP, TCP, UDP, ARP
import sys
import os

def packet_callback(packet):
    print("\n===== New Packet Captured =====")
    
    if packet.haslayer(Ether):
        eth_layer = packet[Ether]
        print(f"Ethernet Frame: {eth_layer.src} -> {eth_layer.dst}")
    
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        print(f"IP Packet: {ip_layer.src} -> {ip_layer.dst}")

    if packet.haslayer(TCP):
        print("Protocol: TCP")
    elif packet.haslayer(UDP):
        print("Protocol: UDP")
    elif packet.haslayer(ARP):
        print("Protocol: ARP")
    else:
        print("Protocol: Other")

    # Save to log file
    with open("captured_packets_log.txt", "a") as log_file:
        log_file.write(packet.summary() + "\n")

def main():
    print("==============================")
    print("   Simple Python Packet Sniffer")
    print("==============================")

    interface = input("\nEnter the network interface to sniff on (e.g., eth0, wlan0mon): ")
    
    # Optional: filter by protocol
    apply_filter = input("\nDo you want to filter packets? (y/n): ")
    if apply_filter.lower() == 'y':
        bpf_filter = input("Enter BPF filter (e.g., tcp, udp, arp, port 80): ")
    else:
        bpf_filter = ''

    try:
        print(f"\n[*] Starting packet capture on {interface}... Press CTRL+C to stop.")
        sniff(iface=interface, prn=packet_callback, filter=bpf_filter, store=0)
    except KeyboardInterrupt:
        print("\n[*] Stopping capture. Exiting...")
        sys.exit(0)
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[!] Please run as root (sudo)!")
        sys.exit(1)
    main()
