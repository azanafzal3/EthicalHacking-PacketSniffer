# Packet Sniffer Tool – Ethical Hacking Concepts & Practices

## 👨‍💻 Author
**Muhammad Azan Afzal**  
**Roll Number:** 22I-1741  
**Date:** April 27, 2025  
**Course:** CS4061 – Ethical Hacking Concepts & Practices  

## 📌 Project Description
This project involves building a Python-based packet sniffer capable of capturing, analyzing, and logging network packets. It supports Ethernet and Wi-Fi interfaces, providing visibility into real-time network traffic in a controlled, ethical environment.

## 🎯 Objectives
- Build a custom packet sniffer using Python and Scapy.
- Capture broadcast, unicast, and multicast packets.
- Parse and analyze key fields at OSI layers (Ethernet, IP, TCP, UDP, ARP).
- Log captured packet information.
- Support filtering based on protocols like HTTP, DNS, ARP, etc.
- Ensure all activities are ethically confined to a test lab.

## 🧰 Technologies Used
- **Language:** Python 3
- **Library:** Scapy
- **OS:** Kali Linux
- **Modes:** Monitor Mode (Wi-Fi), Promiscuous Mode (Ethernet)

## 🛠️ System Design

### User Interface
- Command-Line Interface (CLI)
- Prompt for interface (e.g., wlan0mon, eth0)
- Optional BPF filter input

### Packet Capture Logic
- Uses `scapy.sniff()` method
- Callback function to handle each packet
- Extracts and logs source/destination MAC & IP, protocol, etc.
- Outputs to `captured_packets_log.txt`

### Error Handling
- Checks for root privileges
- Handles invalid interfaces and runtime exceptions gracefully

## 🧪 Screenshots & Testing
Testing performed on Kali Linux in a virtual lab environment.  
- Interface prompt shown at startup  
- Real-time packet capture during web traffic (e.g., example.com)
- Logged data stored in a text file

## 🔐 Ethical Considerations
- Tool used only in a personal isolated lab
- No unauthorized or public network traffic sniffed
- Adherence to legal and ethical standards

## 🚀 Future Improvements
- GUI with Tkinter or PyQt5
- HTTP session reconstruction
- Deep Packet Inspection (DPI)
- Database storage (SQL/NoSQL)
- Real-time alerts for suspicious activity
- Wireless management frame detection

## ✅ Conclusion
This tool effectively demonstrates foundational packet sniffing techniques, reinforces networking concepts, and promotes ethical cybersecurity practices. Future updates can enhance usability and analytical depth.

## 📚 References
- [Scapy Documentation](https://scapy.readthedocs.io/)
- Kurose, J. F., & Ross, K. W. (2017). *Computer Networking: A Top-Down Approach* (7th Edition). Pearson.
