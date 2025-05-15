# 🛡️ Network Scanning Python Script

This project is a comprehensive **network scanning tool** written in Python using the [Scapy](https://scapy.net/) library. It features a **menu-driven interface** for performing various **host discovery**, **port scanning**, and **OS detection** techniques.

---

## 🚀 Features

### 🔍 Host Discovery
- **ICMP Ping**
- **TCP ACK Ping**
- **SCTP INIT Ping**
- **ICMP Timestamp Request**
- **ICMP Address Mask Request**
- **ARP Ping**
- **MAC Address Lookup**

### 🧠 OS Detection
- **Basic OS guessing** via TTL analysis

### ⚙️ Port Scanning
- **TCP Connect Scan**
- **UDP Scan**
- **TCP Null/FIN/Xmas Scans**
- **TCP ACK Scan**
- **TCP Window Scan**

---

## 🧪 Requirements

- Python 3.x
- [Scapy](https://scapy.net/)

### 📦 Install Dependencies

```bash
pip install scapy
🧭 How to Run

sudo python3 scanner.py
You will be presented with an interactive menu:
Network Scanner Menu
Host Discovery:
1. ICMP Ping
2. TCP ACK Ping
3. SCTP Init Ping
4. ICMP Timestamp Ping
5. ICMP Address Mask Ping
6. ARP Ping
7. Find MAC Address of Victim
OS Discovery:
8. OS Detection
Port Scanning:
9. TCP Connect Scan
10. UDP Scan
11. TCP Null Scan
12. TCP FIN Scan
13. Xmas Scan
14. TCP ACK Scan
15. TCP Window Scan
18. Exit
🧪 Example Inputs & Outputs
🔹 ICMP Ping Example

Enter your choice: 1
Enter the target IP: 192.168.1.1
Host 192.168.1.1 is up.
🔹 TCP Connect Scan Example

Enter your choice: 9
Enter the target IP: 192.168.1.10
Enter the port: 22
Port 22 is open on 192.168.1.10.
🔹 OS Detection Example

Enter your choice: 8
Enter the target IP: 192.168.1.5
Host 192.168.1.5 is likely running Linux/Unix (TTL: 64)
