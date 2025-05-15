import scapy.all as scapy
from scapy.layers.inet import IP, ICMP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.layers.sctp import SCTP

def icmp_ping(target):
    packet = IP(dst=target)/ICMP()
    response = scapy.sr1(packet, timeout=2, verbose=False)
    if response:
        print(f"Host {target} is up.")
    else:
        print(f"Host {target} is down.")

def tcp_ack_ping(target):
    packet = IP(dst=target)/TCP(dport=80, flags="A")
    response = scapy.sr1(packet, timeout=2, verbose=False)
    if response:
        print(f"Host {target} is up.")
    else:
        print(f"Host {target} is down.")

def sctp_init_ping(target):
    packet = IP(dst=target)/SCTP()
    response = scapy.sr1(packet, timeout=2, verbose=False)
    if response:
        print(f"Host {target} is up.")
    else:
        print(f"Host {target} is down.")

def icmp_timestamp_ping(target):
    packet = IP(dst=target)/ICMP(type=13)
    response = scapy.sr1(packet, timeout=2, verbose=False)
    if response:
        print(f"Host {target} responded to ICMP Timestamp Request.")

def icmp_address_mask_ping(target):
    packet = IP(dst=target)/ICMP(type=17)
    response = scapy.sr1(packet, timeout=2, verbose=False)
    if response:
        print(f"Host {target} responded to ICMP Address Mask Request.")

def arp_ping(target):
    arp_request = ARP(pdst=target)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp_request
    answered = scapy.srp(packet, timeout=2, verbose=False)[0]
    for sent, received in answered:
        print(f"Host {received.psrc} is up, MAC Address: {received.hwsrc}")

def find_mac(target):
    arp_request = ARP(pdst=target)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp_request
    answered = scapy.srp(packet, timeout=2, verbose=False)[0]
    for sent, received in answered:
        print(f"MAC Address of {received.psrc} is {received.hwsrc}")

def os_detection(target):
    packet = IP(dst=target)/ICMP()
    response = scapy.sr1(packet, timeout=2, verbose=False)
    if response:
        ttl = response.ttl
        if ttl <= 64:
            print(f"Host {target} is likely running Linux/Unix (TTL: {ttl})")
        else:
            print(f"Host {target} is likely running Windows (TTL: {ttl})")

def tcp_connect_scan(target, port):
    packet = IP(dst=target)/TCP(dport=port, flags="S")
    response = scapy.sr1(packet, timeout=2, verbose=False)
    if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
        print(f"Port {port} is open on {target}.")
    else:
        print(f"Port {port} is closed on {target}.")

def udp_scan(target, port):
    packet = IP(dst=target)/UDP(dport=port)
    response = scapy.sr1(packet, timeout=2, verbose=False)
    if response is None:
        print(f"Port {port} is open or filtered on {target}.")
    elif response.haslayer(ICMP):
        print(f"Port {port} is closed on {target}.")

def tcp_null_scan(target, port):
    packet = IP(dst=target)/TCP(dport=port, flags="")
    scapy.sr1(packet, timeout=2, verbose=False)
    print(f"TCP Null scan on port {port} completed.")

def tcp_fin_scan(target, port):
    packet = IP(dst=target)/TCP(dport=port, flags="F")
    scapy.sr1(packet, timeout=2, verbose=False)
    print(f"TCP FIN scan on port {port} completed.")

def tcp_xmas_scan(target, port):
    packet = IP(dst=target)/TCP(dport=port, flags="FPU")
    scapy.sr1(packet, timeout=2, verbose=False)
    print(f"TCP Xmas scan on port {port} completed.")

def tcp_ack_scan(target, port):
    packet = IP(dst=target)/TCP(dport=port, flags="A")
    scapy.sr1(packet, timeout=2, verbose=False)
    print(f"TCP ACK scan on port {port} completed.")

def tcp_window_scan(target, port):
    packet = IP(dst=target)/TCP(dport=port, flags="A")
    scapy.sr1(packet, timeout=2, verbose=False)
    print(f"TCP Window scan on port {port} completed.")

def display_menu():
    print("\nNetwork Scanner Menu")
    print("Host Discovery:")
    print("1. ICMP Ping")
    print("2. TCP ACK Ping")
    print("3. SCTP Init Ping")
    print("4. ICMP Timestamp Ping")
    print("5. ICMP Address Mask Ping")
    print("6. ARP Ping")
    print("7. Find MAC Address of Victim")
    print("OS Discovery:")
    print("8. OS Detection")
    print("Port Scanning:")
    print("9. TCP Connect Scan")
    print("10. UDP Scan")
    print("11. TCP Null Scan")
    print("12. TCP FIN Scan")
    print("13. Xmas Scan")
    print("14. TCP ACK Scan")
    print("15. TCP Window Scan")
    print("18. Exit")

def main():
    while True:
        display_menu()
        try:
            choice = int(input("\nEnter your choice: "))
        except ValueError:
            print("Invalid input. Please enter a number.")
            continue
        
        if choice == 1:
            target = input("Enter the target IP: ")
            icmp_ping(target)
        elif choice == 2:
            target = input("Enter the target IP: ")
            tcp_ack_ping(target)
        elif choice == 3:
            target = input("Enter the target IP: ")
            sctp_init_ping(target)
        elif choice == 4:
            target = input("Enter the target IP: ")
            icmp_timestamp_ping(target)
        elif choice == 5:
            target = input("Enter the target IP: ")
            icmp_address_mask_ping(target)
        elif choice == 6:
            target = input("Enter the target IP: ")
            arp_ping(target)
        elif choice == 7:
            target = input("Enter the target IP: ")
            find_mac(target)
        elif choice == 8:
            target = input("Enter the target IP: ")
            os_detection(target)
        elif choice == 9:
            target = input("Enter the target IP: ")
            port = int(input("Enter the port: "))
            tcp_connect_scan(target, port)
        elif choice == 10:
            target = input("Enter the target IP: ")
            port = int(input("Enter the port: "))
            udp_scan(target, port)
        elif choice == 11:
            target = input("Enter the target IP: ")
            port = int(input("Enter the port: "))
            tcp_null_scan(target, port)
        elif choice == 12:
            target = input("Enter the target IP: ")
            port = int(input("Enter the port: "))
            tcp_fin_scan(target, port)
        elif choice == 13:
            target = input("Enter the target IP: ")
            port = int(input("Enter the port: "))
            tcp_xmas_scan(target, port)
        elif choice == 14:
            target = input("Enter the target IP: ")
            port = int(input("Enter the port: "))
            tcp_ack_scan(target, port)
        elif choice == 15:
            target = input("Enter the target IP: ")
            port = int(input("Enter the port: "))
            tcp_window_scan(target, port)
        elif choice == 18:
            print("Exiting the program.")
            break
        else:
            print("Invalid choice, please try again.")

if __name__ == "__main__":
    main()
