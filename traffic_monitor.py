#!/usr/bin/env python3
"""
Internet Traffic Monitoring System
A simple network packet capture and analysis tool.
"""

import time
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP
from colorama import init, Fore, Style
from collections import defaultdict

# Initialize colorama for colored console output
init()

class TrafficMonitor:
    def __init__(self, interface):
        """
        Initialize the TrafficMonitor with the specified network interface.
        
        Args:
            interface (str): The network interface to monitor
        """
        self.interface = interface
        self.packet_count = 0
        self.protocol_stats = defaultdict(int)
        self.ip_stats = defaultdict(int)
        self.start_time = time.time()

    def packet_callback(self, packet):
        """
        Callback function that processes each captured packet.
        
        Args:
            packet: The captured network packet
        """
        self.packet_count += 1
        
        # Extract basic packet information
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto
            
            # Update protocol statistics
            if TCP in packet:
                self.protocol_stats["TCP"] += 1
            elif UDP in packet:
                self.protocol_stats["UDP"] += 1
            elif ICMP in packet:
                self.protocol_stats["ICMP"] += 1
            else:
                self.protocol_stats["Other"] += 1
            
            # Update IP statistics
            self.ip_stats[src_ip] += 1
            self.ip_stats[dst_ip] += 1
            
            # Display packet information
            self.display_packet_info(packet, src_ip, dst_ip, protocol)
            
            # Display statistics periodically
            if self.packet_count % 10 == 0:
                self.display_statistics()

    def display_packet_info(self, packet, src_ip, dst_ip, protocol):
        """
        Display information about the captured packet.
        
        Args:
            packet: The captured packet
            src_ip (str): Source IP address
            dst_ip (str): Destination IP address
            protocol (int): Protocol number
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        packet_size = len(packet)
        
        print(f"\n{Fore.CYAN}[{timestamp}]{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Source IP:{Style.RESET_ALL} {src_ip}")
        print(f"{Fore.GREEN}Destination IP:{Style.RESET_ALL} {dst_ip}")
        print(f"{Fore.GREEN}Protocol:{Style.RESET_ALL} {self.get_protocol_name(protocol)}")
        print(f"{Fore.GREEN}Packet Size:{Style.RESET_ALL} {packet_size} bytes")

    def get_protocol_name(self, protocol):
        """
        Convert protocol number to its name.
        
        Args:
            protocol (int): Protocol number
            
        Returns:
            str: Protocol name
        """
        protocol_names = {
            1: "ICMP",
            6: "TCP",
            17: "UDP"
        }
        return protocol_names.get(protocol, f"Unknown ({protocol})")

    def display_statistics(self):
        """
        Display current statistics about captured packets.
        """
        elapsed_time = time.time() - self.start_time
        print(f"\n{Fore.YELLOW}=== Statistics ==={Style.RESET_ALL}")
        print(f"{Fore.GREEN}Total Packets:{Style.RESET_ALL} {self.packet_count}")
        print(f"{Fore.GREEN}Capture Duration:{Style.RESET_ALL} {elapsed_time:.2f} seconds")
        print(f"{Fore.GREEN}Packets per Second:{Style.RESET_ALL} {self.packet_count/elapsed_time:.2f}")
        
        print(f"\n{Fore.GREEN}Protocol Distribution:{Style.RESET_ALL}")
        for protocol, count in self.protocol_stats.items():
            print(f"{protocol}: {count} packets")
        
        print(f"\n{Fore.GREEN}Top 5 IP Addresses:{Style.RESET_ALL}")
        sorted_ips = sorted(self.ip_stats.items(), key=lambda x: x[1], reverse=True)[:5]
        for ip, count in sorted_ips:
            print(f"{ip}: {count} packets")

    def start_monitoring(self):
        """
        Start capturing and monitoring network traffic.
        """
        print(f"{Fore.YELLOW}Starting traffic monitoring on interface {self.interface}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Press Ctrl+C to stop monitoring{Style.RESET_ALL}")
        
        try:
            sniff(iface=self.interface, prn=self.packet_callback, store=0)
        except KeyboardInterrupt:
            print(f"\n{Fore.RED}Monitoring stopped by user{Style.RESET_ALL}")
            self.display_statistics()

def main():
    """
    Main function to run the traffic monitor.
    """
    # Get network interface from user
    interface = input("Enter the network interface to monitor (e.g., 'eth0' or 'Wi-Fi'): ")
    
    # Create and start the traffic monitor
    monitor = TrafficMonitor(interface)
    monitor.start_monitoring()

if __name__ == "__main__":
    main() 