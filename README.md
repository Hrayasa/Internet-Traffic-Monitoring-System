# Internet Traffic Monitoring System

A Python-based network traffic monitoring tool that captures and analyzes network packets in real-time. This project is designed to help beginners understand network traffic analysis and packet capture concepts.

## Features

- Real-time packet capture on specified network interfaces
- Basic packet information display:
  - Source and destination IP addresses
  - Protocol type (TCP, UDP, ICMP)
  - Packet size
  - Timestamp
- Real-time statistics:
  - Total packet count
  - Protocol distribution
  - Top IP addresses
  - Packets per second
- Color-coded console output for better readability

## Prerequisites

- Python 3.6 or higher
- Administrative/root privileges (required for packet capture)
- Network interface with traffic to monitor

## Installation

1. Clone this repository or download the source files.

2. Install the required Python packages:
   ```bash
   pip install -r requirements.txt
   ```

3. On Windows, you might need to install Npcap or WinPcap for packet capture functionality.

## Usage

1. Run the script with Python:
   ```bash
   python traffic_monitor.py
   ```

2. When prompted, enter the name of the network interface you want to monitor. Common interface names include:
   - Windows: "Wi-Fi", "Ethernet"
   - Linux: "eth0", "wlan0"
   - macOS: "en0", "en1"

3. The monitor will start capturing packets and displaying information in real-time.

4. To stop monitoring, press `Ctrl+C`. The script will display final statistics before exiting.

## How It Works

The traffic monitor uses the following components:

1. **Packet Capture**: Uses Scapy's `sniff()` function to capture packets on the specified interface.
2. **Packet Analysis**: Processes each captured packet to extract:
   - IP addresses
   - Protocol information
   - Packet size
   - Timestamp
3. **Statistics Tracking**: Maintains counters for:
   - Total packets
   - Protocol distribution
   - IP address frequency
4. **Display**: Shows information in a color-coded format for better readability.

## Future Enhancements

Potential improvements and features that could be added:

1. **Packet Filtering**: Add support for filtering packets by protocol, IP address, or port.
2. **Graphical Interface**: Create a GUI version using Tkinter or PyQt.
3. **Data Export**: Add functionality to export captured data to CSV or JSON files.
4. **Advanced Analysis**: Implement more detailed protocol analysis and traffic patterns.
5. **Alert System**: Add alerts for suspicious traffic patterns or high packet rates.
6. **Bandwidth Monitoring**: Track and display bandwidth usage over time.
7. **Network Mapping**: Visualize network connections and traffic flows.

## Security Note

This tool requires administrative privileges to capture network packets. Use it responsibly and only on networks you have permission to monitor.

## License

This project is open-source and available under the MIT License.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. 