# Network Packet Analyzer

This Python-based **Network Packet Analyzer** allows users to capture and analyze network packets in real time. It provides detailed information about TCP, UDP, and ICMP packets and saves logs to a user-specified file for later analysis. Designed for educational purposes, this tool emphasizes ethical usage.

---

## Features

- **Protocol Filtering**:
  - Capture and analyze specific protocols: TCP, UDP, ICMP, or all at once.
- **Custom Log File**:
  - Save packet details to a log file with timestamps.
- **Real-Time Packet Details**:
  - View packet details such as source/destination IPs, ports, and flags in the terminal.
- **Extensible Design**:
  - Easily add support for other protocols.
- **Error Handling**:
  - Gracefully handles invalid inputs and interruptions.

---

## Requirements

- **Python 3.6+**
- **Scapy Library**:
  Install Scapy using:
  ```bash
  pip install scapy
  ```

---

## Usage

### 1. Clone the Repository

```bash
git clone https://github.com/Faheem-Musthafa/PRODIGY_CS_05.git
cd PRODIGY_CS_05
```

### 2. Run the Script

Run the script with administrative privileges to capture network traffic:
```bash
sudo python3 packet_analyzer.py
```

### 3. Follow Prompts

- **Specify a Log File**: Enter a name for the log file (e.g., `my_packets_log.txt`). If no name is entered, a default file (`default_packet_logs.txt`) will be used.
- **Select Protocol**:
  - `1`: TCP
  - `2`: UDP
  - `3`: ICMP
  - `4`: ALL (analyze all protocols)

Example:
```plaintext
Enter the log file name (e.g., packets_log.txt):
File name: tcp_logs.txt

Select the protocol to filter:
1. TCP
2. UDP
3. ICMP
4. ALL (Analyze all protocols)
Enter your choice (1/2/3/4): 1
```

### 4. Analyze Logs

Captured packets will be saved in the specified log file. You can open the file to view detailed information:
```bash
cat tcp_logs.txt
```

---

## Example Output

### Terminal Output:
```plaintext
Starting packet capture for protocol: TCP
Logs will be saved in: tcp_logs.txt
Press Ctrl+C to stop.

[TCP Packet Captured]
Source IP: 192.168.1.10
Destination IP: 8.8.8.8
Source Port: 56789
Destination Port: 443
Flags: S
```

### Log File (`tcp_logs.txt`):
```plaintext
[2024-11-24 12:45:20] 
[TCP Packet Captured]
Source IP: 192.168.1.10
Destination IP: 8.8.8.8
Source Port: 56789
Destination Port: 443
Flags: S
```

---

## Important Notes

1. **Run with Root Privileges**:
   Packet sniffing requires root or administrative privileges. Use `sudo` when running the script.
2. **Ethical Usage**:
   This tool is strictly for educational purposes. Ensure you have proper authorization before capturing network traffic.
3. **Supported Protocols**:
   - TCP
   - UDP
   - ICMP

---

## Future Enhancements

- Add support for additional protocols (e.g., ARP, DNS).
- Include packet statistics or summaries.
- Provide a graphical user interface (GUI) for easier use.

---

## Contributing

Contributions are welcome! To contribute:
1. Fork this repository.
2. Create a new branch (`feature/your-feature-name`).
3. Commit your changes.
4. Open a pull request.

---

## Contact

For questions or support, reach out via:
- **Email**: faheemmusthafa241@gmail.com
- **GitHub**: [Faheem-Musthafa] https://github.com/Faheem-Musthafa

---
