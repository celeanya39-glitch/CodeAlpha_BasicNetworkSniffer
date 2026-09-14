# Basic Network Sniffer

A Python-based network packet sniffer developed as part of the **CodeAlpha Cyber Security Internship**.

## Project Overview

This project is a basic network packet sniffer built with **Python and Scapy**. It captures and analyzes network traffic from a selected network interface and displays useful information about captured packets.

The sniffer can identify and record:

* Source IP address
* Destination IP address
* Network protocol
* Source port
* Destination port
* Common network services
* Packet size
* Packet payload preview
* Timestamp

Captured packet information and session statistics are also saved to a log file for later analysis.

## Features

* Capture network packets using Scapy
* Select a network interface for packet capture
* Identify TCP, UDP, and ICMP traffic
* Display source and destination IP addresses
* Display source and destination ports
* Identify common network services such as DNS, HTTP, HTTPS, SSH, and FTP
* Display packet size
* Display a limited payload preview
* Record packet timestamps
* Filter packets by protocol
* Filter packets by minimum packet size
* Select the capture duration
* Save captured information to `network_log.txt`
* Generate a capture summary
* Handle common capture and logging errors

## Technologies Used

* **Python 3**
* **Scapy**
* **Npcap**
* **Visual Studio Code**
* **Git & GitHub**

## Requirements

Before running the project, make sure you have:

* Python 3.x
* Scapy
* Npcap on Windows

The required Python package can be installed using the project's `requirements.txt` file.

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/celeanya39-glitch/CodeAlpha_BasicNetworkSniffer.git
```

### 2. Open the project directory

```bash
cd CodeAlpha_BasicNetworkSniffer
```

### 3. Install the required Python package

```bash
python -m pip install -r requirements.txt
```

### 4. Install Npcap

On Windows, Npcap is required by Scapy to capture network packets.

## How to Run

Open a terminal in the project directory and run:

```bash
python sniffer.py
```

The program will first display the available network interfaces and allow you to select an interface.

It will then ask for:

1. Capture duration in seconds
2. Protocol filter
3. Minimum packet size in bytes

Example:

```text
Enter interface number or name: 16
Enter capture duration in seconds: 10
Enter protocol (TCP/UDP/ICMP/ALL): ALL
Enter minimum packet size in bytes (0 for all): 0
```

The program will then capture packets for the selected duration.

## Protocol Filtering

The sniffer supports the following protocol filters:

| Filter | Description                      |
| ------ | -------------------------------- |
| `TCP`  | Capture TCP packets              |
| `UDP`  | Capture UDP packets              |
| `ICMP` | Capture ICMP packets             |
| `ALL`  | Capture all supported IP traffic |

Example:

```text
Enter protocol (TCP/UDP/ICMP/ALL): TCP
```

## Example Output

```text
Packet #1

Time:             2026-09-14 05:10:23.417
Source IP:        192.168.1.188
Destination IP:   104.18.41.41
Protocol:         UDP
Source Port:      55918 (Unknown)
Destination Port: 443 (HTTPS)
Packet Length:    83 bytes
Payload:          b'...'
```

The actual packets captured will vary depending on the network activity taking place during the capture session.

## Capture Summary

After the capture ends, the program displays statistics showing the number of packets captured for each protocol.

Example:

```text
Capture Summary
----------------
TCP packets:   178
UDP packets:   599
ICMP packets:  0
Other packets: 0
Total packets: 777
```

## Log File

Captured packet information is saved to:

```text
network_log.txt
```

The log contains information about accepted packets, including timestamps, IP addresses, protocols, ports, packet sizes, payload previews, and the capture summary.

## Project Structure

```text
CodeAlpha_BasicNetworkSniffer/
│
├── sniffer.py
├── requirements.txt
├── README.md
├── .gitignore
└── network_log.txt
```

> `network_log.txt` is generated when the sniffer runs and may be excluded from GitHub using `.gitignore`.

## Learning Objectives

This project was developed to gain practical experience with:

* Python programming
* Network packet capture
* Network packet analysis
* TCP, UDP, and ICMP protocols
* IP addresses and network ports
* Common network services
* Security-related logging
* Basic cybersecurity concepts
* Using Scapy for network analysis
* Using Git and GitHub for project version control

## Disclaimer

This tool is intended for **educational and authorized security testing purposes only**.

Only capture and analyze network traffic on systems and networks that you own or have explicit permission to monitor.

Do not use this tool to intercept unauthorized network traffic or sensitive information.
