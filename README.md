# Basic Network Sniffer

A Python-based network sniffer developed as part of the CodeAlpha Cyber Security Internship.

## Project Overview

This project captures and analyzes network packets using Python and the Scapy library.

The sniffer displays useful information about captured network traffic, including:

* Source IP address
* Destination IP address
* Network protocol
* Source port
* Destination port
* Common network services
* Packet size
* Packet payload preview
* Timestamp

The program also records captured packet information and capture summaries in a log file.

## Features

* Capture network packets using Scapy
* Identify TCP, UDP, and ICMP traffic
* Display source and destination IP addresses
* Display source and destination ports
* Identify common network services
* Display packet size
* Display a limited payload preview
* Record timestamps with milliseconds
* Filter packets by protocol
* Filter packets by minimum packet size
* Save captured information to `network_log.txt`
* Generate a capture summary
* Allow the user to select the capture duration

## Technologies Used

* Python
* Scapy
* Npcap
* Visual Studio Code

## Requirements

* Python 3.x
* Scapy 2.7.0
* Npcap on Windows

## Installation

Clone or download this repository.

Install the required Python package:

```bash
python -m pip install -r requirements.txt
```

## How to Run

Open a terminal in the project directory and run:

```bash
python sniffer.py
```

The program will ask for three settings:

1. Capture duration in seconds
2. Protocol filter
3. Minimum packet size

Example:

```text
Enter capture duration in seconds: 10
Enter protocol (TCP/UDP/ICMP/ALL): ALL
Enter minimum packet size in bytes (0 for all): 0
```

The program will then capture packets for the selected duration.

## Example Output

```text
Packet #1
Time:             2026-09-14 05:10:23.417
Source IP:        192.168.1.188
Destination IP:   8.8.8.8
Protocol:         UDP
Source Port:      54321 (Unknown)
Destination Port: 443 (HTTPS)
Packet Length:    125 bytes
Payload:          ...
```

## Log File

Captured packet information is saved in:

```text
network_log.txt
```

The log contains information about each accepted packet and a summary of the capture session.

## Learning Objectives

This project was developed to gain practical experience with:

* Python programming
* Network packet analysis
* TCP, UDP, and ICMP protocols
* IP addresses and network ports
* Network services
* Packet capture
* Basic cybersecurity concepts
* Security-related logging and analysis

## Disclaimer

This tool should only be used to capture and analyze network traffic on systems and networks that you own or have explicit permission to monitor.

Do not use this tool to intercept unauthorized network traffic or sensitive information.
