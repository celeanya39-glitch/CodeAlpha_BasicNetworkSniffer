from scapy.all import sniff, IP, Raw, get_if_list, show_interfaces
from datetime import datetime


common_ports = {
    20: "FTP Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS"
}


packet_count = 0
tcp_count = 0
udp_count = 0
icmp_count = 0
other_count = 0


print("\n" + "=" * 60)
print("              BASIC NETWORK SNIFFER")
print("=" * 60)

print("\nCapture Settings")
print("-" * 60)


# ---------------------------------------------------------
# SHOW AVAILABLE INTERFACES
# ---------------------------------------------------------

print("\nAvailable Network Interfaces")
print("-" * 60)

show_interfaces()

print("-" * 60)


# ---------------------------------------------------------
# SELECT INTERFACE
# ---------------------------------------------------------

while True:

    interface_choice = input(
        "\nEnter the interface name or index "
        "(for example: 16): "
    ).strip()

    if interface_choice == "16":

        selected_interface = (
            r"\Device\NPF_{C8766BE9-B1C5-4959-B6B7-D73F91F11CE1}"
        )

        print(
            "\nSelected Wi-Fi interface:"
        )

        print(
            "Intel(R) Dual Band Wireless-AC 8265"
        )

        break

    else:

        print(
            "For this computer, enter 16 to select "
            "the active Wi-Fi adapter."
        )


# ---------------------------------------------------------
# CAPTURE DURATION
# ---------------------------------------------------------

while True:

    try:

        duration = int(
            input(
                "Enter capture duration in seconds: "
            )
        )

        if duration <= 0:

            print(
                "Please enter a number greater than 0."
            )

        else:

            break

    except ValueError:

        print(
            "Invalid input. Please enter a whole number."
        )


# ---------------------------------------------------------
# PROTOCOL FILTER
# ---------------------------------------------------------

while True:

    protocol_filter = input(
        "Enter protocol (TCP/UDP/ICMP/ALL): "
    ).upper()

    if protocol_filter in [
        "TCP",
        "UDP",
        "ICMP",
        "ALL"
    ]:

        break

    print(
        "Invalid protocol. Choose TCP, UDP, ICMP, or ALL."
    )


# ---------------------------------------------------------
# PACKET SIZE FILTER
# ---------------------------------------------------------

while True:

    try:

        min_packet_size = int(
            input(
                "Enter minimum packet size in bytes "
                "(0 for all): "
            )
        )

        if min_packet_size < 0:

            print(
                "Packet size cannot be negative."
            )

        else:

            break

    except ValueError:

        print(
            "Invalid input. Please enter a whole number."
        )


# ---------------------------------------------------------
# DISPLAY SETTINGS
# ---------------------------------------------------------

print("\n" + "-" * 60)
print("Selected Settings")
print("-" * 60)

print(
    "Network interface:    "
    "Intel(R) Dual Band Wireless-AC 8265"
)

print(
    f"Capture duration:     {duration} seconds"
)

print(
    f"Protocol filter:      {protocol_filter}"
)

print(
    f"Minimum packet size:  {min_packet_size} bytes"
)

print("-" * 60)


# ---------------------------------------------------------
# OPEN LOG FILE
# ---------------------------------------------------------

try:

    log_file = open(
        "network_log.txt",
        "a",
        encoding="utf-8"
    )

except PermissionError:

    print(
        "\nERROR: Permission denied while opening "
        "network_log.txt."
    )

    exit()


# ---------------------------------------------------------
# SESSION LOG
# ---------------------------------------------------------

session_time = datetime.now().strftime(
    "%Y-%m-%d %H:%M:%S.%f"
)[:-3]


log_file.write(
    "\n" + "=" * 60 + "\n"
)

log_file.write(
    "NEW PACKET CAPTURE SESSION\n"
)

log_file.write(
    f"Started: {session_time}\n"
)

log_file.write(
    "Network Interface: "
    "Intel(R) Dual Band Wireless-AC 8265\n"
)

log_file.write(
    f"Duration: {duration} seconds\n"
)

log_file.write(
    f"Protocol Filter: {protocol_filter}\n"
)

log_file.write(
    f"Minimum Packet Size: "
    f"{min_packet_size} bytes\n"
)

log_file.write(
    "=" * 60 + "\n"
)

log_file.flush()


# ---------------------------------------------------------
# PACKET CALLBACK
# ---------------------------------------------------------

def packet_callback(packet):

    global packet_count
    global tcp_count
    global udp_count
    global icmp_count
    global other_count


    if IP not in packet:

        return


    protocol_number = packet[IP].proto


    if protocol_number == 6:

        protocol = "TCP"

    elif protocol_number == 17:

        protocol = "UDP"

    elif protocol_number == 1:

        protocol = "ICMP"

    else:

        protocol = f"Other ({protocol_number})"


    # Protocol filter

    if (
        protocol_filter != "ALL"
        and protocol != protocol_filter
    ):

        return


    # Packet size filter

    packet_length = len(packet)

    if packet_length < min_packet_size:

        return


    packet_count += 1


    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S.%f"
    )[:-3]


    source_ip = packet[IP].src

    destination_ip = packet[IP].dst


    # -----------------------------------------------------
    # PORTS
    # -----------------------------------------------------

    if packet.haslayer("TCP"):

        source_port = packet["TCP"].sport

        destination_port = packet["TCP"].dport

    elif packet.haslayer("UDP"):

        source_port = packet["UDP"].sport

        destination_port = packet["UDP"].dport

    else:

        source_port = "N/A"

        destination_port = "N/A"


    # -----------------------------------------------------
    # COUNTERS
    # -----------------------------------------------------

    if protocol == "TCP":

        tcp_count += 1

    elif protocol == "UDP":

        udp_count += 1

    elif protocol == "ICMP":

        icmp_count += 1

    else:

        other_count += 1


    # -----------------------------------------------------
    # SERVICE DETECTION
    # -----------------------------------------------------

    source_service = common_ports.get(
        source_port,
        "Unknown"
    )

    destination_service = common_ports.get(
        destination_port,
        "Unknown"
    )


    # -----------------------------------------------------
    # PAYLOAD
    # -----------------------------------------------------

    if Raw in packet:

        payload = packet[Raw].load

        try:

            payload_preview = payload[:50].decode(
                "utf-8",
                errors="replace"
            )

        except Exception:

            payload_preview = str(
                payload[:50]
            )

    else:

        payload_preview = "None"


    # -----------------------------------------------------
    # DISPLAY PACKET
    # -----------------------------------------------------

    print(f"\nPacket #{packet_count}")

    print(
        f"Time:             {timestamp}"
    )

    print(
        f"Source IP:        {source_ip}"
    )

    print(
        f"Destination IP:   {destination_ip}"
    )

    print(
        f"Protocol:         {protocol}"
    )

    print(
        f"Source Port:      {source_port} "
        f"({source_service})"
    )

    print(
        f"Destination Port: {destination_port} "
        f"({destination_service})"
    )

    print(
        f"Packet Length:    {packet_length} bytes"
    )

    print(
        f"Payload:          {payload_preview}"
    )

    print("-" * 60)


    # -----------------------------------------------------
    # SAVE TO LOG
    # -----------------------------------------------------

    log_file.write(
        f"\nPacket #{packet_count}\n"
    )

    log_file.write(
        f"Time:             {timestamp}\n"
    )

    log_file.write(
        f"Source IP:        {source_ip}\n"
    )

    log_file.write(
        f"Destination IP:   {destination_ip}\n"
    )

    log_file.write(
        f"Protocol:         {protocol}\n"
    )

    log_file.write(
        f"Source Port:      {source_port} "
        f"({source_service})\n"
    )

    log_file.write(
        f"Destination Port: {destination_port} "
        f"({destination_service})\n"
    )

    log_file.write(
        f"Packet Length:    {packet_length} bytes\n"
    )

    log_file.write(
        f"Payload:          {payload_preview}\n"
    )

    log_file.write(
        "-" * 60 + "\n"
    )

    log_file.flush()


# ---------------------------------------------------------
# START CAPTURE
# ---------------------------------------------------------

print("\n" + "=" * 60)
print("              CAPTURE STARTED")
print("=" * 60)

print(
    f"Running for {duration} seconds..."
)

print(
    "Interface: Intel(R) Dual Band Wireless-AC 8265"
)

print(
    "Press Ctrl + C only if you need to stop manually."
)

print()


try:

    sniff(
        iface=selected_interface,
        prn=packet_callback,
        timeout=duration
    )


except PermissionError:

    print(
        "\nERROR: Permission denied."
    )

    print(
        "Try running PowerShell as Administrator."
    )


except Exception as error:

    print(
        f"\nERROR during packet capture: {error}"
    )


# ---------------------------------------------------------
# SUMMARY
# ---------------------------------------------------------

log_file.write(
    "\n\n========== Capture Summary ==========\n"
)

log_file.write(
    f"TCP packets:   {tcp_count}\n"
)

log_file.write(
    f"UDP packets:   {udp_count}\n"
)

log_file.write(
    f"ICMP packets:  {icmp_count}\n"
)

log_file.write(
    f"Other packets: {other_count}\n"
)

log_file.write(
    f"Total packets: {packet_count}\n"
)

log_file.write(
    "=====================================\n"
)

log_file.close()


print("\n" + "=" * 60)
print("              CAPTURE COMPLETE")
print("=" * 60)

print(
    f"TCP packets:   {tcp_count}"
)

print(
    f"UDP packets:   {udp_count}"
)

print(
    f"ICMP packets:  {icmp_count}"
)

print(
    f"Other packets: {other_count}"
)

print(
    f"Total packets: {packet_count}"
)

print("=" * 60)

print(
    "\nPacket information saved to network_log.txt"
)