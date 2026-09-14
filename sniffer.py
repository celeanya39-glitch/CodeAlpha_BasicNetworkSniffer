from scapy.all import sniff, IP, Raw
from datetime import datetime


# ==========================================
# COMMON NETWORK SERVICES
# ==========================================

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


# ==========================================
# PACKET COUNTERS
# ==========================================

packet_count = 0
tcp_count = 0
udp_count = 0
icmp_count = 0
other_count = 0


# ==========================================
# PROGRAM HEADER
# ==========================================

print("\n" + "=" * 60)
print("              BASIC NETWORK SNIFFER")
print("=" * 60)

print("\nCapture Settings")
print("-" * 60)


# ==========================================
# GET CAPTURE DURATION
# ==========================================

while True:

    try:

        duration = int(
            input("Enter capture duration in seconds: ")
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


# ==========================================
# GET PROTOCOL FILTER
# ==========================================

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

    else:

        print(
            "Invalid protocol. Choose TCP, UDP, ICMP, or ALL."
        )


# ==========================================
# GET MINIMUM PACKET SIZE
# ==========================================

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


# ==========================================
# DISPLAY SELECTED SETTINGS
# ==========================================

print("\n" + "-" * 60)
print("Selected Settings")
print("-" * 60)

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


# ==========================================
# OPEN LOG FILE
# ==========================================

log_file = open(
    "network_log.txt",
    "a",
    encoding="utf-8"
)


# ==========================================
# CREATE CAPTURE SESSION
# ==========================================

session_time = datetime.now().strftime(
    "%Y-%m-%d %H:%M:%S.%f"
)[:-3]


log_file.write("\n" + "=" * 60 + "\n")
log_file.write("NEW PACKET CAPTURE SESSION\n")
log_file.write(
    f"Started: {session_time}\n"
)
log_file.write(
    f"Duration: {duration} seconds\n"
)
log_file.write(
    f"Protocol Filter: {protocol_filter}\n"
)
log_file.write(
    f"Minimum Packet Size: {min_packet_size} bytes\n"
)
log_file.write("=" * 60 + "\n")

log_file.flush()


# ==========================================
# PACKET CALLBACK FUNCTION
# ==========================================

def packet_callback(packet):

    global packet_count
    global tcp_count
    global udp_count
    global icmp_count
    global other_count


    # Only process IP packets
    if IP in packet:

        # ----------------------------------
        # GET PROTOCOL
        # ----------------------------------

        protocol_number = packet[IP].proto


        if protocol_number == 6:

            protocol = "TCP"

        elif protocol_number == 17:

            protocol = "UDP"

        elif protocol_number == 1:

            protocol = "ICMP"

        else:

            protocol = f"Other ({protocol_number})"


        # ----------------------------------
        # APPLY PROTOCOL FILTER
        # ----------------------------------

        if (
            protocol_filter != "ALL"
            and protocol != protocol_filter
        ):

            return


        # ----------------------------------
        # GET PACKET LENGTH
        # ----------------------------------

        packet_length = len(packet)


        # ----------------------------------
        # APPLY SIZE FILTER
        # ----------------------------------

        if packet_length < min_packet_size:

            return


        # ----------------------------------
        # COUNT PACKET
        # ----------------------------------

        packet_count += 1


        # ----------------------------------
        # TIMESTAMP
        # ----------------------------------

        timestamp = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S.%f"
        )[:-3]


        # ----------------------------------
        # GET IP ADDRESSES
        # ----------------------------------

        source_ip = packet[IP].src

        destination_ip = packet[IP].dst


        # ----------------------------------
        # GET PORTS
        # ----------------------------------

        if packet.haslayer("TCP"):

            source_port = packet["TCP"].sport

            destination_port = packet["TCP"].dport

        elif packet.haslayer("UDP"):

            source_port = packet["UDP"].sport

            destination_port = packet["UDP"].dport

        else:

            source_port = "N/A"

            destination_port = "N/A"


        # ----------------------------------
        # UPDATE COUNTERS
        # ----------------------------------

        if protocol == "TCP":

            tcp_count += 1

        elif protocol == "UDP":

            udp_count += 1

        elif protocol == "ICMP":

            icmp_count += 1

        else:

            other_count += 1


        # ----------------------------------
        # IDENTIFY SERVICES
        # ----------------------------------

        source_service = common_ports.get(
            source_port,
            "Unknown"
        )

        destination_service = common_ports.get(
            destination_port,
            "Unknown"
        )


        # ----------------------------------
        # GET PAYLOAD
        # ----------------------------------

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


        # ==================================
        # DISPLAY PACKET
        # ==================================

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


        # ==================================
        # SAVE PACKET TO LOG
        # ==================================

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


# ==========================================
# START CAPTURE
# ==========================================

print("\n" + "=" * 60)
print("              CAPTURE STARTED")
print("=" * 60)

print(
    f"Running for {duration} seconds..."
)

print(
    "Press Ctrl + C only if you need to stop manually."
)

print()


# ==========================================
# CAPTURE PACKETS
# ==========================================

sniff(
    prn=packet_callback,
    timeout=duration
)


# ==========================================
# SAVE SUMMARY
# ==========================================

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


# ==========================================
# CLOSE LOG FILE
# ==========================================

log_file.close()


# ==========================================
# DISPLAY SUMMARY
# ==========================================

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