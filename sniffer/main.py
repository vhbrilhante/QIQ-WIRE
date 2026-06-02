# sudo /usr/bin/python3 /home/victor-hugo/projects/QIQ_WIRE/sniffer/main.py -- This code is a simple packet sniffer that captures Ethernet frames and displays their destination MAC address, source MAC address, and protocol type. It uses raw sockets to listen for incoming packets on the network interface. The `format_mac` function converts the raw bytes of the MAC address into a human-readable format, while the `ethernet_frame` function unpacks the Ethernet frame and extracts the relevant information. The program runs indefinitely, printing the details of each captured Ethernet frame to the console.

#socket is a built in module in python that provides low-level networking interfaces.

#struct is a built in module in python that provides functions for working with C-style data structures.

import socket
import struct


# =========================
# FORMATTERS
# =========================

def format_mac(bytes_addr):
    return ':'.join(map('{:02x}'.format, bytes_addr))


def ipv4(addr):
    return '.'.join(map(str, addr))


def tcp_flags_to_string(
    urg,
    ack,
    psh,
    rst,
    syn,
    fin
):
    flags = []

    if urg:
        flags.append("URG")
    if ack:
        flags.append("ACK")
    if psh:
        flags.append("PSH")
    if rst:
        flags.append("RST")
    if syn:
        flags.append("SYN")
    if fin:
        flags.append("FIN")

    return " ".join(flags)


# =========================
# ETHERNET
# =========================

def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack(
        '!6s6sH',
        data[:14]
    )

    return (
        format_mac(dest_mac),
        format_mac(src_mac),
        socket.htons(proto),
        data[14:]
    )


# =========================
# IPV4
# =========================

def ipv4_packet(data):

    version_header_length = data[0]

    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4

    ttl, proto, src, target = struct.unpack(
        '!8xBB2x4s4s',
        data[:20]
    )

    return (
        version,
        header_length,
        ttl,
        proto,
        ipv4(src),
        ipv4(target),
        data[header_length:]
    )


# =========================
# TCP
# =========================

def tcp_segment(data):

    (
        src_port,
        dest_port,
        sequence,
        acknowledgment,
        offset_reserved_flags
    ) = struct.unpack(
        '!HHLLH',
        data[:14]
    )

    offset = (offset_reserved_flags >> 12) * 4

    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1

    return (
        src_port,
        dest_port,
        sequence,
        acknowledgment,
        flag_urg,
        flag_ack,
        flag_psh,
        flag_rst,
        flag_syn,
        flag_fin,
        data[offset:]
    )


# =========================
# UDP
# =========================

def udp_segment(data):

    src_port, dest_port, length, checksum = struct.unpack(
        '!HHHH',
        data[:8]
    )

    if src_port ==  53 or dest_port == 53:
        (
            transaction_id,
            flags,
            questions,
            answers,
            authority,
            additional,
            dns_data,
        ) = dns_header(data)
    
        print("\n[DNS]")
        print("Transaction ID:", transaction_id)
        print("Questions:", questions)
        print("Answers:", answers)
    
    return (
        src_port,
        dest_port,
        length,
        checksum,
        data[8:]
    )
    
#parser DNS
def dns_header(data):
    (
        transaction_id,
        flags,
        questions,
        answers,
        authority,
        additional,
    ) = struct.unpack(
        '!HHHHHH',
        data[:12]
    )

    return (
        transaction_id,
        flags,
        questions,
        answers,
        authority,
        additional,
        data[12:]
    )

# =========================
# COMMON PORTS
# =========================

COMMON_PORTS = {
    80: "HTTP",
    443: "HTTPS",
    53: "DNS",
    22: "SSH",
    25: "SMTP",
    110: "POP3",
    143: "IMAP"
}


# =========================
# RAW SOCKET
# =========================

s = socket.socket(
    socket.AF_PACKET,
    socket.SOCK_RAW,
    socket.ntohs(3)
)

print("[+] Escutando pacotes...\n")



# MAIN LOOP


while True:

    raw_data, addr = s.recvfrom(65535)

    dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)

    print("\n[ETHERNET FRAME]")
    print("Destino:", dest_mac)
    print("Origem :", src_mac)
    print("Proto  :", eth_proto)

    # IPv4
    if eth_proto == 8:

        (
            version,
            header_length,
            ttl,
            proto,
            src,
            target,
            data
        ) = ipv4_packet(data)

        print("\n[IPv4 PACKET]")
        print("Version:", version)
        print("Header Length:", header_length)
        print("TTL:", ttl)
        print("Protocol:", proto)
        print("Source:", src)
        print("Target:", target)

        # TCP
        if proto == 6:

            (
                src_port,
                dest_port,
                sequence,
                acknowledgment,
                flag_urg,
                flag_ack,
                flag_psh,
                flag_rst,
                flag_syn,
                flag_fin,
                data
            ) = tcp_segment(data)

            service = COMMON_PORTS.get(
                dest_port,
                "UNKNOWN"
            )

            print("\n[TCP SEGMENT]")
            print("Source Port:", src_port)
            print(
                f"Destination Port: {dest_port} ({service})"
            )
            print("Sequence:", sequence)
            print("Acknowledgment:", acknowledgment)

            print(
                "Flags:",
                tcp_flags_to_string(
                    flag_urg,
                    flag_ack,
                    flag_psh,
                    flag_rst,
                    flag_syn,
                    flag_fin
                )
            )

        # UDP
        elif proto == 17:

            (
                src_port,
                dest_port,
                length,
                checksum,
                data
            ) = udp_segment(data)

            service = COMMON_PORTS.get(
                dest_port,
                "UNKNOWN"
            )

            print("\n[UDP SEGMENT]")
            print("Source Port:", src_port)
            print(
                f"Destination Port: {dest_port} ({service})"
            )
            print("Length:", length)

            if src_port == 53 or dest_port == 53:
                print("[DNS TRAFFIC DETECTED]")


#1  -> ICMP
#6  -> TCP
#17 -> UDP




