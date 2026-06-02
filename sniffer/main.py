# sudo /usr/bin/python3 /home/victor-hugo/projects/QIQ_WIRE/sniffer/main.py -- This code is a simple packet sniffer that captures Ethernet frames and displays their destination MAC address, source MAC address, and protocol type. It uses raw sockets to listen for incoming packets on the network interface. The `format_mac` function converts the raw bytes of the MAC address into a human-readable format, while the `ethernet_frame` function unpacks the Ethernet frame and extracts the relevant information. The program runs indefinitely, printing the details of each captured Ethernet frame to the console.

#socket is a built in module in python that provides low-level networking interfaces.

#struct is a built in module in python that provides functions for working with C-style data structures.

import socket
import sys

from parsers.ethernet import ethernet_frame
from parsers.ipv4 import ipv4_packet
from parsers.tcp import (
    tcp_segment,
    tcp_flags_to_string
)
from parsers.udp import udp_segment
from parsers.dns import (
    dns_header,
    dns_query_name
)

from constants.ports import COMMON_PORTS

from parsers.dns import (
    dns_header,
    dns_question,
    DNS_TYPES
)


DNS_ONLY = "--dns" in sys.argv
TCP_ONLY = "--tcp" in sys.argv


s = socket.socket(
    socket.AF_PACKET,
    socket.SOCK_RAW,
    socket.ntohs(3)
)

print("[+] Escutando pacotes...\n")


while True:

    raw_data, addr = s.recvfrom(65535)

    dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)

    # Ethernet
    print("\n[ETHERNET FRAME]")
    print("Destino:", dest_mac)
    print("Origem :", src_mac)
    print("Proto  :", eth_proto)

    # IPv4
    if eth_proto != 8:
        continue

    (
        version,
        header_length,
        ttl,
        proto,
        src,
        target,
        data
    ) = ipv4_packet(data)

    if DNS_ONLY and proto != 17:
        continue

    if TCP_ONLY and proto != 6:
        continue

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

        # DNS
        if src_port == 53 or dest_port == 53:

            (
                transaction_id,
                flags,
                questions,
                answers,
                authority,
                additional,
                dns_data
            ) = dns_header(data)

            print("\n[DNS]")
            print("Transaction ID:", transaction_id)
            print("Questions:", questions)
            print("Answers:", answers)

            try:
                domain = dns_query_name(dns_data)
                print("Domain:", domain)

            except Exception:
                pass
            
            domain, qtype, qclass = dns_question(dns_data)
            
            print("\n[DNS QUERY]")
            print("Domain:", domain)
            print("Type:", DNS_TYPES.get(qtype, f"UNKNOWN ({qtype})"))
            print("Class:", qclass)





