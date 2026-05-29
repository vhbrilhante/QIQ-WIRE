# sudo /usr/bin/python3 /home/victor-hugo/projects/QIQ_WIRE/main.py -- This code is a simple packet sniffer that captures Ethernet frames and displays their destination MAC address, source MAC address, and protocol type. It uses raw sockets to listen for incoming packets on the network interface. The `format_mac` function converts the raw bytes of the MAC address into a human-readable format, while the `ethernet_frame` function unpacks the Ethernet frame and extracts the relevant information. The program runs indefinitely, printing the details of each captured Ethernet frame to the console.

#socket is a built in module in python that provides low-level networking interfaces.

#struct is a built in module in python that provides functions for working with C-style data structures.

import socket
import struct


def format_mac(bytes_addr):
    return ':'.join(map('{:02x}'.format, bytes_addr))


def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('!6s6sH', data[:14])

    return (
        format_mac(dest_mac),
        format_mac(src_mac),
        socket.htons(proto),  # convert to host byte order
        data[14:]
    )


def ipv4(addr):
    return '.'.join(map(str, addr))


def ipv4_packet(data):
    version_header_length = data[0]

    version = version_header_length >> 4 #jumping four bits to get the info version
    header_length = (version_header_length & 15) * 4

    ttl, proto, src, target = struct.unpack(
        '!8xBB2x4s4s',
        data[:20]
    )

    # we jump eight bytes with !8
    #Byte 0  -> Version/IHL
    #Byte 1  -> DSCP
    #Byte 2  -> Total Length
    #Byte 4  -> Identification
    #Byte 6  -> Flags/Fragment Offset
    #Byte 8  -> TTL
    #Byte 9  -> Protocol

    return (
        version,
        header_length,
        ttl,
        proto,
        ipv4(src),
        ipv4(target),
        data[header_length:]
    )


# Create raw socket
s = socket.socket(
    socket.AF_PACKET, #gives us complete frames of network card
    socket.SOCK_RAW, #gives us the raw data package
    socket.ntohs(3) # ¨3¨ is basically ordering ¨capture all protocols ethernet
)

print("[+] Escutando pacotes...\n")


while True:
    raw_data, addr = s.recvfrom(65535) #receive from, actually waits the data on the socket, take it and return to who sent. 65535 is 2^16 - 1 same as 16 bits.

    dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)

    print("\n[ETHERNET FRAME]")
    print("Destino:", dest_mac)
    print("Origem :", src_mac)
    print("Proto  :", eth_proto)

    # IPv4
    if eth_proto == 8:

        version, header_length, ttl, proto, src, target, data = ipv4_packet(data)

        print("\n[IPv4 PACKET]")
        print("Version:", version)
        print("Header Length:", header_length)
        print("TTL:", ttl)
        print("Protocol:", proto)
        print("Source:", src)
        print("Target:", target)

#1  -> ICMP
#6  -> TCP
#17 -> UDP




