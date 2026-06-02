import socket
import struct

from utils.formatters import format_mac


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