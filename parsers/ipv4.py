import struct
from utils.formatters import ipv4


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
