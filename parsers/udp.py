import struct


def udp_segment(data):

    src_port, dest_port, length, checksum = struct.unpack(
        '!HHHH',
        data[:8]
    )

    return (
        src_port,
        dest_port,
        length,
        checksum,
        data[8:]
    )