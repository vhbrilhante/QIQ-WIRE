import struct


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