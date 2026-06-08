import socket
import struct


def dns_header(data):

    (
        transaction_id,
        flags,
        questions,
        answers,
        authority,
        additional
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


def dns_query_name(data):

    labels = []

    position = 0

    while True:

        length = data[position]

        if length == 0:
            position += 1
            break

        position += 1

        label = data[position:position + length]

        labels.append(
            label.decode(errors="ignore")
        )

        position += length

    domain = ".".join(labels)
    return domain, position

def dns_question(data):
    
    domain, position = dns_query_name(data)
        
    qtype, qclass = struct.unpack(
            '!HH',
            data[position:position + 4]
        )
    
    return (
        domain,
        qtype,
        qclass,
        position + 4
    )


def is_dns_response(flags):

    return (flags >> 15) & 1

#a register A have
#NAME      2 bytes (ponteiro)
#TYPE      2 bytes
#CLASS     2 bytes
#TTL       4 bytes
#RDLENGTH  2 bytes
#RDATA     4 bytes

def parse_dns_answer(data, offset):

    (
        name,
        rtype,
        rclass,
        ttl,
        rdlenght
    ) = struct.unpack(
        '!HHHIH',
        data[offset:offset+12]
    )

    offset += 12

    if rtype == 1 and rdlenght == 4:
        ip = socket.inet_ntoa(
            data[offset:offset+4]
        )
        return ip

    return None

DNS_TYPES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    15: "MX",
    16: "TXT",
    28: "AAAA",
}
