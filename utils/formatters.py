
def format_mac(bytes_addr):
    return ':'.join(map('{:02x}'.format, bytes_addr))


def ipv4(addr):
    return '.'.join(map(str, addr))