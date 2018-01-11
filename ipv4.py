VERSION_IPV4 = 4
PROTO_TCP = 6
PROTO_UDP = 17
PROTO_DICT = {6: "TCP", 17: "UDP"}


def check_protocol(byte_arr):
    return byte_arr[9]


class IPV4:
    """
    This is the basic IP packet class. We have this as we use AF.INET sockets which returns the bytes in the IP packet,
    header included. We do some basic checks here and get the packet IP source/destination and add them into fields.
    """
    def __init__(self, byte_arr):
        def byte_to_ip_str(byte_list):
            if len(byte_list) != 4:
                raise ValueError("Expected a 4 byte list")
            ip_str = ""
            for i in range(3):
                ip_str += str(byte_list[i]) + "."
            ip_str += str(byte_list[3])
            return ip_str

        # Protocol and validity checks
        self.byte_count = len(byte_arr)
        self.version = byte_arr[0] >> 4
        if self.version != VERSION_IPV4:
            raise ValueError("IPv4 packet expected. A version " + str(self.version) + " packet was received instead.")
        self.IHL = byte_arr[0] & 0b00001111
        self.transport_protocol = byte_arr[9]
        if self.transport_protocol not in PROTO_DICT.keys():
            raise ValueError("Only TCP packets are supported. A code " + str(self.transport_protocol)
                             + " was received instead.")

        # IP addressing
        self.source_ip_bytes = byte_arr[12:16]
        self.source_ip_str = byte_to_ip_str(self.source_ip_bytes)
        self.dest_ip_bytes = byte_arr[16:20]
        self.dest_ip_str = byte_to_ip_str(self.dest_ip_bytes)

        # Break up into header and data bytes
        header_end = self.IHL * 4
        self.header = byte_arr[0:header_end]
        self.data = byte_arr[header_end:]


class TCPPacket(IPV4):
    def __init__(self, byte_arr):
        IPV4.__init__(self, byte_arr)
        if self.transport_protocol != PROTO_TCP:
            raise ValueError("TCP packet expected!")
        tcp_data = self.data
        self.source_port = (tcp_data[0] << 8) + tcp_data[1]
        self.dest_port = (tcp_data[2] << 8) + tcp_data[3]


class UDPPacket(IPV4):
    def __init__(self, byte_arr):
        super(UDPPacket, self).__init__(byte_arr)
        if self.transport_protocol != PROTO_UDP:
            raise ValueError("UDP packet expected!")
        udp_data = self.data
        self.source_port = (udp_data[0] << 8) + udp_data[1]
        self.dest_port = (udp_data[2] << 8) + udp_data[3]

