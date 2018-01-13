import socket
import binascii
import threading
import ipv4
import time


def parse_packet(pkt_data):
    """ By default, socket returns the data as a single string of hexadecimal values. i.e. /xUu /xa1 ...
        We use the binascii module to remove the /x and white space. We then convert it into an
         array of bytes"""
    hex_seq = binascii.hexlify(pkt_data).decode()
    byte_seq = []
    for i in range(0, len(hex_seq), 2):
        byte_seq.append(int(hex_seq[i:i + 2], 16))
    transport_protocol = ipv4.check_protocol(byte_seq)
    pkt_obj = None
    if transport_protocol == ipv4.PROTO_TCP:
        pkt_obj = ipv4.TCPPacket(byte_seq)
    elif transport_protocol == ipv4.PROTO_UDP:
        pkt_obj = ipv4.UDPPacket(byte_seq)
    return pkt_obj


class IPPacketCatcher(threading.Thread):
    """ This captures packets at the IP layers. Duration is how long to run for, protocol is TCP or UDP,
        whitelist will catch all packets as None or if it is a list, only packets whose ip is in the whitelist.
        captured_pkts is where all packets accepted by the whitelist are stored for further processing later."""
    def __init__(self,
                 duration=10,
                 protocol="TCP",
                 src_ip_whitelist=None,
                 src_port_whitelist=None,
                 captured_pkts=None,
                 verbose=True):
        threading.Thread.__init__(self)
        if captured_pkts is None:
            captured_pkts = []
        if src_port_whitelist is None:
            src_port_whitelist = []
        if src_ip_whitelist is None:
            src_ip_whitelist = []
        self.duration = duration
        self.src_ip_whitelist = src_ip_whitelist
        self.src_port_whitelist = src_port_whitelist
        self.captured_pkts = captured_pkts
        self.verbose = verbose
        self.protocol = protocol

    def run(self):
        if self.protocol == "TCP":
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        elif self.protocol == "UDP":
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        else:
            raise NotImplementedError

        stop_time = time.time() + self.duration

        while time.time() < stop_time:
            raw_data = s.recvfrom(2048)
            pkt_data = raw_data[0]
            parsed_pkt = parse_packet(pkt_data)
            if parsed_pkt is None:
                continue

            pkt_src_port = parsed_pkt.source_port
            pkt_src_ip = parsed_pkt.source_ip_str
            relevant_pkt = True

            if self.src_ip_whitelist and pkt_src_ip not in self.src_ip_whitelist:
                relevant_pkt = False
            if self.src_port_whitelist and pkt_src_port not in self.src_port_whitelist:
                relevant_pkt = False

            if relevant_pkt:
                if self.verbose:
                    IPPacketCatcher.print_pkt_info(parsed_pkt)
                self.captured_pkts.append(parsed_pkt)

        return self.captured_pkts

    @staticmethod
    def print_pkt_info(pkt):
        print("Protocol: " + ipv4.PROTO_DICT[pkt.transport_protocol])
        print("Source IP: " + pkt.source_ip_str)
        print("Destination IP: " + pkt.dest_ip_str)
        print("Source Port: " + str(pkt.source_port))
        print("Destination Port: " + str(pkt.dest_port))
        print("______________________________________")


class PacketProcessor:
    """ This processor processes all packets after the packet catcher finishes catching packets.
        The statistics are not so urgent so they are only analyzed at the end.
    """


    def __init__(self):
        self.stats = {}
        self.protocol = ""

    # Each packet updates relevant statistics in the self.stats dictionary
    def process(self, pkt_arr):
        if len(pkt_arr) > 0:
            self.protocol = ipv4.PROTO_DICT[pkt_arr[0].transport_protocol]
        for pkt in pkt_arr:
            src_ip = pkt.source_ip_str
            if src_ip in self.stats.keys():
                self.stats[src_ip]["packet_count"] += 1
                self.stats[src_ip]["bytes_received"] += pkt.byte_count
                self.stats[src_ip]["ports_used"].add(pkt.source_port)
            else:
                self.stats[src_ip] = {}
                self.stats[src_ip]["packet_count"] = 1
                self.stats[src_ip]["bytes_received"] = pkt.byte_count
                self.stats[src_ip]["ports_used"] = {pkt.source_port}

    def print_stats(self):
        print("Aggregate statistics for incoming " + self.protocol + " packets this session are as follows")
        print("Source IP         | Packet count | Byte count | Source ports")
        for k, v in self.stats.items():
            print('{:<15}     {:<12}   {:<9}    {:<}'.format(
                k, str(v["packet_count"]), str(v["bytes_received"]),
                str(v["ports_used"])))
        print("")

    def clear_stats(self):
        self.stats = {}
