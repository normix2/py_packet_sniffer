import socket
import threading
from sniffer import IPPacketCatcher
import time

TESTING_PORT = 40529  # We use a localhost server to test packet sending. This sets the port used for it.


def __send_pkt(packet_type, dest_url, dest_port):
    """Sends a packet and returns the port the sending socket had for comparison later"""
    s = socket.socket(socket.AF_INET, packet_type)
    s.connect((dest_url, dest_port))
    send_port = s.getsockname()[1]
    s.send("SUCCESS".encode())
    s.close()
    return send_port


class __LocalServer(threading.Thread):
    """ Starts a local server in a separate thread for testing whether packets sent back to myself
    are detected correctly"""
    def __init__(self, packet_type, listen_port, incoming_packets):
        threading.Thread.__init__(self)
        self.listen_port = listen_port
        self.incoming_packets = incoming_packets
        self.packet_type = packet_type

    def run(self):
        s = socket.socket(socket.AF_INET, self.packet_type)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Sockets normally remain unavailable for 30-60 seconds after their last use.
        # SO_REUSEADDR removes this limit in case there is repeated testing in a short time
        s.bind(("127.0.0.1", self.listen_port))

        if self.packet_type == socket.SOCK_STREAM:
            s.listen(5)
            while 1:
                conn, addr = s.accept()
                print('Connected by', addr)
                data = conn.recv(8)
                if addr[0] == "127.0.0.1":
                    self.incoming_packets.append(data)
                    return
        elif self.packet_type == socket.SOCK_DGRAM:
            while 1:
                data, addr = s.recvfrom(20)
                print('Connected by', addr)
                if addr[0] == "127.0.0.1":
                    self.incoming_packets.append(data)
                    return


def sniffer_test(protocol_tested, server_url, server_port):
    """ A packet is sent from localhost to localhost. Used to sniff incoming packet ONLY.
        Tests that the sniffer is able to capture only packets with source ips in the whitelist,
        then parse them correctly by comparing the source and destination ports of the packet
        as parsed by the packet sniffer to the original ports used by the sending socket"""
    received_data = []
    sniffed_pkts = []
    if protocol_tested == "TCP":
        packet_type = socket.SOCK_STREAM
    elif protocol_tested == "UDP":
        packet_type = socket.SOCK_DGRAM
    else:
        raise ValueError("Only TCP and UDP are supported")

    sniffer = IPPacketCatcher(duration=1,
                              protocol=protocol_tested,
                              src_ip_whitelist=["127.0.0.1"],
                              captured_pkts=sniffed_pkts,
                              verbose=False)

    # Spawn new threads for the server and sniffer as recvfrom is a blocking call
    server = __LocalServer(packet_type, server_port, received_data)
    server.start()
    sniffer.start()

    time.sleep(1)  # occasionally, server takes too long to start and packet is sent too early, causing an endless wait

    send_port = __send_pkt(packet_type, server_url, server_port) # The randomly selected port used for sending packet

    server.join()
    sniffer.join()

    sniffed_packet = sniffed_pkts[0]

    assert(sniffed_packet.source_ip_str == "127.0.0.1")
    assert(sniffed_packet.dest_ip_str == "127.0.0.1")
    assert(sniffed_packet.source_port == send_port)
    assert(sniffed_packet.dest_port == server_port)


sniffer_test("TCP", "127.0.0.1", TESTING_PORT)
sniffer_test("UDP", "127.0.0.1", TESTING_PORT)

