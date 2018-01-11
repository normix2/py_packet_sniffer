# Linux packet sniffer

from sniffer import *

if __name__ == '__main__':
    sniffing_duration = 10
    udp_caught_pkts = []
    tcp_caught_pkts = []

    udp_catcher = IPPacketCatcher(
                                    duration=sniffing_duration,
                                    protocol="UDP",
                                    captured_pkts=udp_caught_pkts,
                                    verbose=False)

    tcp_catcher = IPPacketCatcher(
                                    duration=sniffing_duration,
                                    protocol="TCP",
                                    captured_pkts=tcp_caught_pkts,
                                    verbose=False)
    udp_catcher.start()
    tcp_catcher.start()

    udp_catcher.join()
    tcp_catcher.join()

    proc = PacketProcessor()
    proc.process(udp_caught_pkts)
    proc.print_stats()

    proc.clear_stats()
    proc.process(tcp_caught_pkts)
    proc.print_stats()

