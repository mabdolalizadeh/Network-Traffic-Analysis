from scapy.all import *


def sniff_packets(filtered="tcp"):
    packets = sniff(filter=filtered, count=10)
    wrpcap('packets.pcap', packets)


if __name__ == '__main__':
    sniff_packets()
