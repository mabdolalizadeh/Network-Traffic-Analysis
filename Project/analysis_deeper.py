import pyshark
from scapy.all import *


def sniff_packets(filtered="tcp"):
    packets = sniff(filter=filtered, count=10)
    wrpcap("packets.pcap", packets)


def analyze_packets(pcap_file='packets.pcap'):
    cap = pyshark.FileCapture(pcap_file)
    for packet in cap:
        print(packet)
        print(packet.eth.src)
        print(packet.ip.src)
        print(packet.eth.dst)


if __name__ == '__main__':
    sniff_packets()
    analyze_packets()
