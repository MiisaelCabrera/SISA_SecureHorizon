from collections import defaultdict
import pandas as pd
from scapy.all import *
total=0

def hasIPLayer(packet: Packet):
    if packet.haslayer("IP"):
        return packet.getlayer("IP").fields
    elif packet.haslayer("IPv6"):
        return packet.getlayer("IPv6").fields
    else:
        return None
def packet_callback(packet):
    IPLayer=hasIPLayer(packet)
    if IPLayer and IPLayer["version"]==4:
        print(IPLayer)
show_interfaces()

sniff( prn=packet_callback)
