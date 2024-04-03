from collections import defaultdict
import pandas as pd
from scapy.all import *
total=0
def hasTCP(packet: Packet):
    if packet.haslayer("TCP"):
        return packet.getlayer("TCP").fields
    else:
        return None
def hasIPLayer(packet: Packet):
    if packet.haslayer("IP"):
        return packet.getlayer("IP").fields
    elif packet.haslayer("IPv6"):
        return packet.getlayer("IPv6").fields
    else:
        return None
def getProtocolNameWithNumberOfProtocol(protocol: int):
    nameofprotocol={0:"hopot",6:"tcp_ip",17:"udp_ip",2:"igmp_ip",58:"icmp_ip"}
    return nameofprotocol[protocol] or None
def packet_callback(packet):
    metadatainpacketfordictionarie={}
    #print(packet.layers)
    IPLayer=hasIPLayer(packet)
    if IPLayer:
        metadatainpacketfordictionarie["source"]=IPLayer["src"]
        metadatainpacketfordictionarie["destination"]=IPLayer["dst"]
        try:
            metadatainpacketfordictionarie["protocolName"]=getProtocolNameWithNumberOfProtocol(IPLayer["proto"])
        except:
            try:
                metadatainpacketfordictionarie["protocolName"]=getProtocolNameWithNumberOfProtocol(IPLayer["nh"])
            except:
                print(IPLayer)
    else:
        metadatainpacketfordictionarie["source"]=0
        metadatainpacketfordictionarie["destination"]=0
        metadatainpacketfordictionarie["protocolName"]=0
    TCPLayer = hasTCP(packet)
    if TCPLayer:
        print(TCPLayer)
    #print(metadatainpacketfordictionarie)
    

show_interfaces()

sniff( prn=packet_callback,count=150)
