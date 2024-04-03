from collections import defaultdict
import pandas as pd
from scapy.all import *
from datetime import datetime
import scapy.fields
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
        return None
def hasUDPLayer(packet: Packet):
    if packet.haslayer("UDP"):
        return packet.getlayer("UDP").fields
    else:
        return None
def getProtocolNameWithNumberOfProtocol(protocol: int):
    nameofprotocol={0:"hopot",6:"tcp_ip",17:"udp_ip",2:"igmp_ip",58:"icmp_ip"}
    return nameofprotocol[protocol] or None

def getFlagsInTCP(flagsTCP:str):
    return ",".join(flagsTCP)

def packet_callback(packet):
    metadatainpacketfordictionarie={}
    #print(packet.fields)
    IPLayer=hasIPLayer(packet)
    #print(packet.layers)
    #print(len(packet.layers()))
    if IPLayer:
        metadatainpacketfordictionarie["source"]=IPLayer["src"]
        metadatainpacketfordictionarie["destination"]=IPLayer["dst"]
        
        try:
            metadatainpacketfordictionarie["protocolName"]=getProtocolNameWithNumberOfProtocol(IPLayer["proto"])
        except:
            try:
                metadatainpacketfordictionarie["protocolName"]=getProtocolNameWithNumberOfProtocol(IPLayer["nh"])
            except:
                print(1/0)
                
    else:
        metadatainpacketfordictionarie["source"]=0
        metadatainpacketfordictionarie["destination"]=0
        metadatainpacketfordictionarie["protocolName"]=0
    TCPLayer = hasTCP(packet)
    if TCPLayer:
        metadatainpacketfordictionarie["sourcePort"]=TCPLayer["sport"]
        metadatainpacketfordictionarie["destinationPort"]=TCPLayer["dport"]
        #print(getFlagsInTCP(TCPLayer["flags"]))
    else:
        metadatainpacketfordictionarie["sourcePort"]=0
        metadatainpacketfordictionarie["destinationPort"]=0
    UDPLayer= hasUDPLayer(packet)
    if UDPLayer:
        metadatainpacketfordictionarie["sourcePort"]=UDPLayer["sport"]
        metadatainpacketfordictionarie["destinationPort"]=UDPLayer["dport"]
    else:
        metadatainpacketfordictionarie["sourcePort"]=0
        metadatainpacketfordictionarie["destinationPort"]=0
    metadatainpacketfordictionarie["startDateTime"] = datetime.now().strftime("%m/%d/%Y %H:%M")
    metadatainpacketfordictionarie["stopDateTime"] = datetime.now().strftime("%m/%d/%Y %H:%M")
    print(metadatainpacketfordictionarie)
show_interfaces()

sniff( prn=packet_callback,count=150)
