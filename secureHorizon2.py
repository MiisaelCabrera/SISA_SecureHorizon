from datetime import datetime
from collections import defaultdict
from scapy import *
import pyshark
import time
import math
import numpy
from collections import defaultdict
import pandas as pd
import heapq
from scapy.all import *
def captureTrafficScapy(ipregistered):
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

    def hasEthernetLayer(packet: Packet):
        if packet.haslayer("Ether"):
            return packet.getlayer("Ether").fields
        else:
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

    def getTimeFormatwithoutladdingzeros():
        datestart =datetime.now().strftime("%m/%d/%Y %H:%M").lstrip("0")
        spliteddate=datestart.split("/")
        if spliteddate[1][0]=="0":
            spliteddate[1]=spliteddate[1][1]
        datestart="/".join(spliteddate)
        spliteddate=datestart.split(" ")
        if spliteddate[1][0]=="0":
            spliteddate[1]=spliteddate[1][1:]
        datestart=" ".join(spliteddate)
        return datestart

    def metadataSortedFormat(metadataNotSortedForModel: dict):
        metadataSorted={}
        metadataSorted["appName"] = metadataNotSortedForModel["appName"]
        metadataSorted["totalSourceBytes"] = metadataNotSortedForModel["totalSourceBytes"]
        metadataSorted["totalDestinationBytes"] = metadataNotSortedForModel["totalDestinationBytes"]
        metadataSorted["totalDestinationPackets"] = metadataNotSortedForModel["totalDestinationPackets"]
        metadataSorted["totalSourcePackets"] = metadataNotSortedForModel["totalSourcePackets"]
        metadataSorted["direction"] = metadataNotSortedForModel["direction"]
        metadataSorted["sourceTCPFlagsDescription"] = metadataNotSortedForModel["sourceTCPFlagsDescription"]
        metadataSorted["destinationTCPFlagsDescription"] = metadataNotSortedForModel["destinationTCPFlagsDescription"]
        metadataSorted["source"]=metadataNotSortedForModel["source"]
        metadataSorted["protocolName"]=metadataNotSortedForModel["protocolName"]
        metadataSorted["sourcePort"] = metadataNotSortedForModel["sourcePort"]
        metadataSorted["destination"] = metadataNotSortedForModel["destination"]
        metadataSorted["destinationPort"] = metadataNotSortedForModel["destinationPort"]
        metadataSorted["startDateTime"] = metadataNotSortedForModel["startDateTime"]
        metadataSorted["stopDateTime"] = metadataNotSortedForModel["stopDateTime"]
        return metadataSorted
    def packet_callback(packet):
        metadatainpacketfordictionarie={}
        EtherLayer =hasEthernetLayer(packet)
        IPLayer=hasIPLayer(packet)
        #print(packet.layers)
        #print(len(packet.layers()))

        if IPLayer:
            
            metadatainpacketfordictionarie["source"]=IPLayer["src"]
            metadatainpacketfordictionarie["destination"]=IPLayer["dst"]
            if IPLayer["src"] in ipregistered:
                ipregistered[IPLayer["src"]]+=1
            else:
                ipregistered[IPLayer["src"]]=1
            try:
                metadatainpacketfordictionarie["protocolName"]=getProtocolNameWithNumberOfProtocol(IPLayer["proto"])
            except:
                try:
                    metadatainpacketfordictionarie["protocolName"]=getProtocolNameWithNumberOfProtocol(IPLayer["nh"])
                except:
                    metadatainpacketfordictionarie["protocolName"]=0
                    
        else:
            metadatainpacketfordictionarie["source"]=0
            metadatainpacketfordictionarie["destination"]=0
            metadatainpacketfordictionarie["protocolName"]=0
        TCPLayer = hasTCP(packet)
        if TCPLayer:
            metadatainpacketfordictionarie["sourcePort"]=TCPLayer["sport"]
            metadatainpacketfordictionarie["destinationPort"]=TCPLayer["dport"]
            metadatainpacketfordictionarie["sourceTCPFlagsDescription"]=getFlagsInTCP(TCPLayer["flags"]) # Fake
            metadatainpacketfordictionarie["destinationTCPFlagsDescription"]="F,P,A" # Fake
        else:
            metadatainpacketfordictionarie["sourceTCPFlagsDescription"]="N/A"
            metadatainpacketfordictionarie["destinationTCPFlagsDescription"]="N/A"
            metadatainpacketfordictionarie["sourcePort"]=0
            metadatainpacketfordictionarie["destinationPort"]=0 
        UDPLayer= hasUDPLayer(packet)
        if UDPLayer:
            metadatainpacketfordictionarie["sourcePort"]=UDPLayer["sport"]
            metadatainpacketfordictionarie["destinationPort"]=UDPLayer["dport"]
        else:
            metadatainpacketfordictionarie["sourcePort"]=0
            metadatainpacketfordictionarie["destinationPort"]=0
        metadatainpacketfordictionarie["totalDestinationBytes"]=len(packet)
        last=packet.getlayer(packet.layers()[-1])
        lastlayer=packet.getlayer(packet.layers()[-1]).fields
        if "load" in lastlayer:
            metadatainpacketfordictionarie["totalSourceBytes"]=len(lastlayer["load"])
        else:
            metadatainpacketfordictionarie["totalSourceBytes"]=0
        metadatainpacketfordictionarie["startDateTime"] = getTimeFormatwithoutladdingzeros()
        metadatainpacketfordictionarie["stopDateTime"] = getTimeFormatwithoutladdingzeros()
        #print(len(packet))
        #print(f"src: {metadatainpacketfordictionarie['totalSourceBytes']} dst:{metadatainpacketfordictionarie['totalDestinationBytes']}")
        direction=["L2R","L2L"]
        metadatainpacketfordictionarie["appName"]="DNS" # Fake
        metadatainpacketfordictionarie["direction"]=direction[numpy.random.randint(low=0,high=2)] # Fake
        metadatainpacketfordictionarie["totalSourcePackets"]=numpy.random.randint(low=0,high=70) # Fake
        metadatainpacketfordictionarie["totalDestinationPackets"]=numpy.random.randint(low=metadatainpacketfordictionarie["totalSourcePackets"],high=metadatainpacketfordictionarie["totalSourcePackets"]+70) # Fake
        
        metadata=pd.DataFrame(metadataSortedFormat(metadatainpacketfordictionarie),index=[0])
        
    show_interfaces()


    sniff( prn=packet_callback,iface="Realtek PCIe FE Family Controller")

def sortdnumericditionaryinalist(defaultdictionarie: defaultdict):
    mostfrequentips=[]
    for i in defaultdictionarie.items():
        if len(mostfrequentips)>=10:
            heapq.heappop(mostfrequentips)
        heapq.heappush(mostfrequentips,[-i[1],i[0]])
    mostfrequentipsarray=[]
    while len(mostfrequentips)>0:
        ip=heapq.heappop(mostfrequentips)
        #print(mostfrequentips)
        mostfrequentipsarray.append([ip[1],-ip[0]])
    return mostfrequentipsarray
def timeToSendFrequentsIPtoDatabase(ipregistered,secondstosend: int=60):
    print("send started")
    current_time=0
    while True:
        if math.floor(time.time())%secondstosend==0 and math.floor(time.time())!=math.floor(current_time):
            currentdatetime=datetime.fromtimestamp(int(time.time()))
            currenttimestamp=int(time.time())
            print(f"{currentdatetime} {math.floor(current_time)} {sortdnumericditionaryinalist(ipregistered)}")
            current_time=time.time()
            time.sleep(1)

def captureTraffic(ipregistered,network: str="Ethernet") -> None:
    print("captureTraffic started")
    total=0
    capture = pyshark.LiveCapture(interface=network)
    for packet in capture.sniff_continuously(): 
        ip_detected=False
        for layer in packet.layers: 
            #print("\n\n\n\n\n\n" + "current layer: " + layer.layer_name )
            currlayer=getattr(packet,layer.layer_name)
            for field in currlayer.field_names:
                #print(f"{field} : {getattr(currlayer,field)}")
                try:
                    if currlayer.src in ipregistered and not ip_detected:
                        ipregistered[currlayer.src]+=1
                        ip_detected=True
                    elif not ip_detected:
                        ip_detected=True
                        ipregistered[currlayer.src]=1
                except:
                    pass
def secureHorizon() -> None:
    import multiprocessing as mp
    ipregistered=mp.Manager().dict()
    #mp.Process(target=captureTraffic,args=[]).start()
    #mp.Process(target=timeToSendFrequentsIPtoDatabase,args=[]).start()

    pool = mp.Pool(mp.cpu_count())
    process1=pool.apply_async(timeToSendFrequentsIPtoDatabase,args=[ipregistered])
    process2=pool.apply_async(captureTrafficScapy,args=[ipregistered])
    
    process2.get()
    process1.get()
    pool.close()
    
if __name__=='__main__':
    secureHorizon()