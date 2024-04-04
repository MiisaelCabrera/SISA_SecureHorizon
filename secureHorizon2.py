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
import json
import smtplib
import os
from email.mime.multipart import MIMEMultipart
import email.mime.base
from email.mime.text import MIMEText

"""
    Escaneo de puertos 
    ataque DD2
    prueba de inyeccion SQL
    Prueba de archivo malicioso
"""
def activeTrigger(asunto="¡Anomalía detectada en el tráfico de red!",mensaje="Se ha detectado una anomalía en el tráfico de red. Por favor, revisa el servidor.",destinatario="angeldaniels365@gmail.com"):
    # Llama a esta función cuando detectes una anomalía y no haya usuarios activos en la página web
    usuario = 'securehorizon45@gmail.com'
    contra = 'tpadyfuneksadfiw'
    # Conecta al servidor SMTP
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()  # Habilita el cifrado TLS
    server.login(usuario, contra)

    # Crea un objeto de mensaje
    msg = MIMEMultipart()
    msg['From'] = usuario
    msg['To'] = destinatario
    msg['Subject'] = asunto

    # Agrega el cuerpo del mensaje
    msg.attach(MIMEText(mensaje, 'plain'))

    # Envía el correo electrónico
    texto_correo = msg.as_string()
    server.sendmail(usuario, destinatario, texto_correo)

    # Cierra la conexión
    server.quit()

def dosfilter(diction: dict,maxRequestsPerMinute=3500):
    lastrow = diction.items()[-1]
    latest=0
    comparison=None
    print(lastrow)
    if lastrow[0]-60 in diction:
        comparison=diction[lastrow[0]-60]
    if not comparison:
        for i in lastrow[1].values():
            if i>maxRequestsPerMinute:
                activeTrigger()
            print(i)

def createJson(dictionarie: dict,outputfile: str="data.json") -> None:
    #print(dictionarie)
    try:
        with open(outputfile, "r") as archivo:
            data = json.load(archivo)
        row=dictionarie["1"]
        data[row[0]]=row[1]
        with open(outputfile, "w") as archivo:
            json.dump(data, archivo)
        dosfilter(data)
    except:
        row=dictionarie["1"]

        with open(outputfile, "w") as archivo:
            json.dump({row[0]:row[1]}, archivo)
        dosfilter({row[0]:row[1]})
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
            metadatainpacketfordictionarie["sourceTCPFlagsDescription"]=getFlagsInTCP(TCPLayer["flags"]) 
            metadatainpacketfordictionarie["destinationTCPFlagsDescription"]=0
        else:
            metadatainpacketfordictionarie["sourceTCPFlagsDescription"]=0
            metadatainpacketfordictionarie["destinationTCPFlagsDescription"]=0
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
            #print(lastlayer)
            metadatainpacketfordictionarie["totalSourceBytes"]=len(lastlayer["load"])
        else:
            metadatainpacketfordictionarie["totalSourceBytes"]=0
        metadatainpacketfordictionarie["startDateTime"] = getTimeFormatwithoutladdingzeros()
        metadatainpacketfordictionarie["stopDateTime"] = getTimeFormatwithoutladdingzeros()
        #print(len(packet))
        #print(f"src: {metadatainpacketfordictionarie['totalSourceBytes']} dst:{metadatainpacketfordictionarie['totalDestinationBytes']}")
        direction=["L2R","L2L"]
        metadatainpacketfordictionarie["appName"]=0
        metadatainpacketfordictionarie["direction"]=direction[numpy.random.randint(low=0,high=2)] # Fake
        metadatainpacketfordictionarie["totalSourcePackets"]=numpy.random.randint(low=0,high=70) # Fake
        metadatainpacketfordictionarie["totalDestinationPackets"]=numpy.random.randint(low=metadatainpacketfordictionarie["totalSourcePackets"],high=metadatainpacketfordictionarie["totalSourcePackets"]+70) # Fake
        
        metadata=pd.DataFrame(metadataSortedFormat(metadatainpacketfordictionarie),index=[0])
        
    show_interfaces()


    sniff( prn=packet_callback,iface="Realtek PCIe FE Family Controller")

def sortdnumericditionaryinalist(defaultdictionarie: defaultdict):
    mostfrequentips=[]
    for i in defaultdictionarie.items():
        mostfrequentips.append([i[0],i[1]])
    mostfrequentips.sort(key=lambda x:x[1],reverse=True)
    if len(mostfrequentips)<=10:
        dictio={}
        for i in mostfrequentips:
            dictio[i[0]]=i[1]
        return dictio
    else:
        dictio={}
        for i in mostfrequentips[0:10]:
            dictio[i[0]]=i[1]
        return dictio    
def timeToSendFrequentsIPtoDatabase(ipregistered,secondstosend: int=60):
    print("send started")
    current_time=0
    
    while True:
        if math.floor(time.time())%secondstosend==0 and math.floor(time.time())!=math.floor(current_time):
            currentdatetime=datetime.fromtimestamp(int(time.time()))
            currenttimestamp=int(time.time())
            createJson({"1":[math.floor(current_time),sortdnumericditionaryinalist(ipregistered)]})
            #print(f"{currentdatetime} {math.floor(current_time)} {sortdnumericditionaryinalist(ipregistered)}")
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