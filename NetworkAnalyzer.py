from collections import defaultdict
import pandas as pd
from scapy.all import *
total=0
def packet_callback(packet):
    global total
    total+=1
    try:
        if total<=1:
            for method in dir(packet):
                try:
                    print(dir(packet))
                    print(method+": ")
                    print(getattr(packet,method))
                except :
                    pass
        #if total==1000:
            #print(packet.keys())  
    except KeyboardInterrupt:
        print("Interrupted")

show_interfaces()

#sniff( prn=packet_callback,iface="Software Loopback Interface 1")
"""
import pyshark
# Open saved trace file 
#cap = pyshark.FileCapture('mycapture.cap')

# Sniff from interface
capture = pyshark.LiveCapture()
capture.sniff(timeout=10)
"""

import os

# Asegúrate de ajustar la ruta según tu sistema y configuración
os.environ["WIRESHARK_MANUF_PATH"] = "C:\\Path\\to\\manuf"
import pyshark

def packet_callback(pkt):
    # Esta función se llamará para cada paquete capturado
    src_ip = pkt.ip.src if 'ip' in pkt else 'N/A'
    dst_ip = pkt.ip.dst if 'ip' in pkt else 'N/A'
    src_port = pkt.tcp.srcport if 'tcp' in pkt else 'N/A'
    dst_port = pkt.tcp.dstport if 'tcp' in pkt else 'N/A'
    protocol = pkt.transport_layer if 'transport_layer' in pkt else 'N/A'

    print(f"Protocolo: {protocol}, IP de origen: {src_ip}, Puerto de origen: {src_port}, IP de destino: {dst_ip}, Puerto de destino: {dst_port}")



# Abre una interfaz de captura en vivo
capture = pyshark.LiveCapture(interface='Ethernet')
print("hola")
# Define la función de callback que se llamará para cada paquete capturado
#capture.sniff(packet_count=0)
capture = pyshark.LiveCapture(interface="Wi-Fi")
"""
for packet in capture:
    try:
        print(packet["ip"].src_host)
    except:
        pass
"""
capture.sniff(packet_count=1)
total=0
ipregistered=defaultdict(int)
# Iterar a través de los paquetes capturados
for packet in capture.sniff_continuously():        
    for layer in packet.layers:
        print("Current Layer: "+ layer.layer_name+"\n\n\n\n\n")
        currlayer=getattr(packet,layer.layer_name)
        if "ip"==layer.layer_name or "ipv4"==layer.layer_name or "ipv6"==layer.layer_name:
            ipregistered[currlayer.src]+=1
        for field in currlayer.field_names:
            print(field+ ": "+ getattr(currlayer,field))
    total+=1
    if total==1000:
        break
print(ipregistered)
# generated(dateTime) appName (Protocol),totalSourceBytes,totalDestinationBytes,totalDestinationPackets,totalSourcePackets,sourcePayloadAsBase64,sourcePayloadAsUTF,destinationPayloadAsBase64,destinationPayloadAsUTF,direction,sourceTCPFlagsDescription,destinationTCPFlagsDescription,source,protocolName,sourcePort,destination,destinationPort,startDateTime,stopDateTime,Label
# payloads