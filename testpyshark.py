from collections import defaultdict
import pandas as pd
from scapy.all import *
import pyshark

import os
from datetime import datetime

# Example timestamp
timestamp = 1672531200  # This represents January 1, 2023, 00:00:00 UTC

# Convert timestamp to datetime
date_time = datetime.fromtimestamp(timestamp)
date_time.fromtimestamp
# Print the datetime object
print(date_time)

# Format the datetime object to a more readable format if desired
formatted_date = date_time.strftime('%Y-%m-%d %H:%M:%S')
print(formatted_date)

show_interfaces()
os.environ["WIRESHARK_MANUF_PATH"] = "C:\\Path\\to\\manuf"
capture = pyshark.LiveCapture(interface='Ethernet')
print("hola")
capture = pyshark.LiveCapture(interface="Ethernet")
"""
for packet in capture:
    try:
        print(packet["ip"].src_host)
    except:
        pass
"""
#capture.sniff(packet_count=1)
total=0
ipregistered=defaultdict(int)

import time
current_time = time.time()
print(f"Current time in seconds since the epoch: {current_time}")
def seeDiference():
    global current_time
    print(time.time())
    if int(time.time())%60==0 and time.time()!=current_time:
        print(date_time.fromtimestamp(int(time.time())))
        current_time=time.time()
for packet in capture.sniff_continuously():     
    for layer in packet.layers: 
        currlayer=getattr(packet,layer.layer_name)
        for field in currlayer.field_names:
            try:
                ipregistered[currlayer.src]+=1
            except:
                pass
    total+=1
# generated(dateTime) appName (Protocol),totalSourceBytes,totalDestinationBytes,totalDestinationPackets,totalSourcePackets,sourcePayloadAsBase64,sourcePayloadAsUTF,destinationPayloadAsBase64,destinationPayloadAsUTF,direction,sourceTCPFlagsDescription,destinationTCPFlagsDescription,source,protocolName,sourcePort,destination,destinationPort,startDateTime,stopDateTime,Label
# payloads

