from datetime import datetime
from collections import defaultdict
import pyshark
import time
import math

def sortdnumericditionaryinalist(defaultdictionarie: defaultdict):
    return defaultdictionarie.items()
def timeToSendFrequentsIPtoDatabase(ipregistered,secondstosend: int=60):
    print("send started")
    current_time=0
    while True:
        if math.floor(time.time())%secondstosend==0 and math.floor(time.time())!=math.floor(current_time):
            currentdatetime=datetime.fromtimestamp(int(time.time()))
            currenttimestamp=int(time.time())
            print(f"{currentdatetime} {math.floor(current_time)} {list(sortdnumericditionaryinalist(ipregistered))}")
            current_time=time.time()
            time.sleep(1)

def captureTraffic(ipregistered,network: str="Ethernet") -> None:
    print("captureTraffic started")
    total=0
    capture = pyshark.LiveCapture(interface=network)
    for packet in capture.sniff_continuously(): 
        ip_detected=False
        for layer in packet.layers: 
            #print("current layer: " + layer.layer_name)
            currlayer=getattr(packet,layer.layer_name)
            for field in currlayer.field_names:
                #print(getattr(currlayer,field))
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
    process2=pool.apply_async(captureTraffic,args=[ipregistered])
    
    process2.get()
    process1.get()
    pool.close()
    
if __name__=='__main__':
    secureHorizon()