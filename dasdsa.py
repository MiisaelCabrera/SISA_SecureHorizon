from scapy.all import *

def packet_callback(packet):
    print(" ---  Paquete capturado  ---")
    print(packet.show())
    
show_interfaces()
sniff(prn=packet_callback,iface="Software Loopback Interface 1")
