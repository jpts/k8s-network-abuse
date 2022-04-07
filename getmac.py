from scapy.all import *

import sys

def getmac(targetip):
	arppacket= Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst=targetip)
	targetmac= srp(arppacket, timeout=2 , verbose= False)[0][0][1].hwsrc
	return targetmac

m = getmac(sys.argv[1])

print(m)

