import ipaddress

from scapy.all import *

# outer 
srcip="10.123.0.10"
nodeip="10.123.0.20"

# inner
returnip="10.123.0.8"
destip="10.100.0.10"
dstport=53
srcport=55353

ipip=Ether()/IP(src=srcip,dst=nodeip)/IP(src=returnip,dst=destip)

payload = UDP(sport=srcport,dport=dstport)/DNS(rd=1,qd=DNSQR(qname="any.any.svc.cluster.local",qtype="SRV"))

packet=ipip/payload

sniff = AsyncSniffer(filter=f"udp and port {srcport}", count=1)
sniff.start()

sendp(packet, loop=0)
sniff.join()

pkt = sniff.results[0]
dns = pkt.getlayer(3)
for i in range(0,len(dns.an.layers())):
    rrsrv = dns.an.getlayer(i)
    name = rrsrv.target.decode().rstrip('.')
    print(f"{name}:{rrsrv.port}")
