import ipaddress

from scapy.all import *

# outer
nodemac="52:54:00:22:f6:29"
outersrc="10.123.0.10"
outerdst="10.123.0.20"
vxlanport=4789
vni=1

# inner
broadcastmac="ae:b0:b2:b5:13:20" # VTEP
bastion="10.123.0.8"
destination="10.100.0.10"
dstport=53
srcport=55353

vxlan=Ether(dst=nodemac)/IP(src=outersrc,dst=outerdst)/UDP(sport=vxlanport,dport=vxlanport)/VXLAN(vni=vni,flags="Instance")

packet=vxlan/Ether(dst=broadcastmac)/IP(src=bastion,dst=destination)/UDP(sport=srcport,dport=dstport)/DNS(rd=1,qd=DNSQR(qname="any.any.svc.cluster.local",qtype="SRV"))

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

