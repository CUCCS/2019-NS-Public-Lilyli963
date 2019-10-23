# TCP XMAS scan
from scapy.all import *

pkt = IP(dst="172.16.111.127")/TCP(dport=RandShort(),flags="FPU")
ret = sr1(pkt1,timeout=10)
if (str(type(ret))=="<class 'NoneType'>"):
	print("open|Filtered")
elif(ret.haslayer(TCP)):
	if(ret.getlayer(TCP).flags == 0x14):  
		print("Closed")
elif(ret.haslayer(ICMP)):
	if(int(ret.getlayer(ICMP).type)==3 and int(ret.getlayer(ICMP).code) in [1,2,3,9,10,13]):
		print("Filtered")
