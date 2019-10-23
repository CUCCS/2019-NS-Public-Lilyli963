# UDP scan
from scapy.all import *

pkt = IP(dst="172.16.111.127")/UDP(dport=68)
ret = sr1(pkt,timeout=10)
if (str(type(ret))=="<class 'NoneType'>"): 
    print("open|flitered")
elif (ret.haslayer(UDP)): 
    print("open")
elif(ret.haslayer(ICMP)): 
    if(int(ret.getlayer(ICMP).type)==3 and int(ret.getlayer(ICMP).code)==3):
        print("closed")
    elif(int(ret.getlayer(ICMP).type)==3 and int(ret.getlayer(ICMP).code) in [1,2,9,10,13]):
        print("filtered")
else:
    print(str(type(ret)))

