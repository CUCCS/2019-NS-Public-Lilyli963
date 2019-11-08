# TCP connect scan
from scapy.all import *

pkt1 = IP(src="172.16.111.104",dst="172.16.111.127")/TCP(sport=RandShort(),dport=80,flags="S")
ret  = sr1(pkt1,timeout=10)
if(str(type(ret))=="<class 'NoneType'>"):             #如果无回复就是关闭
   print("Filtered")
elif(ret.haslayer(TCP)):                             #如果回复了tcp数据
   if(ret.getlayer(TCP).flags == 0x12):             #SYN-ACK        
      pkt2 = IP(dst="172.16.111.127")/TCP(sport=RandShort(),dport=80,flags="AR")
      send_rst = sr1(pkt2,timeout=10)   #RST +ACK           
      print("open")
   elif (ret.getlayer(TCP).flags == 0x14):          #RST
      print("closed")
