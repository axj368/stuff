import socket
import struct
import threading
import time

from ipHeader import IPPacket

#create global variable
arrayToCheck = []
class newIP:
    def __init__(self, host, ip):
        self.host = host
        self.ip = ip
class IP:
    def __init__(self, addy, id, port):
        self.addy = addy
        self.id= id
        self.port = port
#open text file in read mode
def file_open():
    file = open('targets.txt', 'r')
    hostnames = []
    ipaddress = []
    #for every target
    for line in file:
        hostnames.append(line.rstrip())
        ipaddress.append(socket.gethostbyname(line.rstrip()))
    file.close()
    return hostnames, ipaddress

TTL = 32
RETRIES = 4
MESSAGE = "message for class project.questions to student axj368 or professor mrx@case.edu"
LOCAL_IP = '192.168.68.109'
PORT = 33434

#threadOne counts rtt and hops
# does src and dest port and develops udp header
#datagram sends packet to header
#
def threadOne():
    hostnames, ipaddress = file_open()
    file_open()
    new_dg = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    # new_dg.setsockopt(socket.SOL_IP, socket.IP_TTL, TTL)
    msg = bytes(MESSAGE + 'a' * (1472 - len(MESSAGE)), 'ascii')

    srcport = 4711  # arbitrary source port
    dstport = 33434  # arbitrary destination port
    leng = 8 + len(msg);
    checksum = 0
    # create udp header
    udp_head = struct.pack('!HHHH', srcport, dstport, leng, checksum)
    # use datagram to send udp header message
    new_dg.sendto(udp_head + msg, ('', 0))
    print(udp_head)
    a1 = IPPacket(ipaddress[0], LOCAL_IP)
    a1.create_ipv4_fields_list()
    headerIP = a1.assemble_ipv4_fields()
    print(headerIP)
    packet = headerIP + udp_head + msg
    new_dg.sendto(packet, (ipaddress[0], dstport))
    myIpObj = IP(ipaddress,a1.ip_idf, PORT)
    arrayToCheck.append()
    time.time()
    delta_ms = round(time, 3)
    delta_int = int(delta_ms * 1000)
    print(delta_int)



def threadTwo():

 while True:
    rtt = []
    count_hops = []
    #raw socket and ICMP response
    final_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    data, address = final_socket.recvfrom(1500)
    print(data,address)
    new_ttl = data[36]
    #hop count equation
    count_hop = TTL - new_ttl
    count_hops.append(count_hop)
    src_ip = socket.inet_ntoa(data[12:16])
    dst_ip = socket.inet_ntoa(data[16:20])
    src_host =socket.gethostbyaddr(dst_ip)
    res_src_ip = socket.inet_ntoa(data[40:44])
    res_dst_ip = socket.inet_ntoa(data[44:48])
    timeStamp = int((time.time()-data[32:34])* 1000)
    dst_port = struct.unpack("!H", data[50:52])[0]
    new_type = ""
    stamp = False;

    for x in arrayToCheck:
        if dst_ip == x.ip:
            rtt.append("IP address")
            stamp = True
        elif dst_port == x.port:
            rtt.append("Port")
            stamp = True
        elif data[32:34] == x.id:
            rtt.append("IP ID")
            stamp = True
    if stamp == True:
        same_type = ""
        for matches in rtt:
            my_type = same_type + matches
            print("Target:" + src_host +  ";" + + src_ip + "Hops:" + count_hops + ";" + "RTT:"
          + timeStamp +";" + "Matched on:" + new_type)
    else:
        print("Cannot locate packet")

#parallel threads running for header
def main():
    listen_for_header1 = threading.Thread(target=threadTwo())
    listen_for_header = threading.Thread(target=threadOne())
    listen_for_header1.start()
    listen_for_header.start()

main()


