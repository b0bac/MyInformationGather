import time
import socket
import select
import struct


def CheckSummarize(data):
    length = len(data)
    remainder = length % 2
    summarize = 0
    for i in range(0, length - remainder, 2):
        summarize += (data[i]) + ((data[i + 1]) << 8)
    if remainder:
        summarize += (data[-1])
    summarize = (summarize >> 16) + (summarize & 0xffff)
    summarize += (summarize >> 16)
    result = ~summarize & 0xffff
    result = result >> 8 | (result << 8 & 0xff00)
    return result


def Ping(host):
    spacket = struct.pack('>BBHHH32s', 8, 0, 0, 0, 1, b'abcdefghijklmnopqrstuvwabcdefghi')
    summarize = CheckSummarize(spacket)
    spacket = struct.pack('>BBHHH32s', 8, 0, summarize, 0, 1, b'abcdefghijklmnopqrstuvwabcdefghi')
    pinger = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
    pinger.sendto(spacket, (host, 80))
    start = time.time()
    selector = select.select([pinger], [], [], 3)
    end = time.time()
    if not selector[0]:
        return False
    if (3-(end-start)) <= 0:
        return False
    rpacket, ipsrc = pinger.recvfrom(1024)
    header = rpacket[20:28]
    typeid, code, checksum, packetid, sequence = struct.unpack(">BBHHH", header)
    if typeid == 0 and sequence == 1:
        return True
    else:
        return False


def PortTcpScan(ip, port):
    scanner = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    scanner.settimeout(3)
    try:
        scanner.connect((ip, port))
        return True
    except Exception as exception:
        raise exception


'''
def PortUdpScan(ip ,port):
    sender =  socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    receiver = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
    sender.sendto(b"abcd....", (ip, port))
    receiver.settimeout(5)
    try:
        rpacket, addr = receiver.recvfrom(64)
    except Exception as exception:
        print(exception)
        return True
    header = rpacket[20:28]
    rport = int(recPacket.encode('hex')[100:104], 16)
    htype, code, checksum, packetid, sequence = struct.unpack(">BBHHH", header)
    receiver.close()
    print("dd")
    if code == 3 and rort == port and addr[0] == ip:
        return False
    else:
        return True

if __name__ == "__main__":
    print(PortUdpScan("114.114.114.114", 53))
'''