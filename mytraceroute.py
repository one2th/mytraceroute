#!/usr/local/bin/python3

import socket as sckt
import os
import struct
import time
import time as t
import threading
import ipaddress
import sys

if len(sys.argv) == 1:
    print('Введите IP-адрес')
    exit()
try:
    if not ipaddress.ip_address(sys.argv[1]):
        print('Неверный IP-адрес')
        exit()
except ValueError:
    print('Неверный IP-адрес')
    exit()
id = os.getpid() & 0xFFFF
is_interrupt = False
dst = sys.argv[1]
timeout_index = 0
hops_num = -1
packet_ind = 0


def get_icmp_8(seq):
    type = 8
    code = 0
    data = 'qwerty'.encode()
    checksum = (type << 8) + code + id + seq
    for i in range(0, len(data), 2):
        word = (int(data[i]) << 8) + int(data[i+1])
        checksum += word
    checksum = ~(checksum + (checksum >> 16)) & 0xFFFF
    packet = struct.pack('!BBHHH', type, code, checksum, id, seq) + data
    return packet

is_in_route = False
sending_times = [[-1, -1, -1] for i in range(0, 30)]
delays = [[-1, -1, -1] for i in range(0, 30)]
src_ips = [['', '', ''] for i in range(0, 30)]

def send_requests():
    socket = sckt.socket(sckt.AF_INET, sckt.SOCK_RAW, sckt.IPPROTO_ICMP)
    global is_in_route
    is_in_route = True
    i=0
    while is_in_route and i<30:
        ttl = i+1
        for j in range(1, 4):
            socket.setsockopt(sckt.IPPROTO_IP, sckt.IP_TTL, ttl)
            sending_times[i][j - 1] = t.time()
            socket.sendto(get_icmp_8(i*3+j), (dst, 33434))
        i+=1

def receive_replies():
    socket = sckt.socket(sckt.AF_INET, sckt.SOCK_RAW, sckt.IPPROTO_ICMP)
    socket.bind(('', 0))
    socket.setsockopt(sckt.SOL_SOCKET, sckt.SO_RCVBUF, 65535)
    socket.settimeout(2)
    global delays, is_in_route, hops_num
    while not is_in_route:
        pass
    while is_in_route:
        try:
            packet, addr= socket.recvfrom(1024)
            icmp_type = int(packet[20])
        except TimeoutError:
            break
        if len(packet) >= 56:
            pid = (packet[52] << 8) + packet[53]
            if pid == id:
                if icmp_type == 11:
                    seq = int((packet[54] << 8) + packet[55]) - 1
                    delays[seq//3][seq % 3] = t.time() - sending_times[seq//3][seq%3]
                    src_ips[seq // 3][seq % 3]=addr[0]
        if icmp_type == 0:
            if addr[0] == dst:
                seq = int((packet[26] << 8) + packet[27]) - 1
                delays[seq // 3][seq % 3] = t.time() - sending_times[seq // 3][seq % 3]
                src_ips[seq // 3][seq % 3] = addr[0]
                hops_num = (seq // 3) + 1
                count = 1
                while count<3 and is_in_route:
                    try:
                        packet, addr = socket.recvfrom(1024)
                    except TimeoutError:
                        break
                    if addr[0] == dst:
                        seq = int((packet[26] << 8) + packet[27]) - 1
                        delays[seq // 3][seq % 3] = t.time() - sending_times[seq // 3][seq % 3]
                        src_ips[seq // 3][seq % 3] = addr[0]
                        count += 1
                is_in_route = False

receiving_thread = threading.Thread(target=receive_replies)
receiving_thread.start()

send_requests()

time.sleep(0.001)
while is_in_route and time.time()-sending_times[29][2]<2:
    pass

print(f'traceroute to {dst}, 30 hops max, 34 bytes packets')
for i in range(0, hops_num if hops_num!=-1 else 30):
    print(f'{i+1} ', end='')
    if delays[i][0]==-1:
        print('* ', end='')
    else:
        print(f'({src_ips[i][0]}) {delays[i][0]*1000:.3f}ms ', end='')
    if delays[i][1]==-1:
        print('* ', end='')
    elif src_ips[i][1]==src_ips[i][0]:
        print(f'{delays[i][1]*1000:.3f}ms ', end='')
    else:
        print(f'({src_ips[i][1]}) {delays[i][0] * 1000:.3f}ms ', end='')
    if delays[i][2]==-1:
        print('* ')
    elif src_ips[i][2]==src_ips[i][1]:
        print(f'{delays[i][2]*1000:.3f} ms ')
    else:
        print(f'({src_ips[i][2]}){delays[i][2] * 1000:.3f}ms ')

receiving_thread.join()