#!/usr/bin/python3

import socket as sckt
import os
import struct
import time as t
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
dst = sys.argv[1]

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

sending_times = [[-1, -1, -1] for i in range(0, 30)]
delays = [[-1, -1, -1] for i in range(0, 30)]
src_ips = [['', '', ''] for i in range(0, 30)]


print_seq = 0
def print_trace(end):
    global print_seq
    while print_seq <= end:
        i = print_seq // 3
        j = print_seq % 3
        if j == 0:
            print(f'\n{i+1} ', end='')
            if delays[i][j] == -1:
                print('*', end='')
            else:
                print(f'({src_ips[i][j]}) {delays[i][j]:.3f} ms', end='')
        elif delays[i][j] == -1:
            print(' *', end='')
        elif src_ips[i][j] == src_ips[i][j-1]:
            print(f' {delays[i][j]:.3f} ms', end='')
        else:
            print(f' ({src_ips[i][j]}) {delays[i][j]:.3f} ms', end='')
        print_seq += 1

print(f'traceroute to {dst} 30 hops max, 16 bytes packets', end='', flush=True)
socket = sckt.socket(sckt.AF_INET, sckt.SOCK_RAW, sckt.IPPROTO_ICMP)
socket.bind(('', 0))
socket.settimeout(2)
i=0
ttl=0
send_seq=0
for i in range(0, 16):
    send_seq += 1
    ttl = ((send_seq-1)//3) + 1
    socket.setsockopt(sckt.IPPROTO_IP, sckt.IP_TTL, ttl)
    sending_times[ttl-1][(send_seq - 1) % 3] = t.time()
    socket.sendto(get_icmp_8(send_seq), (dst, 0))

in_route = True

while in_route:
    count = 0
    rec_seq = 0
    while True:
        try:
            packet, addr = socket.recvfrom(1024)
            time_ = t.time()
            count += 1
        except TimeoutError:
            break
        icmp_type = packet[20]
        if icmp_type == 11:
            pid = (packet[52] << 8) + packet[53]
            if pid!=id:
                continue
            rec_seq = (packet[54] << 8) + packet[55] - 1
            i = rec_seq // 3
            j = rec_seq % 3
            delays[i][j] = (time_ - sending_times[i][j]) * 1000
            src_ips[i][j] = addr[0]
            if rec_seq + 1 == send_seq:
                break
        if icmp_type == 0:
            if addr[0] == dst:
                rec_seq = int((packet[26] << 8) + packet[27]) - 1
                delays[rec_seq // 3][rec_seq % 3] = (t.time() - sending_times[rec_seq // 3][rec_seq % 3]) * 1000
                src_ips[rec_seq // 3][rec_seq % 3] = addr[0]
                for i in range(0, 3-(send_seq - rec_seq)):
                    send_seq += 1
                    ttl = ((send_seq - 1) // 3) + 1
                    socket.setsockopt(sckt.IPPROTO_IP, sckt.IP_TTL, ttl)
                    sending_times[ttl - 1][(send_seq - 1) % 3] = t.time()
                    socket.sendto(get_icmp_8(send_seq), (dst, 0))
                count_repl = 1
                while count_repl < 3:
                    try:
                        packet, addr = socket.recvfrom(1024)
                        time_ = t.time()
                    except TimeoutError:
                        in_route = False
                        break
                    icmp_type = packet[20]
                    if icmp_type == 0:
                        rec_seq = int((packet[26] << 8) + packet[27]) - 1
                        delays[rec_seq // 3][rec_seq % 3] =  (
                                    t.time() - sending_times[rec_seq // 3][rec_seq % 3]) * 1000
                        src_ips[rec_seq // 3][rec_seq % 3] = addr[0]
                        count_repl+=1
                    elif icmp_type == 11:
                        pid = (packet[52] << 8) + packet[53]
                        if pid != id:
                            continue
                        rec_seq = (packet[54] << 8) + packet[55] - 1
                        i = rec_seq // 3
                        j = rec_seq % 3
                        delays[i][j] = (time_ - sending_times[i][j]) * 1000
                        src_ips[i][j] = addr[0]
                in_route = False
                break

    print_trace(rec_seq)

    if not in_route:
        print_trace(rec_seq)
        for i in range(0, (2 - rec_seq % 3)):
            print(' *', end="")
        break

    for i in range(0, count if count != 0 else 16):
        send_seq += 1
        ttl = ((send_seq - 1) // 3) + 1
        socket.setsockopt(sckt.IPPROTO_IP, sckt.IP_TTL, ttl)
        socket.sendto(get_icmp_8(send_seq), (dst, 33434))
        sending_times[ttl - 1][(send_seq - 1) % 3] = t.time()
