#!/usr/bin/env python3

import socket
import telnetlib
import os
import hashlib
import struct

HOST = 'p2psec.net.in.tum.de'
PORT = 13337

def read_packet(size_field, socket):
    len_b = socket.recv(size_field)
    len_i = int.from_bytes(len_b, "big")
    
    return len_b + socket.recv(len_i-size_field)

def generate_enroll_register(challenge):
    while True:        
        body =  (challenge + 
                struct.pack(">H", 0) +              #teamnumber
                struct.pack(">H", 39943) +          #project
                os.urandom(8)+                      #Nonce
                "ga84suq@mytum.de\r\nJonas\r\nHagg".encode('utf-8'))

        hash = hashlib.sha256(body)
        if hash.digest()[0:3] == 3*b"\x00":
            break
    return body
    
    
    

while True:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))
    packet = read_packet(2, s)

    size_b = packet[0:2]
    enroll_init_b = packet[2:4]
    challenge_b = packet[4:12]

    body = generate_enroll_register(challenge_b)
    #body = b'\xd4\xa0\xd79\xfb\xc2g\xdb\x00\x00\x9c\x07\x87\xb1\xc0\x02\x90l\xda\x91ga84suq@mytum.de\r\nJonas\r\nHagg'
    hash = hashlib.sha256()
    hash.update(body)
    #print("Body: {}({})".format(body,len(body)))
    #print(b"Hash: " + hash.digest())

    message = struct.pack(">H", len(body)+4) + struct.pack(">H", 681) + body
    print("Message: {}({})".format(message,len(message)))
    s.send(message+b"\n")

    packet = read_packet(2,s)

    size_b = packet[0:2]
    size = int.from_bytes(size_b, "big")
    code_b = packet[2:4]
    code = int.from_bytes(code_b, "big")
    if(code == 682):
        print("Success: {}".format(int.from_bytes(packet[6:8], "big")))
        break
    if(code == 683):
        print("Error: {}".format(packet[8:size]))
        continue




