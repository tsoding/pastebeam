#!/usr/bin/env python3
# Reference Client implementation for POSTing via the PasteBEAM Protocol
import hashlib;
from random import randint, randbytes
from base64 import b64encode
import socket
import time
import sys

# TODO: accept address and port via command line

args = sys.argv
program_name = args.pop(0)

if len(args) == 0:
    print(f"Usage: {program_name} <file-path>")
    print(f"ERROR: no file-path is provided")
    exit(1)

file_path = args.pop(0)

with open(file_path) as f:
    content = [line.strip('\n') for line in f.readlines()]

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(('localhost', 6969))
client.send(b'POST\r\n')
for line in content:
    client.send((line+'\r\n').encode())
client.send(b'SUBMIT\r\n')

challenge = client.recv(100).removeprefix(b'CHALLENGE ').strip().decode('utf-8')

counter = 0
limit = 50_000_000
while counter < limit:
    prefix = b64encode(randbytes(randint(3, 100)))
    s = '\r\n'.join([prefix.decode('utf-8')] + content + [challenge, ""])
    h = hashlib.sha256(str.encode(s)).hexdigest()

    c = 0
    while c < len(h) and h[c] == '0':
        c += 1
    if c >= 5:
        print(f"prefix => {prefix}, hash = {h}, c = {c}")
        client.send(b'ACCEPTED ' + prefix + b'\r\n')
        print(client.recv(100))
        break

    counter += 1
