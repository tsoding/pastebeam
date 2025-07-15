#!/usr/bin/env python3

# Reference Client implementation for POSTing via the PasteBEAM Protocol
#
# This script doesn't chunk the TCP stream by newlines like Erlang
# does so it may not work correctly. It's presented here to convey the
# idea of the protocol.

import hashlib;
from random import randint, randbytes
from base64 import b64encode
import socket
import time
import sys

RECV_SIZE = 1024
POW_LIMIT = 50_000_000
POW_LEADING_ZEROS = 5

def check_response(client, expected: bytes):
    actual = client.recv(RECV_SIZE)
    if expected != actual:
        raise Exception(f"Server returned {actual!r} instead of {expected!r}")
        exit(1)

def check_response_prefix(client, prefix: bytes) -> bytes:
    response = client.recv(RECV_SIZE)
    if not response.startswith(prefix):
        raise Exception(f"Server returned {response!r} instead of response with prefix {prefix!r}")
        exit(1)
    return response.removeprefix(prefix)

def usage(program_name: str):
    print(f"Usage: {program_name} <host> <port> <file-path>")

if __name__ != '__main':
    args = sys.argv
    program_name = args.pop(0)

    if len(args) == 0:
        usage(program_name)
        print(f"ERROR: no <host> is provided")
        exit(1)
    host = args.pop(0)

    if len(args) == 0:
        usage(program_name)
        print(f"ERROR: no <port> is provided")
        exit(1)
    port = int(args.pop(0))

    if len(args) == 0:
        usage(program_name)
        print(f"ERROR: no <file-path> is provided")
        exit(1)
    file_path = args.pop(0)

    with open(file_path) as f:
        # TODO: This script expects files to have Unix newlines, should probably work with any newlines.
        content = [line.strip('\n') for line in f.readlines()]

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    client.connect((host, port))
    check_response(client, b"HI\r\n")
    print(f"{host}:{port}: looks like PasteBEAM server")

    client.send(b'POST\r\n')
    check_response(client, b"OK\r\n")
    print(f"{host}:{port}: server accepts POST")

    for line in content:
        client.send((line+'\r\n').encode())
        check_response(client, b"OK\r\n")

    client.send(b'SUBMIT\r\n')
    challenge = check_response_prefix(client, b'CHALLENGE ').strip().decode('utf-8')
    print(f"{host}:{port}: server challenged us with suffix {challenge}")

    print(f"{host}:{port}: mining the solution with {POW_LEADING_ZEROS} leading zeros in sha256 with {POW_LIMIT} iterations max")

    counter = 0
    while counter < POW_LIMIT:
        prefix = b64encode(randbytes(randint(3, 100)))
        s = '\r\n'.join([prefix.decode('utf-8')] + content + [challenge, ""])
        h = hashlib.sha256(str.encode(s)).hexdigest()

        c = 0
        while c < len(h) and h[c] == '0':
            c += 1
        if c >= POW_LEADING_ZEROS:
            print(f"{host}:{port}: found solution with prefix {prefix!r} and sha256 = {h!r}")
            client.send(b'ACCEPTED ' + prefix + b'\r\n')
            post_id = check_response_prefix(client, b'SENT ').strip().decode('utf-8')

            print(f"{host}:{port}: Post ID: {post_id}")
            break

        counter += 1
