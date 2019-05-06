#!/usr/bin/python3
import argparse
import socket
import json
import sys
import re
import os

parser = argparse.ArgumentParser(description="Deobfuscate program output by decrypting filenames")
parser.add_argument('ctlsock', help="Path to the control socket")
args = parser.parse_args()

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect(args.ctlsock)

regex = re.compile("(?<!\\w)" +
                   "([A-Za-z0-9-_]{22,}/|gocryptfs\\.longname\\.[A-Za-z0-9-_]{43}/)*" +
                   "([A-Za-z0-9-_]{22,}|" +
                   "gocryptfs\\.longname\\.[A-Za-z0-9-_]{43}(\\.name)?|" +
                   "gocryptfs\\.(diriv|conf))" +
                   "(?!\\w)")

def decrypt_path(match):
    path = match.group(0)

    if path.endswith("gocryptfs.conf"):
        path = path[:-14]
        suffix = "<gocryptfs.conf>"
    elif path.endswith("gocryptfs.diriv"):
        path = path[:-15]
        suffix = "<gocryptfs.diriv>"
    elif path.endswith(".name"):
        path = path[:-5]
        suffix = "<name>"
    else:
        suffix = None

    if len(path) != 0:
        if path.endswith("/"):
            path = path[:-1]

        sock.sendall(json.dumps({'DecryptPath': path}).encode("utf-8"))

        try:
            response = json.loads(sock.recv(8192).decode("utf-8"))
        except json.JSONDecodeError:
            return match.group(0)

        if response['ErrNo'] != 0:
            return match.group(0)

        path = response['Result']

    if suffix is not None:
        path = os.path.join(path, suffix)
    return path

while True:
    try:
        line = sys.stdin.readline()
    except KeyboardInterrupt:
        break
    if line == "":
        break
    line = regex.sub(decrypt_path, line)
    sys.stdout.write(line)

sock.close()
