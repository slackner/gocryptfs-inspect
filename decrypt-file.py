#!/usr/bin/python3
from Cryptodome.Protocol.KDF import HKDF
from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA256
import itertools
import argparse
import struct
import sys

def decode_masterkey(masterkey):
    return bytes.fromhex(masterkey.replace("-", ""))

def decrypt_block(key, mode, nonce, blockno, fileid, ciphertext, tag):
    aes = AES.new(key, mode, nonce=nonce)
    aes.update(struct.pack(">Q", blockno) + fileid)
    return aes.decrypt_and_verify(ciphertext, tag)

def decrypt_siv(inp, out, masterkey):
    header = inp.read(18)
    if header == "":
        return # empty file

    assert len(header) == 18
    assert header[0:2] == b"\x00\x02"
    fileid  = header[2:]

    key = HKDF(masterkey, salt="", key_len=64, hashmod=SHA256,
               context=b"AES-SIV file content encryption")

    for blockno in itertools.count():
        block = inp.read(4096 + 32)
        if len(block) == 0:
            break

        assert len(block) > 32
        nonce, tag, ciphertext = block[:16], block[16:32], block[32:]
        out.write(decrypt_block(key, AES.MODE_SIV, nonce, blockno, fileid, ciphertext, tag))

def decrypt_gcm(inp, out, masterkey):
    header = inp.read(18)
    if header == "":
        return # empty file

    assert len(header) == 18
    assert header[0:2] == b"\x00\x02"
    fileid  = header[2:]

    key = HKDF(masterkey, salt="", key_len=32, hashmod=SHA256,
               context=b"AES-GCM file content encryption")

    for blockno in itertools.count():
        block = inp.read(4096 + 32)
        if len(block) == 0:
            break

        assert len(block) > 32
        nonce, ciphertext, tag = block[:16], block[16:-16], block[-16:]
        out.write(decrypt_block(key, AES.MODE_GCM, nonce, blockno, fileid, ciphertext, tag))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Decrypt individual file from a gocryptfs volume")
    parser.add_argument('--aessiv', dest='decrypt', action='store_const', const=decrypt_siv,
                        default=decrypt_gcm, help="AES-SIV encryption")
    parser.add_argument('--masterkey', type=decode_masterkey, help="Masterkey as hex string representation")
    parser.add_argument('filename', help="Location of the file to decrypt")

    args = parser.parse_args()

    with open(args.filename, "rb") as fp:
        args.decrypt(fp, sys.stdout.buffer, masterkey=args.masterkey)
