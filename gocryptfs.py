#!/usr/bin/python3
import itertools
import argparse
import getpass
import hashlib
import struct
import base64
import json
import sys
import io
import os

try:
    from Cryptodome.Protocol.KDF import HKDF
    from Cryptodome.Cipher import AES
    from Cryptodome.Hash import SHA256
except ImportError:
    from Crypto.Protocol.KDF import HKDF
    from Crypto.Cipher import AES
    from Crypto.Hash import SHA256

PLAINTEXT_ZERO = b"\x00" * 4096
CIPHERTEXT_ZERO = b"\x00" * (4096 + 32)

def decode_masterkey(masterkey):
    return bytes.fromhex(masterkey.replace("-", ""))

class GocryptfsConfig:
    def __init__(self, filename=None, basepath=None):
        if filename is None:
            basepath = os.path.abspath(basepath)
            while True:
                filename = os.path.join(basepath, "gocryptfs.conf")
                if os.path.isfile(filename):
                    break
                basepath = os.path.dirname(basepath)
                if basepath == "/":
                    raise RuntimeError("Failed to find gocryptfs.conf")

        with open(filename, "rb") as fp:
            self.config = json.load(fp)

        # We only support file systems created with gocryptfs version >= 1.3.
        # Older file systems did not use HKDF to derive separate keys yet.
        assert self.config['Version'] == 2
        assert 'HKDF' in self.config['FeatureFlags']

    def get_masterkey(self, password):
        scrypt = self.config['ScryptObject']
        block  = base64.b64decode(self.config['EncryptedKey'])

        scryptkey = hashlib.scrypt(password.encode('utf-8'),
                                   salt=base64.b64decode(scrypt['Salt']),
                                   n=scrypt['N'], r=scrypt['R'], p=scrypt['P'],
                                   maxmem=0x7fffffff, dklen=scrypt['KeyLen'])

        key = HKDF(scryptkey, salt=b"", key_len=32, hashmod=SHA256,
                   context=b"AES-GCM file content encryption")

        assert len(block) > 32
        assert block != CIPHERTEXT_ZERO
        # Layout: [ NONCE | CIPHERTEXT (...) |  TAG  ]
        nonce, tag, ciphertext = block[:16], block[-16:], block[16:-16]
        aes = AES.new(key, AES.MODE_GCM, nonce=nonce)
        aes.update(struct.pack(">Q", 0))
        return aes.decrypt_and_verify(ciphertext, tag)

    @property
    def aessiv(self):
        return 'AESSIV' in self.config['FeatureFlags']

class GocryptfsFile:
    def __init__(self, filename, masterkey, aessiv=False):
        if aessiv:
            self.decrypt_block = self.decrypt_siv_block
            self.key = HKDF(masterkey, salt=b"", key_len=64, hashmod=SHA256,
                            context=b"AES-SIV file content encryption")
        else:
            self.decrypt_block = self.decrypt_gcm_block
            self.key = HKDF(masterkey, salt=b"", key_len=32, hashmod=SHA256,
                            context=b"AES-GCM file content encryption")

        self.fp = open(filename, "rb")
        header = self.fp.read(18)

        if len(header) == 0:
            # An empty file is valid. It means that the plaintext file
            # was empty.
            self.fileid = None
        else:
            assert len(header) == 18
            assert header[0:2] == b"\x00\x02"
            self.fileid  = header[2:]

        self.blockno = 0
        self.remaining = io.BytesIO()

    def decrypt_gcm_block(self, block):
        assert len(block) > 32
        # File holes are passed through to the underlying FS.
        if block == CIPHERTEXT_ZERO:
            return PLAINTEXT_ZERO
        # Layout: [ NONCE | CIPHERTEXT (...) |  TAG  ]
        nonce, tag, ciphertext = block[:16], block[-16:], block[16:-16]
        aes = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        aes.update(struct.pack(">Q", self.blockno) + self.fileid)
        return aes.decrypt_and_verify(ciphertext, tag)

    def decrypt_siv_block(self, block):
        assert len(block) > 32
        # File holes are passed through to the underlying FS.
        if block == CIPHERTEXT_ZERO:
            return PLAINTEXT_ZERO
        # Layout: [ NONCE |  TAG  | CIPHERTEXT (...) ]
        nonce, tag, ciphertext = block[:16], block[16:32], block[32:]
        aes = AES.new(self.key, AES.MODE_SIV, nonce=nonce)
        aes.update(struct.pack(">Q", self.blockno) + self.fileid)
        return aes.decrypt_and_verify(ciphertext, tag)

    def fill_buffer(self):
        self.fp.seek(18 + (4096 + 32) * self.blockno)
        block = self.fp.read(4096 + 32)
        if len(block) == 0:
            self.remaining = io.BytesIO()
            return False

        self.remaining = io.BytesIO(self.decrypt_block(block))
        self.blockno += 1
        return True

    def seek(self, offset):
        self.blockno = offset // 4096
        self.fill_buffer()
        self.remaining.seek(offset % 4096)

    def read(self, size=None):
        if self.fileid is None:
            return b""

        result = io.BytesIO()
        while size is None or size > 0:
            data = self.remaining.read(size)
            result.write(data)
            if size is not None:
                size -= len(data)
            if size is None or size > 0:
                if not self.fill_buffer():
                    break

        return bytes(result.getbuffer())

    def close(self):
        self.fp.close()
        self.fp = None

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Decrypt individual file from a gocryptfs volume")
    parser.add_argument('--aessiv', action='store_true', help="AES-SIV encryption")
    parser.add_argument('--masterkey', type=decode_masterkey, help="Masterkey as hex string representation")
    parser.add_argument('--password', help="Password to unlock config file")
    parser.add_argument('--config', help="Path to gocryptfs.conf configuration file")
    parser.add_argument('filename', help="Location of the file to decrypt")
    args = parser.parse_args()

    if args.masterkey is None:
        config = GocryptfsConfig(filename=args.config, basepath=os.path.dirname(args.filename))
        if args.password is None:
            args.password = getpass.getpass('Password: ')
        args.masterkey = config.get_masterkey(args.password)
        args.aessiv = config.aessiv

    fp = GocryptfsFile(args.filename, args.masterkey, args.aessiv)
    while True:
        block = fp.read(4096)
        if len(block) == 0:
            break
        sys.stdout.buffer.write(block)
    fp.close()
