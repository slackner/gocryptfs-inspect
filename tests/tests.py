#!/usr/bin/python3
import subprocess
import unittest
import tempfile
import random
import time
import sys
import os

sys.path.insert(0, "../")
import gocryptfs

def generate_content():
    blocks = []
    for _ in range(random.randint(8, 16)):
        if random.randint(0, 1) == 0:
            blocks.append(os.urandom(4096))
        else:
            blocks.append(gocryptfs.PLAINTEXT_ZERO)
    if random.randint(0, 1) == 0:
        blocks.append(os.urandom(random.randint(1, 4095)))
    content = b"".join(blocks)
    return content

def gocryptfs_encrypt(content, masterkey, aessiv):
    """Create an encrypted file with the given content."""

    cipher = tempfile.TemporaryDirectory(prefix="gocryptfs-cipher-")
    plain = tempfile.TemporaryDirectory(prefix="gocryptfs-plain-")

    # Create .diriv file, otherwise gocryptfs refuses to mount.
    with open(os.path.join(cipher.name, "gocryptfs.diriv"), "wb") as fp:
        fp.write(os.urandom(16))

    # Mount cipher -> plain.
    args = ["gocryptfs", "-q"]
    if aessiv:
        args.append("-aessiv")
    args.append("-masterkey=%s" % masterkey.hex())
    args.append("--")
    args.append(cipher.name)
    args.append(plain.name)
    subprocess.check_call(args)

    # Now create a test file with the content.
    with open(os.path.join(plain.name, "testfile"), "wb") as fp:
        hole = False
        for pos in range(0, len(content), 4096):
            hole = (content[pos:pos+4096] == gocryptfs.PLAINTEXT_ZERO)
            if not hole:
                fp.seek(pos)
                fp.write(content[pos:pos+4096])
        if hole:
            fp.truncate(len(content))

    subprocess.check_call(["fusermount", "-u", plain.name])

    # Find the encrypted version.
    found = []
    for filename in os.listdir(cipher.name):
        if filename == "gocryptfs.diriv":
            continue
        if filename == "gocryptfs.conf":
            continue
        if not filename.endswith(".name"):
            found.append(os.path.join(cipher.name, filename))

    # We expect to find exactly one file.
    assert len(found) == 1
    filename = found[0]

    # Copy the ciphertext file.
    encrypted = tempfile.NamedTemporaryFile()
    with open(filename, "rb") as fp:
        encrypted.write(fp.read())
        encrypted.flush()

    cipher.cleanup()
    plain.cleanup()
    return encrypted

class GocryptfsConfigTests(unittest.TestCase):
    def test_masterkey(self):
        config = gocryptfs.GocryptfsConfig("./gocryptfs.conf")
        self.assertFalse(config.aessiv)
        masterkey = config.get_masterkey("test")
        self.assertEqual(masterkey, gocryptfs.decode_masterkey("fd890dab-86bf61cf-ec5ad460-ad3ed01f-9c52d546-2a31783d-a56b088d-3d05232e"))

class GocryptfsFileTests(unittest.TestCase):
    def test_gcm_random(self):
        masterkey = os.urandom(32)

        content = generate_content()
        file = gocryptfs_encrypt(content, masterkey, aessiv=False)
        fp = gocryptfs.GocryptfsFile(file.name, masterkey, aessiv=False)
        self.assertEqual(fp.read(), content)
        for _ in range(1000):
            offset = random.randint(0, len(content) + 10)
            size   = random.randint(0, len(content) + 10 - offset)
            fp.seek(offset)
            self.assertEqual(fp.read(size), content[offset:offset+size])
        fp.close()

        result = subprocess.check_output(["../gocryptfs.py", "--masterkey=%s" % masterkey.hex(), file.name])
        self.assertEqual(result, content)

    def test_gcm_empty(self):
        masterkey = os.urandom(32)

        file = gocryptfs_encrypt(b"", masterkey, aessiv=False)
        fp = gocryptfs.GocryptfsFile(file.name, masterkey, aessiv=False)
        self.assertEqual(fp.read(), b"")
        fp.seek(4096)
        self.assertEqual(fp.read(), b"")
        fp.close()

        result = subprocess.check_output(["../gocryptfs.py", "--masterkey=%s" % masterkey.hex(), file.name])
        self.assertEqual(result, b"")

    def test_siv_random(self):
        masterkey = os.urandom(32)

        content = generate_content()
        file = gocryptfs_encrypt(content, masterkey, aessiv=True)
        fp = gocryptfs.GocryptfsFile(file.name, masterkey, aessiv=True)
        self.assertEqual(fp.read(), content)
        for _ in range(1000):
            offset = random.randint(0, len(content) + 10)
            size   = random.randint(0, len(content) + 10 - offset)
            fp.seek(offset)
            self.assertEqual(fp.read(size), content[offset:offset+size])
        fp.close()

        result = subprocess.check_output(["../gocryptfs.py", "--masterkey=%s" % masterkey.hex(), "--aessiv", file.name])
        self.assertEqual(result, content)

    def test_siv_empty(self):
        masterkey = os.urandom(32)

        file = gocryptfs_encrypt(b"", masterkey, aessiv=True)
        fp = gocryptfs.GocryptfsFile(file.name, masterkey, aessiv=True)
        self.assertEqual(fp.read(), b"")
        fp.seek(4096)
        self.assertEqual(fp.read(), b"")
        fp.close()

        result = subprocess.check_output(["../gocryptfs.py", "--masterkey=%s" % masterkey.hex(), "--aessiv", file.name])
        self.assertEqual(result, b"")

class GocryptfsTests(unittest.TestCase):
    def test_masterkey(self):
        result = subprocess.check_output(["../gocryptfs.py", "--masterkey=fd890dab-86bf61cf-ec5ad460-ad3ed01f-9c52d546-2a31783d-a56b088d-3d05232e", "./mGj2_hdnHe34Sp0iIQUwuw"])
        self.assertEqual(result, b"It works!\n")

    def test_config(self):
        result = subprocess.check_output(["../gocryptfs.py", "--config=./gocryptfs.conf", "--password=test", "./mGj2_hdnHe34Sp0iIQUwuw"])
        self.assertEqual(result, b"It works!\n")
        result = subprocess.check_output(["../gocryptfs.py", "--password=test", "./mGj2_hdnHe34Sp0iIQUwuw"])
        self.assertEqual(result, b"It works!\n")

class GocryptfsDeobfuscateTests(unittest.TestCase):
    def test_wrong_sock(self):
        with self.assertRaises(subprocess.CalledProcessError):
            subprocess.check_call(["../gocryptfs-deobfuscate.py", "/does-not-exist"])

    def test_deobfuscate(self):
        masterkey = os.urandom(32)

        ctlsock = tempfile.NamedTemporaryFile(prefix="gocryptfs-ctlsock-", delete=False)
        cipher = tempfile.TemporaryDirectory(prefix="gocryptfs-cipher-")
        plain = tempfile.TemporaryDirectory(prefix="gocryptfs-plain-")
        os.remove(ctlsock.name)

        # Create .diriv file, otherwise gocryptfs refuses to mount.
        with open(os.path.join(cipher.name, "gocryptfs.diriv"), "wb") as fp:
            fp.write(os.urandom(16))

        # Mount cipher -> plain.
        args = ["gocryptfs", "-q"]
        args.append("-masterkey=%s" % masterkey.hex())
        args.append("-ctlsock=%s" % ctlsock.name)
        args.append(cipher.name)
        args.append(plain.name)
        subprocess.check_call(args)

        for i in range(1, 255):
            with open(os.path.join(plain.name, "x" * i), "wb") as fp:
                fp.write(b"It works!\n")

            # Find the encrypted version.
            found = []
            for filename in os.listdir(cipher.name):
                if filename == "gocryptfs.diriv":
                    continue
                if filename == "gocryptfs.conf":
                    continue
                if not filename.endswith(".name"):
                    found.append(filename)

            # We expect to find exactly one file.
            assert len(found) == 1
            filename = found[0]

            testcase = ["gocryptfs.conf",
                        "gocryptfs.diriv",
                        "%s" % filename,
                        "Hello %s!" % filename,
                        "\"%s\"" % filename,
                        "a%s" % filename]

            expected = ["<gocryptfs.conf>",
                        "<gocryptfs.diriv>",
                        "%s" % ("x" * i),
                        "Hello %s!" % ("x" * i),
                        "\"%s\"" % ("x" * i),
                        "a%s" % filename]

            if filename.startswith("gocryptfs.longname."):
                testcase.append("%s.name" % filename)
                expected.append("%s/<name>" % ("x" * i))

            result = subprocess.check_output(["../gocryptfs-deobfuscate.py", ctlsock.name], input="\n".join(testcase).encode("utf-8"))
            self.assertEqual(result.decode("utf-8").split("\n"), expected)

            os.remove(os.path.join(plain.name, "x" * i))

        subprocess.check_call(["fusermount", "-u", plain.name])

        cipher.cleanup()
        plain.cleanup()

if __name__ == '__main__':
    unittest.main()
