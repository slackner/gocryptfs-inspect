gocryptfs Inspection Tools
==========================

This repository provides pure Python commandline tools that can be used in
conjunction with `gocryptfs`, an encrypted overlay filesystem written in Go.
All programs are standalone applications, and only require few Python
dependencies to run.

## Dependencies

For cryptographic functions, the `pycryptodome` dependency is required. Use
one of the following commands to install it:

```bash
sudo apt install python3-pycryptodome
# - or alternatively -
sudo pip3 install pycryptodome
```

## Decrypting files

`gocryptfs.py` is a reimplementation of the gocryptfs crypto in Python. It is
not meant to replace the original software, and only serves as a reference
implementation for the crypto involved.

At the time of writing it can decrypt config files and cipher text files, both
in `AES-GCM` and `AES-SIV` mode. Just run`./gocryptfs.py --help` to see a list
of available options:

```
usage: gocryptfs.py [-h] [--aessiv] [--masterkey MASTERKEY]
                    [--password PASSWORD] [--config CONFIG]
                    filename

Decrypt individual file from a gocryptfs volume

positional arguments:
  filename              Location of the file to decrypt

optional arguments:
  -h, --help            show this help message and exit
  --aessiv              AES-SIV encryption
  --masterkey MASTERKEY
                        Masterkey as hex string representation
  --password PASSWORD   Password to unlock config file
  --config CONFIG       Path to gocryptfs.conf configuration file
```

The most common use-case (decrypting a single file) works like this:

```bash
./gocryptfs.py mGj2_hdnHe34Sp0iIQUwuw
```

`gocryptfs.py` will automatically search for the `gocryptfs.conf` file, and
ask the user for a password to unlock the config. To skip the automatic
search, it is also possible to specify the path to the `gocryptfs.conf` file
using the `--config=...` commandline option.

If the config file is corrupted or the password was lost, the `--masterkey`
option is the last resort to rescue your data. Usage with `gocryptfs.py`
works as follows:

```bash
./gocryptfs.py --masterkey=fd890dab-... [--aessiv] mGj2_hdnHe34Sp0iIQUwuw
```

The `--aessiv` switch is necessary when `AES-SIV` encryption mode is used.
This is especially the case for reverse mode.

**Note:** At the time of writing, `gocryptfs.py` does not support
decrypting filenames yet.

## Deobfuscating filenames

`gocryptfs-deobfuscate.py` automatically replaces cipher text filenames like
`mGj2_hdnHe34Sp0iIQUwuw` in standard input (`stdin`) with their corresponding
plain text filenames. This is especially useful for reading the output of
programs operating on the cipher directory.

The usage is as follows:

```
usage: gocryptfs-deobfuscate.py [-h] ctlsock

Deobfuscate program output by decrypting filenames

positional arguments:
  ctlsock     Path to the control socket

optional arguments:
  -h, --help  show this help message and exit
```

Just pass the content as input (`stdin`), and provide the control unix socket
(see `gocryptfs -ctlsock ...`) of gocryptfs as parameter, e.g.,

```bash
cat error.log | ./gocryptfs-deobfuscate.py /root/gocryptfs/ctlsock
```

You should now see the deobfuscated output on `stdout`, with all encrypted
filenames translated back to plaintext. Virtual files (i.e., files that only
exist in the encrypted version) are displayed in `<...>` brackets, e.g.,

```
<gocryptfs.conf>
directory/<gocryptfs.diriv>
directory/long[...]name.txt/<name>
```

**Note:** In some situations, decrypting a filename might fail, if the
underlying directory content has changed in the meantime. This applies to
`gocryptfs.longname.` files, or to deleted directories in forward mode, for
example. Also, it might be possible that very long words (22+ characters) are
misinterpreted as encrypted filenames. Most of the time it seems to work pretty
well though.
