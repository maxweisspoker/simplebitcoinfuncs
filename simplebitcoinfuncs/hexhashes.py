#!/usr/bin/env python
# -*- coding: utf-8 -*-


'''
I found I was using hex more often than binary data, so I made these
functions. Hexlifying and unhexlifying probably add unnecessary time,
but using hex instead of raw data helps me visualize what is going
on. In time-sensitive and efficient applications, these functions
should probably not be used, but for learning purposes, I was happy
to have them.

The point of doing this:
# >>> str().rstrip("'").replace("b'","",1).replace("'","")
is to convert Python 3 byte objects to strings.
rstrip must go first so that strings like "b'adcb'" don't get the
right b lopped off. See miscfuncs.strlify() for more info.
'''


from binascii import hexlify, unhexlify
import hashlib


# All functions: input ascii hex string, output ascii hex string


def sha256(hexstring):
    return str(hexlify(hashlib.sha256(unhexlify(hexstring)).digest())) \
           .rstrip("'").replace("b'","",1).replace("'","")


def sha512(hexstring):
    return str(hexlify(hashlib.sha512(unhexlify(hexstring)).digest())) \
           .rstrip("'").replace("b'","",1).replace("'","")


def sha512d(hexstring):
    return str(hexlify(
           hashlib.sha512(hashlib.sha512(unhexlify(hexstring))
                  .digest())     .digest())) \
           .rstrip("'").replace("b'","",1).replace("'","")


def ripemd160(hexstring):
    h = hashlib.new('ripemd160')
    h.update(unhexlify(hexstring))
    return str(hexlify(h.digest())) \
           .rstrip("'").replace("b'","",1).replace("'","")


def hash160(hexstring):
    h = hashlib.new('ripemd160')
    h.update(hashlib.sha256(unhexlify(hexstring)).digest())
    return str(hexlify(h.digest())) \
           .rstrip("'").replace("b'","",1).replace("'","")


def hash256(hexstring):
    return str(hexlify(
           hashlib.sha256(hashlib.sha256(unhexlify(hexstring))
                  .digest())     .digest())) \
           .rstrip("'").replace("b'","",1).replace("'","")


def hash512(hexstring):
    return str(hexlify(
           hashlib.sha512(hashlib.sha256(unhexlify(hexstring))
                  .digest())     .digest())) \
           .rstrip("'").replace("b'","",1).replace("'","")

