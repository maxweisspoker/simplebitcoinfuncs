#!/usr/bin/env python
# -*- coding: utf-8 -*-


from __future__ import division
import sys
import hashlib
import hmac

from binascii import hexlify, unhexlify
try:
    ModuleNotFoundError
except:
    ModuleNotFoundError = ImportError

try:
    from .ecmath import N
    from .miscfuncs import dechex
except Exception as e:
    if type(e) != ImportError and \
       type(e) != ModuleNotFoundError and \
       type(e) != ValueError and \
       type(e) != SystemError:
        raise Exception("Unknown problem with imports.")
    from ecmath import N
    from miscfuncs import dechex


# Most code taken from python-ecdsa library, possibly other sources, I forget.

if sys.version_info[0] == 3:
    def bstrencodeforecdsa(s):
        return s.encode("latin-1")
else:
    def bstrencodeforecdsa(s):
        try:
            return str(s,'ascii')
        except:
            return s

def bit_length(num):
    s = bin(num)
    s = s.lstrip('-0b')
    return len(s)

def orderlen(order):
    return (1+len("%x"%order))//2

def number_to_string(num, order):
    l = orderlen(order)
    fmt_str = "%0" + str(2*l) + "x"
    string = unhexlify((fmt_str % num).encode())
    assert len(string) == l, (len(string), l)
    return string

def number_to_string_crop(num, order):
    l = orderlen(order)
    fmt_str = "%0" + str(2*l) + "x"
    string = unhexlify((fmt_str % num).encode())
    return string[:l]

def bits2int(data, qlen):
    x = int(hexlify(data), 16)
    l = len(data) * 8
    if l > qlen:
        return x >> (l-qlen)
    return x

def bits2octets(data, order):
    z1 = bits2int(data, bit_length(order))
    z2 = z1 - order
    if z2 < 0:
        z2 = z1
    return number_to_string_crop(z2, order)

def generate_k(secexp, data, hash_func=hashlib.sha256, order=N):
    qlen = bit_length(order)
    holen=hash_func().digest_size
    secexp = int(secexp,16)
    data = unhexlify(data)
    rolen = (qlen + 7) / 8
    bx = number_to_string(secexp, order) + bits2octets(data, order)
    v = bstrencodeforecdsa('\x01') * holen
    k = bstrencodeforecdsa('\x00') * holen
    k = hmac.new(k, v+bstrencodeforecdsa('\x00')+bx, hash_func).digest()
    v = hmac.new(k, v, hash_func).digest()
    k = hmac.new(k, v+bstrencodeforecdsa('\x01')+bx, hash_func).digest()
    v = hmac.new(k, v, hash_func).digest()
    while True:
        t = bstrencodeforecdsa('')
        while len(t) <= rolen:
            v = hmac.new(k, v, hash_func).digest()
            t += v
        secret = bits2int(t, qlen)
        if secret >= 1 and secret < order:
            return int(secret)
        k = hmac.new(k, v+bstrencodeforecdsa('\x00'), hash_func).digest()
        v = hmac.new(k, v, hash_func).digest()
