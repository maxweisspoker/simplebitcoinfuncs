#!/usr/bin/env python
# -*- coding: utf-8 -*-


'''
Mostly ripped from Jeff Garzik's code:
https://github.com/jgarzik/python-bitcoinlib/blob/master/bitcoin/base58.py

which itself was ripped from:
git://github.com/joric/brutus.git

which was forked from:
git://github.com/samrushing/caesure.git

All of which are under the MIT license, as is my code.

That said, it's just base converstion FFS, so I'm not sure how much
attribution is really necessary here. I copied a lot of the code
because it was already there, but base conversion isn't that hard.
Divide and subtract, rinse and repeat!

Base58 encoding is used in Bitcoin because it doesn't contain digits
that look alike. 0OIl  are all excluded. Additionally, in 99.9% of
applications, base58 encoding is done where the data is hashed twice
with sha256, and the most siginificant 4 bytes of the resulting hash
are appending to the end of the data. The process of decoding then
always verifies the checksum, and in that manner, any typos or other
errors are always immediately spotted by whatever Bitcoin software
the user is using.  Hence the "check=True" input parameters in the
code below.
'''


from binascii import hexlify, unhexlify
import sys, hashlib


b58_digits = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def b58e(b,check=True):
    b = unhexlify(b)
    if check:
        b = b + hashlib.sha256(hashlib.sha256(b).digest()).digest()[:4]
    n = int('0x0' + hexlify(b).decode('utf8'), 16)
    res = []
    while n > 0:
        n, r = divmod(n, 58)
        res.append(b58_digits[r])
    res = ''.join(res[::-1])
    
    # "1" is prepended, since "0" isn't in the base58 alphabet
    czero = b'\x00'
    if sys.version_info[0] > 2:
        czero = 0
    pad = 0
    for c in b:
        if c == czero: pad += 1
        else: break
    o = b58_digits[0] * pad + res
    # 

    try:  o = str(o,'ascii')
    except:  pass
    return o


def b58d(s,check=True):
    assert s
    n = 0
    for c in s:
        n *= 58
        if c not in b58_digits:
            raise Exception('Character %r is not a valid base58 character' % c)
        digit = b58_digits.index(c)
        n += digit
    h = '%x' % n
    if len(h) % 2:
        h = '0' + h
    res = unhexlify(h.encode('utf8'))
    pad = 0

    for c in s[:-1]:
        if c == b58_digits[0]: pad += 1
        else: break
    o = b'\x00' * pad + res

    if check:
        assert hashlib.sha256(hashlib.sha256(o[:-4]).digest()).digest()[:4] == o[-4:]
        return str(hexlify(o[:-4])) \
               .rstrip("'").replace("b'","",1).replace("'","")

    else:
        return str(hexlify(o)) \
               .rstrip("'").replace("b'","",1).replace("'","")

