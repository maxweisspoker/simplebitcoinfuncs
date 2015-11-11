#!/usr/bin/env python
# -*- coding: utf-8 -*-


'''
Misc functions related to Bitcoin, but which didn't feel right being
in the main bitcoin funcs

See _doctester.py for examples of most functions below.
'''


import os
import datetime
from binascii import hexlify, unhexlify
try:
    from .hexhashes import hash256
    from .ecmath import N
    from .base58 import b58e
    from .miscfuncs import *
except ValueError:
    from hexhashes import hash256
    from ecmath import N
    from base58 import b58e
    from miscfuncs import *
except SystemError:
    from hexhashes import hash256
    from ecmath import N
    from base58 import b58e
    from miscfuncs import *


def genkeyhex():
    '''
    Generate new random Bitcoin private key, using os.urandom and
    double-sha256.  Hex format.
    '''

    while True:
        key = hash256(
                hexlify(os.urandom(40) + str(datetime.datetime.now())
                                            .encode("utf-8")))
        # 40 bytes used instead of 32, as a buffer for any slight
        #     lack of entropy in urandom
        # Double-sha256 used instead of single hash, for entropy
        #     reasons as well.
        # I know, it's nit-picking, but better safe than sorry.

        if int(key,16) > 1 and int(key,16) < N:
            break
    return key


def genkey(outcompressed=True,prefix='80'):
    '''
    Generate new random Bitcoin private key, using os.urandom and
    double-sha256.
    '''

    key = prefix + genkeyhex()
    if outcompressed:
        key = key + '01'
    return b58e(key)


def oppushdatalen(num):
    assert isitint(num)
    assert num < 4294967296
    assert num > 0
    if num < 76:
        return dechex(num,1)
    elif num < 256:
        return "4c" + dechex(num,1)
    elif num < 65536:
        return "4d" + hexreverse(dechex(num,2))
    elif num < 4294967296:
        return "4e" + hexreverse(dechex(num,4))


def intfromoppushdatalen(oppushdatalenhex):
    oppushdatalenhex = strlify(oppushdatalenhex)
    if oppushdatalenhex[:2] == "4c":
        assert len(oppushdatalenhex) == 4
        return int(oppushdatalenhex[2:4],16)
    elif oppushdatalenhex[:2] == "4d":
        assert len(oppushdatalenhex) == 6
        return int(oppushdatalenhex[4:6] + 
                   oppushdatalenhex[2:4],16)
    elif oppushdatalenhex[:2] == "4e":
        assert len(oppushdatalenhex) == 10
        return int(oppushdatalenhex[8:10] + 
                   oppushdatalenhex[6:8] + 
                   oppushdatalenhex[4:6] + 
                   oppushdatalenhex[2:4],16)
    else:
        assert len(oppushdatalenhex) == 2
        return int(oppushdatalenhex,16)


def tovarint(num):
    assert isitint(num) and num < 18446744073709551616
    if num == 0:
        return '00'
    elif num < 253:
        o = dechex(num,1)
    elif num < 65536:
        o = hexstrlify(b'\xfd' + unhexlify(dechex(num,2))[::-1])
    elif num < 4294967296:
        o = hexstrlify(b'\xfe' + unhexlify(dechex(num,4))[::-1])
    elif num < 18446744073709551616:
        o = hexstrlify(b'\xff' + unhexlify(dechex(num,8))[::-1])
    return o


def numvarintbytes(varint):
    varint = strlify(varint)
    assert len(varint) == 2
    if varint == 'ff':
        return 9
    elif varint == 'fe':
        return 5
    elif varint == 'fd':
        return 3
    else:
        return 1


def fromvarint(varint):
    varint = strlify(varint)
    if varint[:2] == 'ff':
        assert len(varint) == 18
    elif varint[:2] == 'fe':
        assert len(varint) == 10
    elif varint[:2] == 'fd':
        assert len(varint) == 6
    else:
        assert len(varint) == 2
        return int(varint,16)
    return int(hexreverse(varint[2:]),16)


def getandstrip_varintdata(data):
    '''
    Takes a hex string that begins with varint data, and has extra at
    the end, and gets the varint integer, strips the varint bytes, and
    returns the integer and the remaining data.  So rather than having
    to manually read the varint prefix, count, and strip, you can do
    it in one function.  This function will return a tuple of the data
    and the leftover.

    For example, let's say you are parsing a transaction from
    beginning to end, and you know the next byte is a varint byte.

    Here's an example:

    fd5d010048304502200187af928e9d155c4b1ac9c1c9118153239aba76774f77
    5d7c1f9c3e106ff33c0221008822b0f658edec22274d0b6ae9de10ebf2da06b1
    bbdaaba4e50eb078f39e3d78014730440220795f0f4f5941a77ae032ecb9e337
    53788d7eb5cb0c78d805575d6b00a1d9bfed02203e1f4ad9332d1416ae01e270
    38e945bc9db59c732728a383a6f1ed2fb99da7a4014cc952410491bba2510912
    a5bd37da1fb5b1673010e43d2c6d812c514e91bfa9f2eb129e1c183329db55bd
    868e209aac2fbc02cb33d98fe74bf23f0c235d6126b1d8334f864104865c4029
    3a680cb9c020e7b1e106d8c1916d3cef99aa431a56d253e69256dac09ef122b1
    a986818a7cb624532f062c1d1f8722084861c5c3291ccffef4ec687441048d24
    55d2403e08708fc1f556002f1b6cd83f992d085097f9974ab08a28838f07896f
    bab08f39495e15fa6fad6edbfb1e754e35fa1c7844c41f322a1863d4621353ae
    ffffffff0140420f00000000001976a914ae56b4db13554d321c402db3961187
    aed1bbed5b88ac00000000
    
    If the above tx fragment is input as a single long string with no
    white-space, this function will return the tuple:
    ('004830...53ae', 'ffffffff...00000000')

    See _doctester.py for that example in action.
    '''

    data = strlify(data)
    numbytes = numvarintbytes(data[:2])
    varint = data[:2*numbytes]
    data = data[2*numbytes:]
    tostrip = fromvarint(varint) * 2
    return data[:tostrip], data[tostrip:]


def inttoDER(a):
    '''
    Format an int/long to DER hex format
    '''

    o = dechex(a,1)
    if int(o[:2],16) > 127:
        o = '00' + o
    olen = dechex(len(o)//2,1)
    return '02' + olen + o


def inttoLEB128(intinput):
    '''
    Convert int/long to unsigned LEB128 format hex
    '''

    binstr = str(bin(intinput)) \
             .lstrip("0b").replace("b","").replace("L","") \
             .replace("'","").replace('"',"")
    if len(binstr) % 7:
        binstr = binstr.zfill(len(binstr) + 7 - (len(binstr) % 7))
    bytelist = ""
    for i in range(len(binstr) // 7):
        if i < ((len(binstr) // 7) - 1):
            pad = "1"
        else:
            pad = "0"
        currbyte = binstr[(len(binstr) - (7*i + 7)):(len(binstr) - (7*i))]
        currbyte = pad + currbyte
        currbyte = dechex(int(currbyte,2))
        # assert len(currbyte) == 2
        bytelist = bytelist + currbyte
    return bytelist


def LEB128toint(LEBinput):
    '''
    Convert unsigned LEB128 hex to integer
    '''

    reversedbytes = hexreverse(LEBinput)
    binstr = ""
    for i in range(len(LEBinput) // 2):
        if i == 0:
            assert int(reversedbytes[2*i:(2*i + 2)],16) < 128
        else:
            assert int(reversedbytes[2*i:(2*i + 2)],16) >= 128
        tempbin = str(bin(int(reversedbytes[2*i:(2*i + 2)],16))) \
                  .lstrip("0b").replace("b","").replace("L","") \
                  .replace("'","").replace('"',"") \
                  .zfill(8)
        binstr += tempbin[1:]
    return int(binstr,2)

