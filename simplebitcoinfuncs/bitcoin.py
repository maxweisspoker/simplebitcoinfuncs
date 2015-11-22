#!/usr/bin/env python
# -*- coding: utf-8 -*-


from binascii import hexlify, unhexlify
try:
    from .hexhashes import *
    from .ecmath import *
    from .base58 import *
    from .miscfuncs import *
    from .miscbitcoinfuncs import *
except ValueError:
    from hexhashes import *
    from ecmath import *
    from base58 import *
    from miscfuncs import *
    from miscbitcoinfuncs import *
except SystemError:
    from hexhashes import *
    from ecmath import *
    from base58 import *
    from miscfuncs import *
    from miscbitcoinfuncs import *


def uncompress(pub):
    '''
    Input must be hex string, and a valid compressed public key.
    Check if it's a valid key first, using the validatepubkey()
    function below, and then verify that the str len is 66.
    '''

    yp = int(pub[:2],16) - 2
    x = int(pub[2:],16)
    a = (pow_mod(x,3,P) + 7) % P
    y = pow_mod(a, (P+1)//4, P)
    if y % 2 != yp:
        y = -y % P
    x = dechex(x,32)
    y = dechex(y,32)
    return '04' + x + y


def compress(pub):
    '''
    Input must be hex string, and a valid uncompressed public key.
    Check if it's a valid key first, using the validatepubkey()
    function below, and then verify that the str len is 130.
    '''

    x = pub[2:66]
    y = pub[66:]
    if int(y,16) % 2:
        o = str('03') + str(x)
    else:
        o = str('02') + str(x)
    return o


def privtopub(priv,outcompressed=True):
    '''
    Input must be 64-char hex string
    '''

    x, y = ecmultiply(Gx,Gy,int(priv,16))
    x = dechex(x,32)
    y = dechex(y,32)
    o = '04' + x + y
    if outcompressed:
        return compress(o)
    else:
        return o


def addprivkeys(p1,p2):
    '''
    Input must be 64-char hex string
    '''

    return dechex(((int(p1,16) + int(p2,16)) % N),32)


def subtractprivkeys(p1,p2):
    '''
    Input must be 64-char hex string
    '''

    return dechex(((int(p1,16) + (N - int(p2,16))) % N),32)


def multiplypriv(p1,p2):
    '''
    Input must be 64-char hex string
    '''

    return dechex(((int(p1,16) * int(p2,16)) % N),32)


def multiplypub(pub,priv,outcompressed=True):
    '''
    Input pubkey must be hex string and valid pubkey.
    Input privkey must be 64-char hex string.

    Pubkey input can be compressed or uncompressed, as long as it's a
    valid key and a hex string. Use the validatepubkey() function to
    validate the public key first.  The compression of the input
    public key does not do anything or matter in any way.
    '''

    if len(pub) == 66:
        pub = uncompress(pub)
    x, y = ecmultiply(int(pub[2:66],16),int(pub[66:],16),int(priv,16))
    x = dechex(x,32)
    y = dechex(y,32)
    o = '04' + x + y
    if outcompressed:
        return compress(o)
    else:
        return o


def addpubs(p1,p2,outcompressed=True):
    '''
    Pubkey inputs can be compressed or uncompressed, as long as
    they're valid keys and hex strings. Use the validatepubkey()
    function to validate them first. The compression of the input
    keys does not do anything or matter in any way. Only the
    outcompressed bool dictates the compression of the output.
    '''

    if len(p1) == 66:
        p1 = uncompress(p1)
    if len(p2) == 66:
        p2 = uncompress(p2)
    x, y = ecadd(int(p1[2:66],16),int(p1[66:],16),
                 int(p2[2:66],16),int(p2[66:],16))
    x = dechex(x,32)
    y = dechex(y,32)
    o = '04' + x + y
    if outcompressed:
        return compress(o)
    else:
        return o


def subtractpubs(p1,p2,outcompressed=True):
    '''
    Pubkey inputs can be compressed or uncompressed, as long as
    they're valid keys and hex strings. Use the validatepubkey()
    function to validate them first. The compression of the input
    keys does not do anything or matter in any way. Only the
    outcompressed bool dictates the compression of the output.
    '''

    if len(p1) == 66:
        p1 = uncompress(p1)
    if len(p2) == 66:
        p2 = uncompress(p2)
    x, y = ecsubtract(int(p1[2:66],16),int(p1[66:],16),
                      int(p2[2:66],16),int(p2[66:],16))
    x = dechex(x,32)
    y = dechex(y,32)
    o = '04' + x + y
    if outcompressed:
        return compress(o)
    else:
        return o


def pubtoaddress(pub,prefix='00'):
    return b58e(prefix + hash160(pub))


def validatepubkey(pub):
    '''
    Returns input key if it's a valid hex public key, or False
    otherwise.

    Input must be hex string, not bytes or integer/long or anything
    else.
    '''

    try:
        pub = hexstrlify(unhexlify(pub))
    except:
        return False
    if len(pub) == 130:
        if pub[:2] != '04':
            return False
        if uncompress(compress(pub)) != pub:
            return False
    elif len(pub) == 66:
        if pub[:2] != '02' and pub[:2] != '03':
            return False
    else:
        return False
    return pub


def wiftohex(wifkey):
    '''
    Returns a tuple of:
    (64-char hex key, 2-char hex prefix for key, if it was compressed)
    '''

    iscompressed = False
    wifkey = normalize_input(wifkey)
    assert len(wifkey) == 50 or len(wifkey) == 51 or len(wifkey) == 52
    for c in wifkey:
        if c not in b58_digits:
            raise Exception("Not WIF")
    key = b58d(wifkey)
    prefix, key = key[:2], key[2:] 
    if len(key) == 66:
        assert key[-2:] == '01'
        key = key[:-2]
        iscompressed = True
    assert len(key) == 64
    return key, prefix, iscompressed


def privtohex(key):
    '''
    Used for getting unknown input type into a private key.

    For example, if you ask a user to input a private key, and they
    may input hex, WIF, integer, etc. Run it through this function to
    get a standardized format.

    Function either outputs private key hex string or raises an
    exception. It's really going to try to make any input into
    a private key, so make sure that whatever you import is indeed
    supposed to be a private key. For example, if you put an int in,
    it will turn that into a key. Make sure you want a key when you
    use this function!!!
    '''

    if isitint(key):
        key = dechex(key,32)
    else:
        try:
            key, z, zz = wiftohex(key)
        except:
            try:
                key = unhexlify(key)
            except:
                try:
                    key1 = hexstrlify(key)
                    assert len(key1) == 64 or len(key1) == 66 or len(key1) == 68
                    if len(key1) == 68:
                        assert key1[-2:] == '01'
                    key = key1
                except:
                    raise Exception("Cannot interpret input key.")
            else:
                key = hexstrlify(key)
    if len(key) == 68:
        assert key[-2:] == '01'
        key = key[:-2]
    if len(key) == 66:
        key = key[2:]
    assert len(key) == 64
    return key


class Coin(object):
    '''
    Simple object class to hold a single Bitcoin key in all its forms.

    If input is a private key can be any form, if it's a public key,
    it should be a hex string 66 or 130 chars long (and a valid key).
    '''

    def __init__(self, key, privprefix=str('80'), pubprefix=False):
        try:
            key = privtohex(key)
        except:
            try:
                key = validatepubkey(key)
                assert key
            except:
                raise TypeError('Input must be a public or private key')
        assert len(key) == 64 or len(key) == 66 or len(key) == 130
        if len(key) != 64:
            self.priv = False
            self.wifc = False
            self.wifu = False
            if len(key) == 130:
                self.pubu = key
                self.pubc = compress(key)
            else:
                self.pubc = key
                self.pubu = uncompress(key)
        else:
            self.priv = key
            self.wifc = b58e(privprefix + key + '01')
            self.wifu = b58e(privprefix + key)
            self.pubu = privtopub(key,False)
            self.pubc = compress(self.pubu)
        self.hash160c = hash160(self.pubc)
        self.hash160u = hash160(self.pubu)
        self.privprefix = privprefix
        if pubprefix == False:
            assert int(privprefix,16) > 127 and int(privprefix,16) < 256
            self.pubprefix = dechex(int(privprefix,16)-128,1)
        else:
            self.pubprefix = normalize_input(pubprefix)
        self.addrc = b58e(self.pubprefix + self.hash160c)
        self.addru = b58e(self.pubprefix + self.hash160u)

