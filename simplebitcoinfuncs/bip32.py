#!/usr/bin/env python
# -*- coding: utf-8 -*-


import hmac
import hashlib
from binascii import hexlify, unhexlify
try:
    from .ecmath import *
    from .hexhashes import *
    from .base58 import *
    from .miscfuncs import *
    from .miscbitcoinfuncs import *
    from .bitcoin import *
except ValueError:
    from ecmath import *
    from hexhashes import *
    from base58 import *
    from miscfuncs import *
    from miscbitcoinfuncs import *
    from bitcoin import *
except SystemError:
    from ecmath import *
    from hexhashes import *
    from base58 import *
    from miscfuncs import *
    from miscbitcoinfuncs import *
    from bitcoin import *


class BIP32(object):
    '''
    A simple object to hold info on a BIP0032 key, as well as a few
    functions to do derivation for child keys.

    child("m/1") function returns a BIP32 object, __getitem__("m/1")
    returns a string.

    Input can be an xpub/xpr string, or hex to be used as a generation
    seed... or if there's no input, a new random key will be
    generated.

    Additionally, there is a crack() staticmethod that takes a mpub
    and child private key, both xpub/xprv string format, and the
    path from master to child, and if it doesn't contain any
    hardened keys in the path, the function spits out the master
    private xprv key.
    '''

    def __init__(self, a=genkeyhex(), istestnet=False):
        if a[:4] == 'xpub' or a[:4] == 'tpub':
            assert BIP32.validkey(a)
            ispub = True
            self.xprv = False
            self.xpub = a
        elif a[:4] == 'xprv' or a[:4] == 'tprv':
            assert BIP32.validkey(a)
            ispub = False
            self.xpub = BIP32.xprvtoxpub(a)
            self.xprv = a
        else:
            ispub = False
            self.xprv = BIP32.genmaster(a,istestnet)
            self.xpub = BIP32.xprvtoxpub(self.xprv)
        if ispub:
            self.deserialized = b58d(self.xpub)
            self.priv = False
            self.wif = False
            self.pub = self.deserialized[-66:]
        else:
            self.deserialized = b58d(self.xprv)
            self.priv = self.deserialized[-64:]
            self.pub = privtopub(self.priv,True)
            self.wif = b58e('80' + self.priv + '01')
        assert len(self.deserialized) == 156
        self.chaincode = self.deserialized[-130:-66]
        self.parentfpr = self.deserialized[10:18]
        self.version = self.deserialized[:8]
        self.fpr = hash160(self.pub)[:8]
        self.addr = b58e('00' + hash160(self.pub))
        self.depth = int(self.deserialized[8:10],16)
        self.index = int(self.deserialized[18:26],16)


    def ishard(self):
        return self.index >= 2147483648

    def child(self, path):
        path = path.lower().replace(' ','').replace("'","h")
        if path[:1] != 'm':
            raise Exception("Path wrong format")
        for c in path:
            if c not in "1234567890mh/":
                raise Exception("Path wrong format")
        if self.priv is False and 'h' in path:
            raise Exception('Input path contains hardened derivation. Cannot derive hardened child from public master key.')
        if path[-1] == "/":
            path = path[:-1]
        pathlist = path.split("/")
        newkey = self.__str__()
        for i in range(len(pathlist)):
            if pathlist[i] == "m":
                if self.priv is False:
                    newkey = self.xpub
                else:
                    newkey = self.xprv
            else:
                if 'h' in pathlist[i]:
                    index = (int(pathlist[i].replace('h','')) + 2147483648)
                else:
                    index = int(pathlist[i])
                newkey = BIP32.ckd(newkey,index)
        return newkey

    @staticmethod
    def ckd(key, i):
        key = b58d(key)
        assert int(key[8:10],16) < 255
        i = int(i)
        assert i >= 0 and i <= 4294967295
        ihex = dechex(i,4)
        if i >= 2147483648:
            if key[-66:-64] != '00' or key[:8] == '043587cf' or key[:8] == '0488b21e':
                raise Exception('Cannot derive hardened child from public parent key.')
            o = hexstrlify(hmac.new(unhexlify(key[-130:-66]), \
                           unhexlify('00' + key[-64:] + ihex), \
                           hashlib.sha512).digest())
        else:
            if key[-66:-64] != '00' or key[:8] == '043587cf' or key[:8] == '0488b21e':
                o = hexstrlify(hmac.new(unhexlify(key[-130:-66]), \
                               unhexlify(key[-66:] + ihex), \
                               hashlib.sha512).digest())
            else:
                o = hexstrlify(hmac.new(unhexlify(key[-130:-66]), \
                               unhexlify(privtopub(key[-64:],True) + ihex), \
                               hashlib.sha512).digest())
        x = int(o[:64],16)
        assert x > 0 and x < N

        if key[-66:-64] != '00':
            newkey = addpubs(key[-66:],privtopub(o[:64],False),True)
            keyfpr = hash160(key[-66:])[:8]
        else:
            newkey = '00' + addprivkeys(key[-64:],o[:64])
            keyfpr = hash160(privtopub(key[-64:],True))[:8]
        return b58e(key[:8] + dechex(int(key[8:10],16) + 1,1) + \
                    keyfpr + ihex + o[64:] + newkey)

    @staticmethod
    def genmaster(a,istestnet=False):
        o = hexstrlify(hmac.new(bytearray("Bitcoin seed",'utf-8'),
                                unhexlify(a),hashlib.sha512).digest())
        if istestnet:
            version = '04358394'
        else:
            version = '0488ade4'
        x = int(o[:64],16)
        assert x > 0 and x < N
        return b58e(version + '000000000000000000' + o[64:] + '00' + o[:64])

    @staticmethod
    def xprvtoxpub(a):
        a = b58d(a)
        if a[:8] == '04358394':
            version = '043587cf'
        elif a[:8] == '0488ade4':
            version = '0488b21e'
        else:
            raise Exception('Input not xprv key.')
        return b58e(version + a[8:90] + privtopub(a[-64:],True))

    @staticmethod
    def validkey(key):
        try:
            assert isitstring(key)
            assert len(key) == 111
            assert key[:4] == 'xpub' or key[:4] == 'tpub' or \
                   key[:4] == 'xprv' or key[:4] == 'tprv'
            key2 = b58d(key)
            assert len(key2) == 156
            if key[:4] == 'xprv' or key[:4] == 'tprv':
                assert key2[-66:-64] == '00'
            else:
                assert key2[-66:-64] == '02' or key2[-66:-64] == '03'
        except:
            return False
        else:
            return True

    @staticmethod
    def crack(mpub,priv,pathtopriv):
        '''
        Input mpub is master xpub key string.
        Input priv is xprv string.
        Path is the path string (e.g. 'm/3/6/2') from the mpub to the
        priv. Path cannot contain any hardened keys.
        '''

        mpub = str(mpub)
        priv = b58d(priv)
        if int(priv[18:26],16) >= 2147483648:
            raise Exception("Private key input is hardened.  Cannot crack up a level from a hardened key.")
        pathtopriv = pathtopriv.lower()
        if 'h' in pathtopriv or "'" in pathtopriv:
            raise Exception("Path input indicates a hardened key. Cannot crack up a level from hardened keys.")
        for c in pathtopriv:
            if c not in "1234567890mh/":
                raise Exception("Path wrong format")
        assert pathtopriv[0] == 'm'
        if pathtopriv[-1] == "/":
            pathtopriv = pathtopriv[:-1]
        pathlist = pathtopriv.split("/")
        pathlist = pathlist[1:]
        assert int(pathlist[-1]) == int(priv[18:26],16)
        counter = len(pathlist)
        xpublist = [mpub]
        for i in range(counter-1):
            mpub = BIP32.ckd(mpub,int(pathlist[i]))
            xpublist.append(mpub)
        xpublist.reverse()
        for i in range(counter):
            newpub = b58d(xpublist[i])
            tmp = hexstrlify(hmac.new(unhexlify(newpub[-130:-66]), \
                              unhexlify(newpub[-66:] + priv[18:26]), \
                               hashlib.sha512).digest())
            tmppriv = subtractprivkeys(priv[-64:],tmp[:64])
            priv = priv[:8] + newpub[8:-66] + '00' + tmppriv
            pathlist = pathlist[:-1]
        return b58e(priv)

    def __getitem__(self,path="m"):
        return BIP32(self.child(path))

    def __str__(self):
        if self.xprv == False:
            return self.xpub
        else:
            return self.xprv

    def __repr__(self):
         if self.xprv == False:
            return self.xpub
         else:
            return self.xprv

