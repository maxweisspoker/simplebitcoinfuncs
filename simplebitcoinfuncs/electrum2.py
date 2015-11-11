#!/usr/bin/env python
# -*- coding: utf-8 -*-


from __future__ import division
from pbkdf2 import PBKDF2
from binascii import hexlify, unhexlify
try:
    from .hexhashes import *
    from .base58 import *
    from .miscfuncs import *
    from .miscbitcoinfuncs import *
    from .bitcoin import *
    from .bip32 import *
    from .bip39wordlists import BIP39ENGWORDLIST
except ValueError:
    from hexhashes import *
    from base58 import *
    from miscfuncs import *
    from miscbitcoinfuncs import *
    from bitcoin import *
    from bip32 import *
    from bip39wordlists import BIP39ENGWORDLIST
except SystemError:
    from hexhashes import *
    from base58 import *
    from miscfuncs import *
    from miscbitcoinfuncs import *
    from bitcoin import *
    from bip32 import *
    from bip39wordlists import BIP39ENGWORDLIST


class Electrum2(object):
    def __init__(self,a=128,prefix="01",customentropy=1):
        if isitint(a):
            assert a >= 32
            self.hex = self.makeseed(a,prefix,customentropy)
        else:
            try:
                self.hex = Electrum2.wordstohex(a)
            except:
                try:
                    self.hex = hexstrlify(unhexlify(a))
                except:
                    raise Exception("Cannot interpret input.")
            else:
                try:
                    assert Electrum2.validate(a)
                except:
                    raise Exception("Word list invalid.")
        assert Electrum2.validate(Electrum2.hextowords(self.hex),prefix,customentropy)
        self.words = Electrum2.hextowords(self.hex)
        self.seed = Electrum2.Bip32Seed(self.words,'',prefix,customentropy)
        self.bip32xprv = BIP32(self.seed).xprv
        self.bip32xpub = BIP32(self.seed).xpub

    def __str__(self):
        return self.words

    def __repr__(self):
        return self.words

    def __getitem__(self, a):
        '''
        Retrieves a tuple of private wif key, pubkey, and address for
        a given index. If the input index is an int, it gets the main
        address index, if it's a float (0.0 or 1.0), it gets change
        address info.

        Alternatively, a path ('m/1/2h/3') can be entered, and it will
        get the BIP32 key info that corresponds to that path.
        '''

        if 'float' == type(a).__name__:
            path = "m/1/" + str(int(a))
        elif isitint(a):
            path = "m/0/" + str(a).replace("L","")
        elif isitstring(a) and "m" in str(a).lower():
            path = normalize_input(a).replace("u'","").replace("/'","/").replace("''","'")
        else:
            raise Exception("Invalid __getitem__() input.")
        o = BIP32(self.seed)[path]
        return o.wif, o.pub, o.addr

    def makeseed(self, numbits=128, prefix="01", customentropy=1):
        from math import ceil, log
        n = int(ceil(log(customentropy,2)))
        k = len(prefix)*4
        n_added = int(max(16, k + numbits - n))
        numbytes = int(ceil(n_added/8.0))
        while True:
            entropy = int(sha512d(hexlify(os.urandom(80) + \
                      str(datetime.datetime.now()).encode("utf-8")))[:numbytes*2],16)
            if entropy < 2**n_added:
                break
        nonce = 0
        while True:
            nonce += 1
            i = dechex(int(customentropy * (entropy + nonce)),1)
            words = Electrum2.hextowords(i)
            if Electrum2.validate(words, prefix, customentropy):
                break
        return i

    @staticmethod
    def validate(words, prefix="01", customentropy=1):
        try:
            assert Electrum2.validateentropy(words,prefix,customentropy)
        except:
            return False
        o = hexstrlify(hmac.new(bytearray("Seed version",'utf-8'),
                       bytearray(words,'utf-8'), hashlib.sha512).digest())
        return o.startswith(prefix)

    @staticmethod
    def validateentropy(words, prefix="01", customentropy=1):
        return int(Electrum2.wordstohex(words),16) % customentropy == 0

    @staticmethod
    def hextowords(i):
        i = int(i,16)
        n = len(BIP39ENGWORDLIST)
        words = []
        while i:
            x = i%n
            i = i//n
            words.append(BIP39ENGWORDLIST[x])
        return ' '.join(words)

    @staticmethod
    def wordstohex(seed):
        n = len(BIP39ENGWORDLIST)
        words = seed.split()
        assert len(words) > 1
        i = 0
        while words:
            w = words.pop()
            k = BIP39ENGWORDLIST.index(w)
            try:
                assert k
            except:
                assert k == 0
            i = i*n + k
        return dechex(i,1)

    @staticmethod
    def Bip32Seed(words,password="",prefix="01",customentropy=1):
        words = normalize_input(words).lower()
        assert Electrum2.validate(words,prefix,customentropy)
        password = normalize_input(password,False,True)
        salt = 'electrum' + password
        o = hexstrlify(PBKDF2(words,salt,2048,macmodule=hmac,
                       digestmodule=hashlib.sha512).read(64))
        return o

    @staticmethod
    def crack(mpub,priv,index=None,privtests=100):
        priv = privtohex(priv)
        starting = 0
        if index is not None:
            starting = int(index)
        for i in range(starting,privtests):
            privxprvchange = BIP32(mpub)['m/1/' + str(i).replace("L","")]
            privxprvchange = privxprvchange.deserialized[8:-66] + \
                             '00' + priv
            if mpub[0] == 't':
                privxprvchange = b58e('04358394' + privxprvchange)
            elif mpub[0] == 'x':
                privxprvchange = b58e('0488ade4' + privxprvchange)
            privxprvmain = BIP32(mpub)['m/1/' + str(i).replace("L","")]
            privxprvmain = privxprvmain.deserialized[8:-66] + \
                           '00' + priv
            if mpub[0] == 't':
                privxprvmain = b58e('04358394' + privxprvmain)
            elif mpub[0] == 'x':
                privxprvmain = b58e('0488ade4' + privxprvmain)
            try:
                crackchange = BIP32.crack(mpub,privxprvchange,'m/1/' + str(i).replace("L",""))
                crackmain = BIP32.crack(mpub,privxprvmain,'m/0/' + str(i).replace("L",""))
            except:
                if index is not None:
                    return False
                continue
            if BIP32(crackchange).xpub == mpub:
                return BIP32(crackchange).xprv
            elif BIP32(crackmain).xpub == mpub:
                return BIP32(crackmain).xprv
            else:
                if index is not None:
                    return False
        return False

