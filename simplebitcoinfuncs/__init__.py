#!/usr/bin/env python
# -*- coding: utf-8 -*-


from __future__ import print_function, division, absolute_import

try:
    from __builtin__ import bytes, str, open, super, range, zip, round, int, pow, object, input
except ImportError:    pass

try:
    from __builtin__ import raw_input as input
except:    pass

from codecs import decode


# Imports made explicit because some helper functions I made have common names

try:
    #from .hexhashes import *  # Can still be explicity imported separately
    #from .ecmath import *     # but not including by default
    from .base58 import b58e, b58d
    from .miscfuncs import strlify, isitstring, isitint, hexstrlify, hexreverse, dechex, normalize_input
    from .miscbitcoinfuncs import genkeyhex, genkey, oppushdatalen, intfromoppushdatalen, tovarint, numvarintbytes, fromvarint, getandstrip_varintdata, inttoDER, inttoLEB128, LEB128toint
    from .bitcoin import uncompress, compress, privtopub, addprivkeys, subtractprivkeys, multiplypriv, multiplypub, addpubs, subtractpubs, pubtoaddress, validatepubkey, wiftohex, privtohex, Coin
    from .signandverify import sign, verify, checksigformat, signmsg, verifymsg, checkmsgsigformat
    from .stealth import paystealth, receivestealth, newstealthaddr
    from .bip32 import BIP32
    from .bip39wordlists import BIP39ENGWORDLIST
    from .bip39 import BIP39
    from .electrum1 import ELECTRUM_WORDLIST, Electrum1
    from .electrum2 import Electrum2

# Doctester excepts on relative import
except ValueError:
    #from hexhashes import *
    #from ecmath import *
    from base58 import b58e, b58d
    from miscfuncs import strlify, isitstring, isitint, hexstrlify, hexreverse, dechex, normalize_input
    from miscbitcoinfuncs import genkeyhex, genkey, oppushdatalen, intfromoppushdatalen, tovarint, numvarintbytes, fromvarint, getandstrip_varintdata, inttoDER, inttoLEB128, LEB128toint
    from bitcoin import uncompress, compress, privtopub, addprivkeys, subtractprivkeys, multiplypriv, multiplypub, addpubs, subtractpubs, pubtoaddress, validatepubkey, wiftohex, privtohex, Coin
    from signandverify import sign, verify, checksigformat, signmsg, verifymsg, checkmsgsigformat
    from stealth import paystealth, receivestealth, newstealthaddr
    from bip32 import BIP32
    from bip39wordlists import BIP39ENGWORDLIST
    from bip39 import BIP39
    from electrum1 import ELECTRUM_WORDLIST, Electrum1
    from electrum2 import Electrum2
except SystemError:
    #from hexhashes import *
    #from ecmath import *
    from base58 import b58e, b58d
    from miscfuncs import strlify, isitstring, isitint, hexstrlify, hexreverse, dechex, normalize_input
    from miscbitcoinfuncs import genkeyhex, genkey, oppushdatalen, intfromoppushdatalen, tovarint, numvarintbytes, fromvarint, getandstrip_varintdata, inttoDER, inttoLEB128, LEB128toint
    from bitcoin import uncompress, compress, privtopub, addprivkeys, subtractprivkeys, multiplypriv, multiplypub, addpubs, subtractpubs, pubtoaddress, validatepubkey, wiftohex, privtohex, Coin
    from signandverify import sign, verify, checksigformat, signmsg, verifymsg, checkmsgsigformat
    from stealth import paystealth, receivestealth, newstealthaddr
    from bip32 import BIP32
    from bip39wordlists import BIP39ENGWORDLIST
    from bip39 import BIP39
    from electrum1 import ELECTRUM_WORDLIST, Electrum1
    from electrum2 import Electrum2

