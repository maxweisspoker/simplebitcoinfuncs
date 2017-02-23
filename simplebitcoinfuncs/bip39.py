#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import division
import os
import hmac
import hashlib
import datetime
from pbkdf2 import PBKDF2
from binascii import hexlify, unhexlify
try:
    from codecs import decode
except ImportError:
    pass
try:
    from .ecmath import *
    from .hexhashes import *
    from .base58 import *
    from .miscfuncs import *
    from .miscbitcoinfuncs import *
    from .bitcoin import *
    from .bip39wordlists import *
except ValueError:
    from ecmath import *
    from hexhashes import *
    from base58 import *
    from miscfuncs import *
    from miscbitcoinfuncs import *
    from bitcoin import *
    from bip39wordlists import *
except SystemError:
    from ecmath import *
    from hexhashes import *
    from base58 import *
    from miscfuncs import *
    from miscbitcoinfuncs import *
    from bitcoin import *
    from bip39wordlists import *


# TODO: Fix foreign language wordlists.
# Checks for everything but English aren't validating
# Figure out why!


class BIP39(object):
    def __init__(self, a=128, password=''):
        if isitint(a):
            try:
                assert a >= 32
                assert a <= 992
                assert a % 32 == 0
            except:
                raise Exception('Input integer for bits of entropy must be ' + \
                      'between 32 and 992 (inclusive), and be divisible by 32.')
            self.hex = sha512d(hexlify(os.urandom(80) + \
                       str(datetime.datetime.now()).encode("utf-8")))
            if a > 512:
                self.hex = self.hex + sha512d(hexlify(os.urandom(80) + \
                           str(datetime.datetime.now()).encode("utf-8")))
            self.hex = self.hex[:a//4]
        else:
            try:
                self.hex = hexstrlify(unhexlify(a))
            except:
                try:
                    self.hex = BIP39.wordstohex(a)
                except Exception as e:
                    if "Word list checksum is invalid." in str(e):
                        raise Exception("Word list checksum is invalid.")
                    else:
                        raise Exception("Input must be int for new " + \
                             "wordlist of input bit strength, a word " + \
                             "list separated by a single space (and " + \
                             "where applicable, lowercase), or a string " + \
                             "of hex in 4-byte multiples. All input must " + \
                             "be between 32 and 992 (inclusive) bits of " + \
                             "entropy and be divisible by 32.")
        assert len(self.hex) % 8 == 0
        assert len(self.hex) >= 8
        assert len(self.hex) <= 248
        self.password = password
        self.en = BIP39.hextowords(self.hex,'en')
        # self.es = BIP39.hextowords(self.hex,'es')
        # self.fr = BIP39.hextowords(self.hex,'fr')
        # self.jp = BIP39.hextowords(self.hex,'jp')
        # self.zh = BIP39.hextowords(self.hex,'chinese simplified')
        # self.zhtrad = BIP39.hextowords(self.hex,'chinese traditional')
        self.enbip32seed = BIP39.Bip32Seed(self.en,self.password)
        # self.esbip32seed = BIP39.Bip32Seed(self.es,self.password)
        # self.frbip32seed = BIP39.Bip32Seed(self.fr,self.password)
        # self.jpbip32seed = BIP39.Bip32Seed(self.jp,self.password)
        # self.zhbip32seed = BIP39.Bip32Seed(self.zh,self.password)
        # self.zhtradbip32seed = BIP39.Bip32Seed(self.zhtrad,self.password)

    def setpassword(self,password):
        self.password = password
        self.enbip32seed = BIP39.Bip32Seed(self.en,self.password)
        # self.esbip32seed = BIP39.Bip32Seed(self.es,self.password)
        # self.frbip32seed = BIP39.Bip32Seed(self.fr,self.password)
        # self.jpbip32seed = BIP39.Bip32Seed(self.jp,self.password)
        # self.zhbip32seed = BIP39.Bip32Seed(self.zh,self.password)
        # self.zhtradbip32seed = BIP39.Bip32Seed(self.zhtrad,self.password)

    def __str__(self):
        return self.en

    def __repr__(self):
        return self.en

    @staticmethod
    def hextowords(h,lang=''):
        WORD_LIST = ''
        if lang != '':
            lang = lang.lower()
        if lang == 'english' or lang == 'eng' or lang == 'en':
            WORD_LIST = BIP39ENGWORDLIST
        elif lang == 'spanish' or lang == 'español' or lang == 'espanol' or \
             lang == 'sp' or lang == 'span' or lang == 'es':
            WORD_LIST = BIP39SPANISHWORLDLIST
        elif lang == 'french' or lang == 'française' or lang == 'francaise' or \
             lang == 'fr':
            WORD_LIST = BIP39FRWORDLIST
        elif lang == 'japanese' or lang == 'nihongo' or lang == 'nihõŋɡo' \
          or lang == 'nihõŋŋo' or lang == '日本語' or lang == 'jp':
            WORD_LIST = BIP39JPWORDLIST
        elif lang == 'chinese' or ('chinese' in lang and 'simp' in lang) or \
             lang == '汉语' or lang == 'hànyǔ' or lang == 'hanyu' or \
             ('zh' in lang and 'simp' in lang) or \
             ('hànyǔ' in lang and 'simp' in lang) or \
             ('hanyu' in lang and 'simp' in lang) or lang == 'zh':
            WORD_LIST = BIP39ZHSIMPWORDLIST
        elif lang == '漢語' or ('chinese' in lang and 'trad' in lang) or \
             ('hànyǔ' in lang and 'trad' in lang) or \
             ('zh' in lang and 'trad' in lang) or \
             ('hanyu' in lang and 'trad' in lang):
            WORD_LIST = BIP39ZHTRADWORDLIST
        elif lang == '':
            WORD_LIST = BIP39ENGWORDLIST
        elif lang != '':
            raise Exception('Unknown language input.')
        assert len(h) % 8 == 0
        b = strlify(bin(int(h,16))).replace("0b","").replace("'","") \
                   .replace('"',"").replace("u","").zfill(len(h)*4)
        cslen = len(h)//8
        cs = strlify(bin(int(sha256(h),16))).replace("0b","").replace("'","") \
                    .replace('"',"").replace("u","").zfill(256)[:cslen]
        o = b + cs
        assert len(o) % 11 == 0
        binaryarray = [o[i:i+11] for i in range(0,len(o),11)]
        words = []
        for i in range(len(binaryarray)):
            words.append(WORD_LIST[int(binaryarray[i],2)])
        # if WORD_LIST == BIP39JPWORDLIST: # Specification dictates that JP wordlist use and accommodate ideographic space
            # out = u''
            # for word in words:
                # out = out + word.decode('latin-1') + u'\u3000'
            # out = out.rstrip(u'\u3000')
        else:
            out = ' '.join(words)
        return out

    @staticmethod
    def wordstohex(wordlist):
        if " " not in wordlist and u'\u3000' not in wordlist:
            newwordlist = ''
            for char in wordlist:
                newwordlist = newwordlist + char + ' '
            newwordlist = newwordlist[:-1]
            wordlist = newwordlist
        listtouse = None
        words = wordlist.lower().lstrip(" ").rstrip(" ") \
                        .replace(u'\u3000'," ").replace("  "," ")
        words = words.split(" ")
        assert len(words) <= 93
        assert len(words) >= 3
        assert len(words) % 3 == 0
        # langlists = [BIP39ENGWORDLIST,BIP39JPWORDLIST,BIP39SPANISHWORLDLIST,
                     # BIP39FRWORDLIST,BIP39ZHSIMPWORDLIST,BIP39ZHTRADWORDLIST]
        # for i in range(len(langlists)):
            # newlist = []
            # for j in range(len(langlists[i])):
                # newlist.append(normalize_input(langlists[i][j]))
            # try:
                # for word in words:
                    # assert word in langlists[i] or \
                           # word in newlist
            # except:
                # continue
            # else:
                # listtouse = langlists[i]
                # break
        # if listtouse == None:
            # raise Exception('Cannot read word list.')
        newlist = BIP39ENGWORDLIST

        b = ''
        newwords = []
        for i in range(len(words)):
            try:
                newwords.append(normalize_input(words[i]).lower())
            except:
                newwords.append(words[i].lower())
        for i in range(len(newwords)):
            b = b + (strlify(bin(int(newlist.index(newwords[i])))) \
                    .replace("0b","").replace("'","").replace('"',"") \
                    .replace("u","").zfill(11))
        cslen = len(b) % 32
        cs = b[-1*cslen:]
        b = b[:-1*cslen]
        h = dechex(int(b,2),1).zfill(8*len(newwords)//3)
        cs2 = strlify(str(bin(int(sha256(h),16)))).replace("0b","") \
                     .replace("'","").replace('"',"").replace("u","") \
                     .zfill(256)[:cslen]
        try:
            assert cs == cs2
        except:
            raise Exception("Word list checksum is invalid.")
        return h

    @staticmethod
    def Bip32Seed(words,password=""):
        try:
            words = normalize_input(words).lower()
        except:
            words = words.lower()
        try:
            password = normalize_input(password,False,True)
        except: pass
        try:    salt = 'mnemonic' + password
        except: salt = u'mnemonic' + password
        o = dechex(int(hexlify(PBKDF2(words,salt,2048,macmodule=hmac,
                               digestmodule=hashlib.sha512).read(64)),16),64)
        return o

