#!/usr/bin/env python
# -*- coding: utf-8 -*-


'''
A set of miscellaneous functions to save me from headaches related
to Python 2/3 compatibility issues and other common annoyances.
'''


import sys
import unicodedata
from binascii import hexlify, unhexlify
try:
    from codecs import decode
except ImportError:
    pass


def strlify(a):
    '''
    Used to turn hexlify() into hex string.

    Does nothing in Python 2, but is necessary for Python 3, so that
    all inputs and outputs are always the same encoding.  Most of the
    time it doesn't matter, but some functions in Python 3 brick when
    they get bytes instead of a string, so it's safer to just
    strlify() everything.

    In Python 3 for example (examples commented out for doctest):
#   >>> hexlify(unhexlify("a1b2c3"))
    b'a1b2c3'
#   >>> b'a1b2c3' == 'a1b2c3'
    False
#   >>> strlify(hexlify(unhexlify("a1b2c3")))
    'a1b2c3'

    Whereas in Python 2, the results would be:
#   >>> hexlify(unhexlify("a1b2c3"))
    'a1b2c3'
#   >>> b'a1b2c3' == 'a1b2c3'
    True
#   >>> strlify(hexlify(unhexlify("a1b2c3")))
    'a1b2c3'

    Safe to use redundantly on hex and base64 that may or may not be
    byte objects, as well as base58, since hex and base64 and base58
    strings will never have "b'" in the middle of them.

    Obviously it's NOT safe to use on random strings which might have
    "b'" in the middle of the string.

    Use this for making sure base 16/58/64 objects are in string
    format.

    Use normalize_input() below to convert unicode objects back to
    ascii strings when possible.
    '''

    if a == b'b' or a == 'b':
        return 'b'

    return str(a).rstrip("'").replace("b'","",1).replace("'","")
    # rstrip must go first so that strings like "b'adcb'" don't get
    #     the right b lopped off.


def isitstring(i):
    if sys.version_info[0] == 2:
        if isinstance(i,str) or isinstance(i,unicode) or isinstance(i,basestring):
            return True
        else:
            return False
    else:
        if isinstance(i,str):
            return True
        else:
            return False


def isitint(i):
    if sys.version_info[0] == 2:
        if isinstance(i,int) or isinstance(i,long):
            return True
        else:
            return False
    else:
        if isinstance(i,int):
            return True
        else:
            return False


def hexstrlify(a):
    return strlify(hexlify(a))


def hexreverse(a):
    return hexstrlify(unhexlify(a)[::-1])


def dechex(num,zfill=0):
    '''
    Simple integer to hex converter.

    The zfill is the number of bytes, even though the input is a hex
    string, which means that the actual zfill is 2x what you might
    initially think it would be.

    For example:
    >>> dechex(4,2)
    '0004'
    '''

    if not isitint(num):
        raise TypeError("Input must be integer/long.")
    o = hex(num).lstrip("0x").rstrip("L")
    if o == "" or o == "0":
        o = '00'
    try:
        o = unhexlify(o)
    except:
        o = unhexlify("0"+o)
    if o == b'\x00' or o == 0:
        o = '00'
    else:
        o = hexstrlify(o)
    for i in range((2*zfill)-len(o)):
        o = "0" + o
    if len(o) % 2:
        o = "0" + o
    return str(o)


def normalize_input(input,preferunicodeoverstring=False,nfconly=False):
    '''
    This looks dirty as crap, but the try/catch failure series goes in
    the correct order and it's a lot easier to use this most of the
    time, and it works for every situation I needed to use it in. That
    said, I'm kind of hoping nobody ever sees this...
    '''

    if nfconly:
        try:
            return unhexlify(hexlify(unicodedata.normalize('NFC',unicode(input)).encode('utf-8')))
        except:
            try:
                return unhexlify(hexlify(unicodedata.normalize('NFC',input).encode('utf-8'))).decode('utf-8')
            except:
                try:
                    return unhexlify(hexlify(unicodedata.normalize('NFC',unicode(input,'utf-8')).encode('utf-8')))
                except:
                    raise Exception("Unable to NFC normalize.")
    if sys.version_info[0] == 2:
        input = unicode(input)
    if preferunicodeoverstring:
        return unicodedata.normalize('NFKD',input)
    else:
        try:
            return str(unicodedata.normalize('NFKD',input))
        except:
            return unicodedata.normalize('NFKD',input)

