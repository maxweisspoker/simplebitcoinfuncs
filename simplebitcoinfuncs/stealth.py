#!/usr/bin/env python
# -*- coding: utf-8 -*-


from binascii import hexlify, unhexlify
try:
    from .hexhashes import *
    from .base58 import *
    from .miscfuncs import *
    from .miscbitcoinfuncs import *
    from .bitcoin import *
except ValueError:
    from hexhashes import *
    from base58 import *
    from miscfuncs import *
    from miscbitcoinfuncs import *
    from bitcoin import *
except SystemError:
    from hexhashes import *
    from base58 import *
    from miscfuncs import *
    from miscbitcoinfuncs import *
    from bitcoin import *


def paystealth(stealthaddr,ephempriv=genkeyhex(),
               _doctest_nonce=(int(genkeyhex(),16) % (2**32))):
    '''
    Input a stealth address, and optionally an ephemeral private key,
    and generate a payment pubkey and stealth OP_RETURN data.

    (The OP_RETURN data is just a nonce and the ephemeral public key.)

    Works with standard single spend key stealth addresses, which
    begin with the '2a00' version bytes, and have 00-08 prefix bits
    and any 1-byte prefix.

    Prefix ff with 08 prefix bits and nonce starts at 0:
    >>> paystealth("vJmvinTgWP1phdFnACjc64U5iMExyv7JcQJVZjMA15MRf2KzmqjSpgDjmj8NxaFfiMBUEjaydmNfLBCcXstVDfkjwRoFQw7rLHWdFk", \
    '824dc0ed612deca8664b3d421eaed28827eeb364ae76abc9a5924242ddca290a', 0)
    ('03e05931191100fa6cd072b1eda63079736464b950d2875e67f2ab2c8af9b07b8d', \
'0600000124025c6fb169b0ff1c95426fa073fadc62f50a6e98482ec8b3f26fb73006009d1c00')
    '''

    addrhex = b58d(stealthaddr)

    assert len(addrhex) == 142
    assert int(addrhex[-4:-2],16) < 9
    # Assume one spend key, and 1-byte prefix and prefix-bits

    assert addrhex[:4] == '2a00'
    assert addrhex[70:72] == '01'

    scanpub = addrhex[4:70]
    spendpub = addrhex[72:-4]
    ephempub = privtopub(ephempriv,True)
    secret = sha256(multiplypub(scanpub,ephempriv,True))
    paykey = addpubs(spendpub,privtopub(secret,False),True)

    nonce = _doctest_nonce
    while True:
        if nonce > 4294967295:
            nonce = 0
        noncehex = dechex(nonce,4)
        hashprefix = unhexlify(hash256('6a2606' + noncehex + ephempub))[::-1][:4]
        prebits = int(addrhex[-4:-2],16)
        if prebits == 0:
           break

        prefix = unhexlify(addrhex[-2:])
        # Location of prefix should be explicit if it's ever more than 1 byte

        bytepos = 0
        cont = False
        while prebits > 8: # Not necessary with asserted 1-byte prefix
            if hexstrlify(prefix)[2*bytepos:(2*bytepos)+2] != \
               hexstrlify(hashprefix)[2*bytepos:(2*bytepos)+2]:
                cont = True
                break
            prebits = prebits - 8
            bytepos = bytepos + 1
        if cont:
            continue

        prefixhex = hexstrlify(prefix)[2*bytepos:(2*bytepos)+2]
        if prefixhex == "": prefixhex = hexstrlify(b"00")
        hashprefixhex = hexstrlify(hashprefix)[2*bytepos:(2*bytepos)+2]
        if hashprefixhex == "": hashprefixhex = hexstrlify(b"00")
        prefixbits = (((1 << (8 - prebits)) - 1) ^ 0xff) & int(prefixhex, 16)
        hashbits = (((1 << (8 - prebits)) - 1) ^ 0xff) & int(hashprefixhex, 16)
        if prefixbits == hashbits:
            cont = False
        else:
            cont = True
        if not cont:
            break
        nonce += 1
        if nonce == _doctest_nonce:
            raise Exception("No valid nonce was found. A different ephemeral key must be used.")
    return paykey, '06' + noncehex + ephempub


def receivestealth(scanpriv,spendpriv,ephempub):
    '''
    Derive the private key for a stealth payment, using the scan and
    spend private keys, and the ephemeral public key.

    Input private keys should be 64-char hex strings, and ephemeral
    public key should be a 66-char hex compressed public key.

    >>> receivestealth('af4afaeb40810e5f8abdbb177c31a2d310913f91cf556f5350bca10cbfe8b9ec', \
    'd39758028e201e8edf6d6eec6910ae4038f9b1db3f2d4e2d109ed833be94a026', \
    '03b8a715c9432b2b52af9d58aaaf0ccbdefe36d45e158589ecc21ba2f064ebb315')
    '6134396c3bc9a56ccaf80cd38728e6d3a7751524246e7924b21b08b0bfcc3cc4'
    '''

    return addprivkeys(sha256(multiplypub(ephempub,scanpriv,True)),spendpriv)


def newstealthaddr(scanpriv=genkeyhex(), spendpriv=genkeyhex(), \
                  prefixlen=1, prefixbyte='00'):
    scanpriv = privtohex(scanpriv)
    spendpriv = privtohex(spendpriv)
    prefixlen = int(prefixlen)
    assert prefixlen > 0 and prefixlen < 9
    prefixbyte = hexstrlify(unhexlify(prefixbyte))
    assert len(prefixbyte) == 2
    return scanpriv, spendpriv, \
           b58e('2a00' + privtopub(scanpriv,True) + '01' + \
                privtopub(spendpriv,True) + dechex(prefixlen,1) + \
                prefixbyte)

