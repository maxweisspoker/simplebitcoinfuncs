#!/usr/bin/env python
# -*- coding: utf-8 -*-


import os
import base64
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


def sign(hash,priv,k=0):
    '''
    Returns a DER-encoded signature from a input of a hash and private
    key, and optionally a K value.

    Hash and private key inputs must be 64-char hex strings,
    k input is an int/long.

    >>> h = 'f7011e94125b5bba7f62eb25efe23339eb1637539206c87df3ee61b5ec6b023e'
    >>> p = 'c05694a7af0e01dceb63e5912a415c28d3fc823ca1fd3fa34d41afde03740466'
    >>> k = 4 # chosen by fair dice roll, guaranteed to be random
    >>> sign(h,p,k)
    '3045022100e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd130220598e37e2e66277ef4d0caf0e32d095debb3c744219508cd394b9747e548662b7'
    '''

    if k == 0:
        k = int(genkeyhex(),16)

    hash = int(hash,16)
    priv = int(priv,16)

    r = int(privtopub(dechex(k,32),True)[2:],16) % N
    s = ((hash + (r*priv)) * modinv(k,N)) % N

    # High S value is non-standard (soon to be invalid)
    if s > (N / 2):
        s = N - s

    r, s = inttoDER(r), inttoDER(s)
    olen = dechex(len(r+s)//2,1)
    return '30' + olen + r + s

def verify(hash,sig,pub,exceptonhighS=False):
    '''
    Verify a DER-encoded signature against a given hash and public key

    No checking of format is done in this function, so the signature
    format (and other inputs) should be verified as being the correct
    format prior to using this method.

    Hash is just 64-char hex string
    Public key format can be verified with validatepubkey() which is
      found in .bitcoin
    Signature format can be validated with checksigformat() which is
      the next function after this

    'exceptonhighS' is available because many Bitcoin implementations
    will soon be invalidating high S values in signatures, in order
    to reduce transaction malleability issues. I decided an exception
    was preferable to returning False, so as to be distinct from a bad
    signature.

    >>> h = 'f7011e94125b5bba7f62eb25efe23339eb1637539206c87df3ee61b5ec6b023e'
    >>> sig = '3045022100e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd130220598e37e2e66277ef4d0caf0e32d095debb3c744219508cd394b9747e548662b7'
    >>> pub = '022587327dabe23ee608d8504d8bc3a341397db1c577370389f94ccd96bb59a077'
    >>> verify(h,sig,pub)
    True
    >>> sig = '3046022100e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13022100a671c81d199d8810b2f350f1cd2f6a1fff7268a495f813682b18ea0e7bafde8a'
    >>> verify(h,sig,pub)
    True
    >>> verify(h,sig,uncompress(pub))
    True
    >>> verify(h,sig,pub,True)
    Traceback (most recent call last):
    ...
    TypeError: High S value.
    '''

    rlen = 2*int(sig[6:8],16)
    r = int(sig[8:8+(rlen)],16)
    s = int(sig[(12+rlen):],16) # Ignoring s-len; format dictates it
                                #   will be to the end of string
    assert r < N

    if exceptonhighS:
        if s > (N / 2):
            raise TypeError("High S value.")

    w = modinv(s,N)
    x = int(addpubs(
              privtopub(dechex((int(hash,16) * w) % N,32),False),
              multiplypub(pub,dechex((r*w) % N,32),False),
            False)[2:66],16)
    return x==r


def checksigformat(a,invalidatehighS=False):
    '''
    Checks input to see if it's a correctly formatted DER Bitcoin
    signature in hex string format.

    Returns True/False.  If it excepts, there's a different problem
    unrelated to the signature...

    This does NOT valid the signature in any way, it ONLY checks that
    it is formatted properly.

    If invalidatehighS is True, this function will return False on an
    otherwise valid signature format if it has a high S value.
    '''

    try:
        a = hexstrlify(unhexlify(a))
    except:
        return False

    try:
        rlen = 2*int(a[6:8],16)
        slen = 2*int(a[(10+rlen):(12+rlen)],16)
        r = a[8:8+(rlen)]
        s1 = a[(12+rlen):]
        s2 = a[(12+rlen):(12+rlen+slen)]

        assert s1 == s2
        s1 = int(s1,16)
        assert s1 < N
        assert a[:2] == '30'
        assert len(a) == ((2*int(a[2:4],16)) + 4)
        assert a[4:6] == '02'
        assert a[(8+rlen):(10+rlen)] == '02'

        if int(dechex(int(r,16))[:2],16) > 127:
            assert r[:2] == '00'
            assert r[2:4] != '00'
        else:
            assert r[:2] != '00'

        if int(dechex(s1)[:2],16) > 127:
            assert s2[:2] == '00'
            assert s2[2:4] != '00'
        else:
            assert s2[:2] != '00'

        assert len(r) < 67
        assert len(s2) < 67

    except AssertionError:
        return False

    except Exception as e:
        raise Exception(str(e))

    if invalidatehighS:
        if s1 > (N / 2):
            return False

    return True


def signmsg(msg,priv,iscompressed,k=0):
    '''
    Sign a message -- the message itself, not a hash -- with a given
    private key.

    Input private key must be hex, NOT WIF.  Use wiftohex() found in
    .bitcoin in order to get the hex private key and whether it is
    (or rather, its public key is) compressed.

    'iscompressed' is True/False bool for whether or not to indicate
    compression on the public key that corresponds to the input
    private key hex.

    'iscompressed' is not defaulted to True like it is in most other
    functions, because it really matters whether you use it. All
    software implementations treat uncompressed and compressed keys as
    entirely different, and a valid message signature will NOT
    validate if the public key compression is not correct. Whereas for
    transaction signatures, only the r-value is checked, message
    signature validation additionally checks/verifies public key
    compression. So you must manually set it!

    Also, note that message signatures are an entirely different
    format from DER-encoded transaction signatures.

    Sample message, which includes the quotation marks, and has a new
    line and 4 spaces after the new line:

    "You miss 100% of the shots you don't take.  -- Wayne Gretzky"
        -- Michael Scott

    >>> msg = '"You miss 100% of the shots you don\\'t take.  -- Wayne Gretzky"\\n    -- Michael Scott'
    >>> p = 'c05694a7af0e01dceb63e5912a415c28d3fc823ca1fd3fa34d41afde03740466'
    >>> k = 4 # chosen by fair dice roll, guaranteed to be random
    >>> signmsg(msg,p,True,k)
    'H+ST2/HBDYDzWB5JBJMLFATMbBOQDuB1hHT6lKvoxM0TBxoLMWsgrFmA3CGam/poUZPl/PukXCrYBzuwMW3Tyyo='

    Your software should then translate that data set into something akin to:

    -----BEGIN BITCOIN SIGNED MESSAGE-----
    "You miss 100% of the shots you don't take.  -- Wayne Gretzky"
        -- Michael Scott
    -----BEGIN BITCOIN SIGNATURE-----
    Address: 1AuZ7wby1rUVzwFvFgySeTFS7JcHN2TeGs

    H+ST2/HBDYDzWB5JBJMLFATMbBOQDuB1hHT6lKvoxM0TBxoLMWsgrFmA3CGam/poUZPl/PukXCrYBzuwMW3Tyyo=
    -----END BITCOIN SIGNATURE-----
    '''

    omsg = msg

    # Stripping carraige returns is standard practice in every
    # implementation I found, including Bitcoin Core
    msg = msg.replace("\r\n","\n")

    msg1 = hexstrlify(bytearray("\x18Bitcoin Signed Message:\n",'utf-8'))
    msg2 = tovarint(len(msg))
    msg3 = hexstrlify(bytearray(msg,'utf-8'))
    msg = hash256(msg1 + msg2 + msg3)


    sig = sign(msg,priv,k)

    # Bitcoin message signature format doesn't use DER leading '00's
    # Although, r/s must be 64-char, so they are zfilled to that
    rlen = 2*int(sig[6:8],16)
    r = sig[8:8+(rlen)].lstrip("0").zfill(64)
    slen = 2*int(sig[10+(rlen):12+(rlen)],16)
    s = sig[12+(rlen):(12+(rlen)+(slen))].lstrip("0").zfill(64)

    pubkey = privtopub(priv,iscompressed)
    for i in range(4):
        prefix = 27 + i
        if iscompressed:
            prefix = prefix + 4
        o = base64.b64encode(unhexlify(dechex(prefix,1) + r + s))
        if str(o)[:2] == "b'": # Fuck you, Python 3
            o = str(o)[2:-1]
        if verifymsg(omsg,o) == pubkey:
            return o

    raise Exception("Unknown failure. This method should never reach the end.")


def verifymsg(msg,sig):
    '''
    Compares the message and input signature, and outputs what the
    corresponding public key is that would make that message/signature
    pair valid.

    I didn't set it to take in a pubkey and output True/False because
    sometimes it is useful to have the resulting key, even if the
    msg/sig pair is invalid.
    (And not just in the signmsg() function above.)

    Also, worth remembering that message signatures are an entirely
    different format than DER-encoded transaction signatures.

    >>> msg = '"You miss 100% of the shots you don\\'t take.  -- Wayne Gretzky"\\n    -- Michael Scott'
    >>> sig = 'H+ST2/HBDYDzWB5JBJMLFATMbBOQDuB1hHT6lKvoxM0TBxoLMWsgrFmA3CGam/poUZPl/PukXCrYBzuwMW3Tyyo='
    >>> x = verifymsg(msg,sig)
    >>> pub = '022587327dabe23ee608d8504d8bc3a341397db1c577370389f94ccd96bb59a077'
    >>> x == pub
    True
    '''

    msg = msg.replace("\r\n","\n")
    # Again, standard convention to remove returns

    msg1 = hexstrlify(bytearray("\x18Bitcoin Signed Message:\n",'utf-8'))
    msg2 = tovarint(len(msg))
    msg3 = hexstrlify(bytearray(msg,'utf-8'))
    msg = hash256(msg1 + msg2 + msg3)

    sig = hexstrlify(base64.b64decode(sig))

    r = int(sig[2:66],16)
    s = int(sig[66:],16)

    prefix = int(sig[:2],16)
    if prefix > 30:
        out_compressed = True
        prefix = prefix - 4
    else:
        out_compressed = False
    prefix = prefix - 27

    m = int(N*prefix) if prefix > 1 else 0
    x = (r + int(m//2)) % N
    a = (pow_mod(x, 3, P) + 7) % P
    b = pow_mod(a, ((P+1)//4), P)
    if (b % 2) != prefix:
        y = (-b % P)
    else:
        y = b

    x, y = dechex(x,32), dechex(y,32)
    pubkey = "04" + x + y

    negative_msg = dechex((N - int(msg,16)),32)
    modinv_r = dechex(modinv(r, N),32)
    pubkey = multiplypub(
                   addpubs(
                     multiplypub(pubkey,dechex(s,32),False),
                     privtopub(negative_msg,False),False),
                   modinv_r,False)

    if out_compressed:
        pubkey = compress(pubkey)
    return strlify(pubkey)


def checkmsgsigformat(sig,invalidatehighS=False):
    try:
        sig = hexstrlify(base64.b64decode(sig))
        assert len(sig) == 130
        prefix = int(sig[:2],16)
        assert prefix > 26 and prefix < 35
        if invalidatehighS:
            assert int(sig[-64:],16) <= (N / 2)
    except AssertionError:
        return False
    except Exception as e:
        raise Exception(str(e))
    return True

