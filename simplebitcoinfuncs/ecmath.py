#!/usr/bin/env python
# -*- coding: utf-8 -*-


'''
Elliptic curve math for the bitcoin curve, used in almost every
Bitcoin function.

For example, to get a public key from a private key, you multiply the
private key by the generator point using the ecmultiply() function.
It's that simple.

Much code taken from James D'Angelo's excellent introduction to
Bitcoin math:
https://www.youtube.com/watch?v=U2bw_N6kQL8

The whole "Bitcoin Blackboard 101" series is amazing, and very worth
watching.

Code taken from:
https://github.com/wobine/blackboard101/blob/master/EllipticCurvesPart5-TheMagic-SigningAndVerifying.py

Bitcoin curve: y**2 = x**3 + 7
Curve is of the family y**2 = x**3 + (A*x) + B
with A=0 and B=7
Using the constants immediately below, this is known as the secp256k1
curve. I really don't know more than that, I copied this code just to
get an idea of what was going on from a programming perspective. I
don't understand the math at any relevent level.
'''


# Prime field (2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 -1)
P = 115792089237316195423570985008687907853269984665640564039457584007908834671663


# Curve order (number of points in the field)
N = 115792089237316195423570985008687907852837564279074904382605163141518161494337


# Generator point
Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424

# Just for interest, the private key for the generator point is 1.
# So the generator is the two  -- uncompressed and compressed -- privkey/address pairs:
# ("5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf", "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm")
# ("KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn", "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH")


def modinv(a,n=P):
    lm, hm = 1, 0
    low, high = a % n, n
    while low > 1:
        ratio = high // low
        nm, new = hm - lm*ratio, high - low*ratio
        lm, low, hm, high = nm, new, lm, low
    return lm % n


def ecadd(xp,yp,xq,yq):
    m = ((yq-yp) * modinv(xq-xp,P)) % P
    xr = (m*m-xp-xq) % P
    yr = (m*(xp-xr)-yp) % P
    return xr, yr


def ecsubtract(xp,yp,xq,yq):
    return ecadd(xp,yp,xq,((P-yq) % P))


def ecdouble(xp,yp):
    ln = 3*xp*xp
    ld = 2*yp
    lam = (ln * modinv(ld,P)) % P
    xr = (lam**2 - 2*xp) % P
    yr = (lam*(xp-xr) - yp) % P
    return xr, yr


def ecmultiply(xs,ys,scalar):
    if scalar == 0 or scalar >= N:
        raise Exception("Invalid scalar.")
    scalarbin = str(bin(scalar)).lstrip('0b')
    Qx,Qy=xs,ys
    for i in range (1, len(scalarbin)):
        Qx, Qy = ecdouble(Qx,Qy)
        if scalarbin[i] == '1':
            Qx,Qy=ecadd(Qx,Qy,xs,ys)
    return Qx, Qy


def pow_mod(x,y,z):
    n = 1
    while y:
        if y & 1:
            n = n * x % z
        y >>= 1
        x = x * x % z
    return n

