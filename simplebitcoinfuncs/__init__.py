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

try:
    #from .hexhashes import *  # Can still be explicity imported separately
    #from .ecmath import *     # but not including by default
    from .base58 import *
    from .miscfuncs import *
    from .miscbitcoinfuncs import *
    from .bitcoin import *
    from .signandverify import *
    from .stealth import *
    from .bip32 import *
    from .bip39 import *
    from .electrum1 import *
    from .electrum2 import *

# Doctester excepts on relative import
except ValueError:
    #from hexhashes import *
    #from ecmath import *
    from base58 import *
    from miscfuncs import *
    from miscbitcoinfuncs import *
    from bitcoin import *
    from signandverify import *
    from stealth import *
    from bip32 import *
    from bip39 import *
    from electrum1 import *
    from electrum2 import *
except SystemError:
    #from hexhashes import *
    #from ecmath import *
    from base58 import *
    from miscfuncs import *
    from miscbitcoinfuncs import *
    from bitcoin import *
    from signandverify import *
    from stealth import *
    from bip32 import *
    from bip39 import *
    from electrum1 import *
    from electrum2 import *

