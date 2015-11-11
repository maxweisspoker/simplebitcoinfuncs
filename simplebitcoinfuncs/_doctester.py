#!/usr/bin/env python
# -*- coding: utf-8 -*-


'''
I removed all the doctests from everywhere else and put them here.
'''


from __future__ import print_function, division, absolute_import

try:
    from __builtin__ import bytes, str, open, super, range, zip, round, int, pow, object, input
except ImportError:    pass

try:
    from __builtin__ import raw_input as input
except:    pass

from codecs import decode
from binascii import hexlify, unhexlify

from hexhashes import *
from ecmath import *
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


def hexhashes_py___doctest():
    '''
    hexhashes.py tests:

    >>> sha256('')
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'

    >>> sha256('aabbccdd')
    '8d70d691c822d55638b6e7fd54cd94170c87d19eb1f628b757506ede5688d297'

    >>> sha512('')
    'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e'

    >>> sha512('aabbccdd')
    '48e218b30d4ea16305096fe35e84002a0d262eb3853131309423492228980c60238f9eed238285036f22e37c4662e40c80a461000a7aa9a03fb3cb6e4223e83b'

    >>> sha512d('')
    '826df068457df5dd195b437ab7e7739ff75d2672183f02bb8e1089fabcf97bd9dc80110cf42dbc7cff41c78ecb68d8ba78abe6b5178dea3984df8c55541bf949'

    >>> sha512d('aabbccdd')
    '46561839a3278e5cd3999450c8f89e459aa8c234fbee7935635db777d7dbd654bf7293c84cf64c318be0197a41c622a247a70024ff9d27f392c0d4a4da8d6354'

    >>> ripemd160('')
    '9c1185a5c5e9fc54612808977ee8f548b2258d31'

    >>> ripemd160('aabbccdd')
    '148164ccf60a825bc3250722074c3426a7f67fcb'

    >>> hash160('')
    'b472a266d0bd89c13706a4132ccfb16f7c3b9fcb'

    >>> hash160('aabbccdd')
    'd6e9254683798a28eabd2626fd573cf2cf3869f9'

    >>> hash256('')
    '5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456'

    >>> hash256('aabbccdd')
    '6a83c7f1def9386347c206e94c90559f49be557609fc1811bfe311b67ecef8b0'

    >>> hash512('')
    '6b4e6c1fe36504e12e6d9716f74250ecb6fefb2a83af8e8edee9caeb3f32ca4683eca58c50faa06afc40a15fdc4c706d296a6f859bfb9b22871d28a500baf7b1'

    >>> hash512('aabbccdd')
    '20df4f6c9244b517cb5dd1c3b1e13bb316a45f5b904fc57799b66389947186d266ad611ee282fdea6630da4dbc96015beba2faecc110782015df662c4abf6297'

    '''
    return



def ecmath_py___doctest():
    '''
    Many doctest for ecmath are done in a weird way. That is to ensure
    the same output for Python 2 and 3, so things like 4 vs 4L don't
    mess up the tests.

    >>> modinv(2521213890399410648018095333325722136449021566908310412768334520696982806641) == \
    17465617466841484688650846354295959695753514552349626970717521890536775674935
    True

    >>> modinv(-95700528412413679576195283092455617561285633360671739483652140770588235170392,N) == \
    11411284869303779416452608717884069348175089368882490102158000583211275329323
    True

    >>> x,y = ecadd( \
    4938373901174265576094805690384936437621390742743114714534166734031749709952, \
    23406007515733211420427986631155727216565925582529100160361434981966318828999, \
    11029270422249989266356636372380040023432092195222839243672437607748020962878, \
    12338920660869481789439141094019604918037726829679018934712977981859756778348)
    >>> x == 83336094426407305185582932726071265758876028986498851406936393497302545717601
    True
    >>> y == 71857134501436534997244054415723847888276629084374532235863885413095164252131
    True

    >>> x,y = ecsubtract( \
    4938373901174265576094805690384936437621390742743114714534166734031749709952, \
    23406007515733211420427986631155727216565925582529100160361434981966318828999, \
    11029270422249989266356636372380040023432092195222839243672437607748020962878, \
    12338920660869481789439141094019604918037726829679018934712977981859756778348)
    >>> x == 55597633869961612317309410433076836678766403763677101352598043583451378461409
    True
    >>> y == 26239925317332119257936947014113260047893818687460697966446999229620006489892
    True

    >>> x,y = ecdouble( \
    17122607971474055933869599824585174586417044884544686165239805207052395415204, \
    40838023179274613372805173210407024975579475223402894269126337256598864150690)
    >>> x == 72311113040667355501201059093433510680042205181920994715815687665050367873657
    True
    >>> y == 81202695815007557875587128276299271839897857009219307151962560322569452526782
    True

    >>> x,y = ecmultiply(Gx,Gy,42)
    >>> x == 115136800820456833737994126771386015026287095034625623644186278108926690779567
    True
    >>> y == 3479535755779840016334846590594739014278212596066547564422106861430200972724
    True

    >>> x,y = ecmultiply( \
    2521213890399410648018095333325722136449021566908310412768334520696982806641, \
    61992791029995100687584613680591045503872148133214804167999634260847801377258, \
    86160004736639257141798190143937095024102878958814199546049053726283481854320)
    >>> x == 84191613447606291376043707809973780390176222720060740978105574111402634616050
    True
    >>> y == 109474824470067519156060832976900905455196281901984947573736908658291479411212
    True

    >>> pow_mod(int(N//4),int(N//15),P) == \
    85863265686857850576725992990591539765753424982812429250530061375940639195105
    True
    '''
    return



def base58_py___doctest():
    '''
    >>> b58e('0000000000000000000000000000000000000000000000000000000000000000')
    '11111111111111111111111111111111273Yts'

    >>> b58e('80000000000000000000000000000000000000000000000000000000000000000101')
    'KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn'

    >>> b58e('80000000000000000000000000000000000000000000000000000000000000000101', False)
    '3tq8Vmhh9SN5XhjTGSWgx8iKk59XbKG6UH4oqpejRoF9ASt'

    >>> b58e('')
    '3QJmnh'

    >>> b58d('3A5vdSL9MQrKRijvxr8S3V2DQ918XPL1GL')
    '055c16274562a91d531f6043f86c68d3a0f65be42a'

    >>> b58d('11111111111111111111111111111111', False)
    '0000000000000000000000000000000000000000000000000000000000000000'

    >>> b58d('11111111111111111111111111111111273Yts')
    '0000000000000000000000000000000000000000000000000000000000000000'

    # Incorrect checksum, while check is True
    >>> b58d('11111111111111111111111111111111273YYY')
    Traceback (most recent call last):
    ...
    AssertionError

    >>> b58d('11111111111111111111111111111111273YYY', False)
    '00000000000000000000000000000000000000000000000000000000000000002b32d6d1'

    >>> b58d('')
    Traceback (most recent call last):
    ...
    AssertionError

    # str() because if unicode, Exception says character u'0' which fails
    # the doctest
    >>> b58d(str('XY0Z'))
    Traceback (most recent call last):
    ...
    Exception: Character '0' is not a valid base58 character
    '''
    return



def miscfuncs_py___doctest():
    '''
    >>> strlify(b'aabb')
    'aabb'
    >>> strlify(hexlify(unhexlify("aabb")))
    'aabb'
    >>> strlify('bb')
    'bb'
    >>> strlify(b'b')
    'b'
    >>> strlify('b')
    'b'

    >>> isitstring(55)
    False
    >>> isitstring('Hello')
    True
    >>> isitstring(u'Hello')
    True

    >>> isitint(4)
    True
    >>> isitint(2**256)
    True
    >>> isitint(-4)
    True
    >>> isitint(0)
    True
    >>> isitint('0')
    False
    >>> isitint('00')
    False
    >>> isitint(unhexlify('00'))
    False
    >>> isitint(4.0)
    False

    # Doctest for Py3 doesn't properly handle bytes completely,
    # hence using unhexlify
    >>> hexstrlify(bytes(unhexlify('bbc7f07e59670ffdbb6bbb')))
    'bbc7f07e59670ffdbb6bbb'

    >>> hexreverse('a1b2c3d4')
    'd4c3b2a1'

    >>> dechex(4,2)
    '0004'
    >>> dechex(0)
    '00'
    >>> dechex(0000)
    '00'
    >>> dechex(43528704357807084357809435278904235,16)
    '000862217d6e549c3fdf5c2e5b450bab'
    '''
    return



def miscbitcoinfuncs_py___doctest():
    '''
    >>> oppushdatalen(13)
    '0d'
    >>> oppushdatalen(105)
    '4c69'
    >>> oppushdatalen(436)
    '4db401'
    >>> oppushdatalen(4294967290)
    '4efaffffff'

    >>> intfromoppushdatalen('4efaffffff')
    4294967290
    >>> intfromoppushdatalen('4db401')
    436
    >>> intfromoppushdatalen('4c69')
    105
    >>> intfromoppushdatalen('0d')
    13
    >>> intfromoppushdatalen('4c69dd')
    Traceback (most recent call last):
    ...
    AssertionError
    >>> intfromoppushdatalen('0daa')
    Traceback (most recent call last):
    ...
    AssertionError

    >>> tovarint(250)
    'fa'
    >>> tovarint(253)
    'fdfd00'
    >>> tovarint(260)
    'fd0401'
    >>> tovarint(294967296)
    'fe00d89411'
    >>> tovarint(6418473620)
    'ff9422927e01000000'

    >>> numvarintbytes('b5')
    1
    >>> numvarintbytes('fb')
    1
    >>> numvarintbytes('fc')
    1
    >>> numvarintbytes('fd')
    3
    >>> numvarintbytes('fe')
    5
    >>> numvarintbytes('ff')
    9
    >>> numvarintbytes('fd0401')
    Traceback (most recent call last):
    ...
    AssertionError

    >>> fromvarint('ff9422927e01000000')
    6418473620
    >>> fromvarint('fe00d89411')
    294967296
    >>> fromvarint('fd0401')
    260
    >>> fromvarint('fdfd00')
    253
    >>> fromvarint('fc')
    252
    >>> fromvarint('fdfd0005')
    Traceback (most recent call last):
    ...
    AssertionError
    >>> fromvarint('c9')
    201

    >>> x = 'fd5d010048304502200187af928e9d155c4b1ac9c1c9118153239aba76774f775d7c1f9c3e106ff33c0221008822b0f658edec22274d0b6ae9de10ebf2da06b1bbdaaba4e50eb078f39e3d78014730440220795f0f4f5941a77ae032ecb9e33753788d7eb5cb0c78d805575d6b00a1d9bfed02203e1f4ad9332d1416ae01e27038e945bc9db59c732728a383a6f1ed2fb99da7a4014cc952410491bba2510912a5bd37da1fb5b1673010e43d2c6d812c514e91bfa9f2eb129e1c183329db55bd868e209aac2fbc02cb33d98fe74bf23f0c235d6126b1d8334f864104865c40293a680cb9c020e7b1e106d8c1916d3cef99aa431a56d253e69256dac09ef122b1a986818a7cb624532f062c1d1f8722084861c5c3291ccffef4ec687441048d2455d2403e08708fc1f556002f1b6cd83f992d085097f9974ab08a28838f07896fbab08f39495e15fa6fad6edbfb1e754e35fa1c7844c41f322a1863d4621353aeffffffff0140420f00000000001976a914ae56b4db13554d321c402db3961187aed1bbed5b88ac00000000'
    >>> getandstrip_varintdata(x)
    ('0048304502200187af928e9d155c4b1ac9c1c9118153239aba76774f775d7c1f9c3e106ff33c0221008822b0f658edec22274d0b6ae9de10ebf2da06b1bbdaaba4e50eb078f39e3d78014730440220795f0f4f5941a77ae032ecb9e33753788d7eb5cb0c78d805575d6b00a1d9bfed02203e1f4ad9332d1416ae01e27038e945bc9db59c732728a383a6f1ed2fb99da7a4014cc952410491bba2510912a5bd37da1fb5b1673010e43d2c6d812c514e91bfa9f2eb129e1c183329db55bd868e209aac2fbc02cb33d98fe74bf23f0c235d6126b1d8334f864104865c40293a680cb9c020e7b1e106d8c1916d3cef99aa431a56d253e69256dac09ef122b1a986818a7cb624532f062c1d1f8722084861c5c3291ccffef4ec687441048d2455d2403e08708fc1f556002f1b6cd83f992d085097f9974ab08a28838f07896fbab08f39495e15fa6fad6edbfb1e754e35fa1c7844c41f322a1863d4621353ae', 'ffffffff0140420f00000000001976a914ae56b4db13554d321c402db3961187aed1bbed5b88ac00000000')


    >>> inttoDER(23159624154826860047781259025922852200415127951164078404008335037124850950245)
    '02203333e1fba07e542a357c45103a2fa62c044af1000d21b54dc9c54de36aef2065'

    >>> inttoDER(59344652041488171117647191841137823404561998159176754666338830039597703962725)
    '0221008333e1fba07e542a357c45103a2fa62c044af1000d21b54dc9c54de36aef2065'

    >>> inttoDER(6783848548763080805863616406882737495015296602382933530988832128704613)
    '021e00fba07e542a357c45103a2fa62c044af1000d21b54dc9c54de36aef2065'

    >>> inttoDER(3332975375367798912146238475744224768789742116297740253407570016804965)
    '021d7ba07e542a357c45103a2fa62c044af1000d21b54dc9c54de36aef2065'

    >>> inttoLEB128(624485)
    'e58e26'

    >>> LEB128toint('e58e26')
    624485

    '''
    return



def bitcoin_py___doctest():
    '''
    >>> uncompress('03AB27DC61A8D60CEB3A3234E69B818F2DF5B79FD67E0CCFF474B788ACE319FBB8')
    '04ab27dc61a8d60ceb3a3234e69b818f2df5b79fd67e0ccff474b788ace319fbb89dff12fbeb8368d30d28bf6c00dd1900c89ba086b19dab33828557418d855267'

    >>> uncompress('02ab27dc61a8d60ceb3a3234e69b818f2df5b79fd67e0ccff474b788ace319fbb8')
    '04ab27dc61a8d60ceb3a3234e69b818f2df5b79fd67e0ccff474b788ace319fbb86200ed04147c972cf2d74093ff22e6ff37645f794e6254cc7d7aa8bd727aa9c8'

    >>> compress('04ab27dc61a8d60ceb3a3234e69b818f2df5b79fd67e0ccff474b788ace319fbb89dff12fbeb8368d30d28bf6c00dd1900c89ba086b19dab33828557418d855267')
    '03ab27dc61a8d60ceb3a3234e69b818f2df5b79fd67e0ccff474b788ace319fbb8'

    >>> compress('04ab27dc61a8d60ceb3a3234e69b818f2df5b79fd67e0ccff474b788ace319fbb86200ed04147c972cf2d74093ff22e6ff37645f794e6254cc7d7aa8bd727aa9c8')
    '02ab27dc61a8d60ceb3a3234e69b818f2df5b79fd67e0ccff474b788ace319fbb8'

    >>> privtopub('178f156436f88baaa8a42b41a4ad8d7612711ad1fa277e1d8ac64705d778413d')
    '03ab27dc61a8d60ceb3a3234e69b818f2df5b79fd67e0ccff474b788ace319fbb8'

    >>> privtopub('178f156436f88baaa8a42b41a4ad8d7612711ad1fa277e1d8ac64705d778413d', False)
    '04ab27dc61a8d60ceb3a3234e69b818f2df5b79fd67e0ccff474b788ace319fbb89dff12fbeb8368d30d28bf6c00dd1900c89ba086b19dab33828557418d855267'

    >>> addprivkeys('178f156436f88baaa8a42b41a4ad8d7612711ad1fa277e1d8ac64705d778413d', \
    '5a499293484e3dec9d452d0996d9566613bebfe75b7c49bb205517336254105d')
    '71d8a7f77f46c99745e9584b3b86e3dc262fdab955a3c7d8ab1b5e3939cc519a'

    >>> addprivkeys('ff8f156436f88baaa8a42b41a4ad8d7612711ad1fa277e1d8ac64705d778413d', \
    '5a499293484e3dec9d452d0996d9566613bebfe75b7c49bb205517336254105d')
    '59d8a7f77f46c99745e9584b3b86e3dd6b80fdd2a65b279ceb48ffac69961059'

    >>> subtractprivkeys('178f156436f88baaa8a42b41a4ad8d7612711ad1fa277e1d8ac64705d778413d', \
    '5a499293484e3dec9d452d0996d9566613bebfe75b7c49bb205517336254105d')
    'bd4582d0eeaa4dbe0b5efe380dd4370eb96137d14df3d49e2a438e5f455a7221'

    >>> multiplypriv('178f156436f88baaa8a42b41a4ad8d7612711ad1fa277e1d8ac64705d778413d', \
    '5a499293484e3dec9d452d0996d9566613bebfe75b7c49bb205517336254105d')
    'a08be4c08d9820284fc81896b465a08b0a95305cf364517d9d46ec7ae954321e'

    >>> multiplypub( \
    '04eee3998f3546c061cfedd989cc77280ba2777dff4ed437b00d43dd2942dae003a702ba24e6c79ca23f1890249639c2621f897618d51d633b5039f1f3a4f4e7d4', \
    '178f156436f88baaa8a42b41a4ad8d7612711ad1fa277e1d8ac64705d778413d')
    '02fdd25715a72408d662e844027d6deb58b76cb0b9a294ee490191a4ef40df4792'

    >>> multiplypub('02eee3998f3546c061cfedd989cc77280ba2777dff4ed437b00d43dd2942dae003', \
    '178f156436f88baaa8a42b41a4ad8d7612711ad1fa277e1d8ac64705d778413d', False)
    '04fdd25715a72408d662e844027d6deb58b76cb0b9a294ee490191a4ef40df47923efac534afd12d2fcd07c751ef4f6fac9286045df6e9e29608d56efc403a0438'

    >>> addpubs('02fdd25715a72408d662e844027d6deb58b76cb0b9a294ee490191a4ef40df4792', \
    '02eee3998f3546c061cfedd989cc77280ba2777dff4ed437b00d43dd2942dae003')
    '024abeabbdd5de7727bbb2ff5251d57310ef2607dab1e2889f4315474778b466a3'

    >>> subtractpubs( \
    '02fdd25715a72408d662e844027d6deb58b76cb0b9a294ee490191a4ef40df4792', \
    '02eee3998f3546c061cfedd989cc77280ba2777dff4ed437b00d43dd2942dae003')
    '02e3752f728d53e227f789be951fd899e36295c386f6c249940b5c9c275b4f908c'

    >>> pubtoaddress('02e3752f728d53e227f789be951fd899e36295c386f6c249940b5c9c275b4f908c')
    '18o5G4us8k5DscDdyFq1nx8iSE7RFy2euv'

    >>> pubtoaddress(uncompress('02e3752f728d53e227f789be951fd899e36295c386f6c249940b5c9c275b4f908c'))
    '1MtiJXjp3Vr8s1AtgK1veGLNnjhy3PrUxE'

    >>> validatepubkey('02E3752F728D53E227F789BE951FD899E36295C386F6C249940B5C9C275B4F908C')
    '02e3752f728d53e227f789be951fd899e36295c386f6c249940b5c9c275b4f908c'

    >>> validatepubkey('04e3752f728d53e227f789be951fd899e36295c386f6c249940b5c9c275b4f908c9a50cec685f8e2a1f77b216b60319c5b5da20cb1ad305af39c85c42a78cebf64')
    '04e3752f728d53e227f789be951fd899e36295c386f6c249940b5c9c275b4f908c9a50cec685f8e2a1f77b216b60319c5b5da20cb1ad305af39c85c42a78cebf64'

    >>> validatepubkey('04e3752f728d53e227f789be951fd899e36295c386f6c249940b5c9c275b4f908c9a50cec685f8e2a1f77b216b60319c5b5da20cb1ad305af39c85c42a78cebf65')
    False

    >>> validatepubkey('04e3752f728d53e227f789be951fd899e36295c386f6c249940b5c9c275b4f908c')
    False

    >>> validatepubkey('e3752f728d53e227f789be951fd899e36295c386f6c249940b5c9c275b4f908c')
    False

    >>> wiftohex("5KcCmPP68JhjXE3guHwMnA5aiYWvsMbQrpDJYkreLpgGQAroXDh")
    ('ebf4c9e128721400d4d8ac059c1aff929e9ad121518f744bfedf456592cd1dbd', '80', False)

    >>> wiftohex("L58NvunVdF8ngQas7okviK5DpN76mFttJsPJTAa7pVSJy1KbUUkL")
    ('ebf4c9e128721400d4d8ac059c1aff929e9ad121518f744bfedf456592cd1dbd', '80', True)

    >>> wiftohex("6uUqLX6roU6TbVtWqWRRzSAwMx2E7ctTbwDGL8Dyn1bmyKfS9f8")
    ('2f43829ce7f2985d4b4de7cbbb99b8d15843ad3f3149879ab20963f2978aeab6', 'b0', False)


    >>> privtohex('178f156436f88baaa8a42b41a4ad8d7612711ad1fa277e1d8ac64705d778413d')
    '178f156436f88baaa8a42b41a4ad8d7612711ad1fa277e1d8ac64705d778413d'

    >>> privtohex('5HzfMyinNsX6ohao4LxY6dssqxy9Tg5unjV1KCt9UCiJRZvq5Gv')
    '178f156436f88baaa8a42b41a4ad8d7612711ad1fa277e1d8ac64705d778413d'

    >>> privtohex('Kx1WKbMRHXyrd88AHm68FsmZR82pLjWfzrWcPMSkP4hHuHszrrZK')
    '178f156436f88baaa8a42b41a4ad8d7612711ad1fa277e1d8ac64705d778413d'

    >>> privtohex('T3qmmLebguxTPxm2qQ2zUEJwMyg8QpXZp4QsFA5Hx2sTRBUPvfom')
    '178f156436f88baaa8a42b41a4ad8d7612711ad1fa277e1d8ac64705d778413d'

    >>> privtohex(10656002286135494676906904972529529473002948329995631005275422314744862228797)
    '178f156436f88baaa8a42b41a4ad8d7612711ad1fa277e1d8ac64705d778413d'

    >>> privtohex(unhexlify('178f156436f88baaa8a42b41a4ad8d7612711ad1fa277e1d8ac64705d778413d'))
    '178f156436f88baaa8a42b41a4ad8d7612711ad1fa277e1d8ac64705d778413d'

    >>> privtohex("This is not a private key!")
    Traceback (most recent call last):
    ...
    Exception: Cannot interpret input key.

    >>> privtohex('T3qmmLebguxTPxm2qQ2zUEJwMyg8QpX')
    Traceback (most recent call last):
    ...
    Exception: Cannot interpret input key.


    >>> mycoin = Coin(u'ed4cbc48b674f3d3bce9f3f17ec7b9d8c03b5423afefd16a8c098ead535ec206','80','00')
    >>> mycoin.priv
    'ed4cbc48b674f3d3bce9f3f17ec7b9d8c03b5423afefd16a8c098ead535ec206'

    >>> mycoin.wifc
    'L5AzQaAcHxGhZUfzyHQqrJ76YFyzozEHZ1JNLbVQzbUScbPSw1hv'

    >>> mycoin.wifu
    '5Kco5tU6jMgMX1qFwtkTvmCoZunYDuqmz6WJyYq8FQfqrMrdMhE'

    >>> mycoin.addrc
    '1B7jusx1FY9u7XxsSYzLQtcohzf8sevxE4'

    >>> mycoin.pubprefix
    '00'

    '''
    return



def signandverify_py___doctest():
    '''
    >>> h = 'f7011e94125b5bba7f62eb25efe23339eb1637539206c87df3ee61b5ec6b023e'
    >>> p = 'c05694a7af0e01dceb63e5912a415c28d3fc823ca1fd3fa34d41afde03740466'
    >>> k = 4 # chosen by fair dice roll, guaranteed to be random
    >>> sign(h,p,k)
    '3045022100e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd130220598e37e2e66277ef4d0caf0e32d095debb3c744219508cd394b9747e548662b7'


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

    >>> checksigformat('3045022100e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd130220598e37e2e66277ef4d0caf0e32d095debb3c744219508cd394b9747e548662b7')
    True
    >>> checksigformat('3046022100e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13022100a671c81d199d8810b2f350f1cd2f6a1fff7268a495f813682b18ea0e7bafde8a')
    True
    >>> checksigformat('3046022100e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13022100a671c81d199d8810b2f350f1cd2f6a1fff7268a495f813682b18ea0e7bafde8a', \
    True)
    False

    >>> msg = '"You miss 100% of the shots you don\\'t take.  -- Wayne Gretzky"\\n    -- Michael Scott'
    >>> p = 'c05694a7af0e01dceb63e5912a415c28d3fc823ca1fd3fa34d41afde03740466'
    >>> k = 4 # chosen by fair dice roll, guaranteed to be random
    >>> signmsg(msg,p,True,k)
    'H+ST2/HBDYDzWB5JBJMLFATMbBOQDuB1hHT6lKvoxM0TBxoLMWsgrFmA3CGam/poUZPl/PukXCrYBzuwMW3Tyyo='

    >>> msg = '"You miss 100% of the shots you don\\'t take.  -- Wayne Gretzky"\\n    -- Michael Scott'
    >>> sig = 'H+ST2/HBDYDzWB5JBJMLFATMbBOQDuB1hHT6lKvoxM0TBxoLMWsgrFmA3CGam/poUZPl/PukXCrYBzuwMW3Tyyo='
    >>> x = verifymsg(msg,sig)
    >>> pub = '022587327dabe23ee608d8504d8bc3a341397db1c577370389f94ccd96bb59a077'
    >>> x == pub
    True

    >>> checkmsgsigformat('H+ST2/HBDYDzWB5JBJMLFATMbBOQDuB1hHT6lKvoxM0TBxoLMWsgrFmA3CGam/poUZPl/PukXCrYBzuwMW3Tyyo=')
    True
    >>> checkmsgsigformat('H+ST2/HBDYDzWB5JBJMLFATMbBOQDuB1hHT6lKvoxM0TBxoLMWsgrFmA3CGam/poUZPl/PukXCrYBzuwMW3Tyyo=')
    True
    >>> checkmsgsigformat('H+ST2/HBDYDzWB5JBJMLFATMbBOQDuB1hHT6lKvoxM0T+OX0zpTfU6Z/I95lZAWXrSbI3+sK7HVjuJauW2Jidhc=')
    True
    >>> checkmsgsigformat('H+ST2/HBDYDzWB5JBJMLFATMbBOQDuB1hHT6lKvoxM0T+OX0zpTfU6Z/I95lZAWXrSbI3+sK7HVjuJauW2Jidhc=',True)
    False
    '''
    return



def stealth_py___doctest():
    '''
    >>> paystealth("vJmvinTgWP1phdFnACjc64U5iMExyv7JcQJVZjMA15MRf2KzmqjSpgDjmj8NxaFfiMBUEjaydmNfLBCcXstVDfkjwRoFQw7rLHWdFk", \
    '824dc0ed612deca8664b3d421eaed28827eeb364ae76abc9a5924242ddca290a', 0)
    ('03e05931191100fa6cd072b1eda63079736464b950d2875e67f2ab2c8af9b07b8d', \
'0600000124025c6fb169b0ff1c95426fa073fadc62f50a6e98482ec8b3f26fb73006009d1c00')

    >>> receivestealth('af4afaeb40810e5f8abdbb177c31a2d310913f91cf556f5350bca10cbfe8b9ec', \
    'd39758028e201e8edf6d6eec6910ae4038f9b1db3f2d4e2d109ed833be94a026', \
    '03b8a715c9432b2b52af9d58aaaf0ccbdefe36d45e158589ecc21ba2f064ebb315')
    '6134396c3bc9a56ccaf80cd38728e6d3a7751524246e7924b21b08b0bfcc3cc4'
    '''
    return



def bip32_py___doctest():
    '''
    >>> testvector1 = BIP32('000102030405060708090a0b0c0d0e0f')
    >>> str(testvector1)
    'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi'
    >>> testvector1.child("m/0H/1/2H/2/1000000000")
    'xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76'
    >>> BIP32.xprvtoxpub(testvector1.child("m/0H/1/2H/2/1000000000"))
    'xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy'
    >>> testvector1.wif
    'L52XzL2cMkHxqxBXRyEpnPQZGUs3uKiL3R11XbAdHigRzDozKZeW'
    >>> testvector1["m/0H/1/2H/2/1000000000"].addr
    '1LZiqrop2HGR4qrH1ULZPyBpU6AUP49Uam'

    >>> testvector2 = BIP32('fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542')
    >>> testvector2.child("m/0/2147483647'/1/2147483646'/2")
    'xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j'
    >>> BIP32(BIP32.xprvtoxpub(testvector2.xprv)).child("m/0/2147483647'/1/2147483646'/2")
    Traceback (most recent call last):
    ...
    Exception: Input path contains hardened derivation. Cannot derive hardened child from public master key.

    >>> path = 'm/2/4352/0/231/8/0'
    >>> x = testvector1.child(path)
    >>> x
    'xprvA5hf574kbP5WQsvUYw7z8o7Sp5RmABwvw9wNFdeBotkbYfGedxB8UguRcxFPYVXDQzeb5SETXCCP8aXsyP3u2sNb42XdNZVYFUQ2nptCVUQ'
    >>> crack_test = BIP32.crack(testvector1.xpub,x,path)
    >>> crack_test == testvector1.xprv
    True
    >>> path = 'm/2/4352/0H/231/8/0'
    >>> BIP32.crack(testvector1.xpub,testvector1.child(path),path)
    Traceback (most recent call last):
    ...
    Exception: Path input indicates a hardened key. Cannot crack up a level from hardened keys.
    '''
    return



def bip39_py___doctest():
    '''
    >>> x = BIP39("00000000000000000000000000000000")
    >>> x.en
    'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
    >>> x.enbip32seed
    '5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4'
    >>> x.setpassword('TREZOR')
    >>> x.enbip32seed
    'c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04'
    >>> x.hex
    '00000000000000000000000000000000'
    '''
    return



def electrum1_py___doctest():
    '''
    >>> x = Electrum1('school eventually space front trip delicate drift score surely nine serve again')
    >>> x.words
    'school eventually space front trip delicate drift score surely nine serve again'
    >>> x.seed
    '950421e37c371408a14aeb9164d7a559'
    >>> x.seed == Electrum1.wordstohex(x.words)
    True
    >>> x.mpriv
    '9f8d1ab5da1f3133a87a6dff6daa1f8905906187ed72b6476fdc8a9a9aec68d5'
    >>> x.mpub
    '887867b2914527765faed6ac3d7fd1a4c373fda4a7d6350ac9adabc55befe34a50fc0ada9d1a439650653d445c5aad27d52d153cea3cf375578646a2b9820c58'
    >>> x[4.0][0]
    '5KJZT97WqVvLXwbbDyaVkGAcjK2AnMWBBy979BhWYbQ2yP7uJvb'
    >>> x.mpriv == Electrum1.crack(x.mpub,x[4.0][0])
    True
    '''
    return


def electrum2_py___doctest():
    '''
    >>> x = Electrum2('ride win pass silver noble position because balcony unveil perfect keen pyramid abuse')
    >>> str(x)
    'ride win pass silver noble position because balcony unveil perfect keen pyramid abuse'
    >>> x.bip32xpub
    'xpub661MyMwAqRbcGEHVXvE19EHH5Bpe7S4YFYXKPNAvCZ982MA1MyzkSAPSTmxWKqHjPsht3BDG2DxBfhiAKwrVzJFzVCTSovCEVXst6LPamzv'
    >>> x.hex
    '9af0f368c77311c27aa1cadc8d417ed5cb'
    >>> x[3][0]
    'Kwk1qQYC1NQkYrv2sgedWGEvSggKWMRbwrRTRCfVSbKbCrd2WfmL'
    >>> x[1.]
    ('L2cthViuxbGEMiiBcxhAvgtusg13mSXT94ZHv2WuYfmDZbu3q4dx', '02fa3aab7ebc4a45f4e2bf428b113751f0aa31b39110c2f039c46b4da39fa0477b', '1NSuzNYZJBU9G91HdQw9szoAiGuZJyXRWj')
    >>> x['m/4/8h/0'][2]
    '18GrpcrjMDTnNtbbgNUuphNS2DhC9YMhPC'
    >>> y = Electrum2.crack(x.bip32xpub,x[3][0])
    >>> y == x.bip32xprv
    True
    >>> Electrum2.validate('ride win pass silver noble position because balcony unveil perfect keen pyramid abuse')
    True
    >>> Electrum2.validate('ride win pass silver noble position because balcony unveil perfect keen pyramid pyramid')
    False
    >>> Electrum2('ride win pass silver noble position because balcony unveil perfect keen pyramid pyramid')
    Traceback (most recent call last):
    ...
    Exception: Word list invalid.
    '''
    return



if __name__ == "__main__":
    import doctest
    doctest.testmod()


