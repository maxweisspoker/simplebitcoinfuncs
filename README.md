## simplebitcoinfuncs
Simple, easy, and quick Python 2/3 functions for common Bitcoin operations


There is currently no cli, although that is planned for the future. Right now though, these can only be imported through Python. If you want a good cli app for functions similar to these, I suggest Vitalik Buterin's pybitcointools.

These functions were written to help me learn and understand Bitcoin, and to help me learn and understand Python. These are some of the first things I wrote in Python, but they work great.

Hex output is always a string of hex, not bytes or anything else. Hex inputs are usually supposed to be a string as well. In the function list, I will try to be very clear about what the input and output is. For math operations, if an input is a hex public key, it can, unless otherwise specified, be compressed or uncompressed. You shouldn't ever need to use the keyword arg names, but if you want to, you need to check the actual functions for the real keyword arg names, since I changed some of them below for clarification's sake.


List of functions
-----------------

Base58 encoding:

    b58e(hex_string, include_checksum_in_output=True):
        returns string

    b58d(encoded_string, verify_and_strip_checksum=True):
        returns hex_string


Bitcoin-related operations:

    genkey(compressed=True, prefix_byte='80'):
        retuns randomly_generated_ascii_wif_privkey

    compress(uncompressed_pubkey_hex_string):
        returns uncompressed_pub_hex_string

    uncompress(compressed_pubkey_hex_string):
        returns compressed_pub_hex_string

    privtopub(64_char_hex_string, output_compressed_pub=True):
        returns pubkey_hex_string

    addprivkeys(64_char_hex_string, 64_char_hex_string):
        returns 64_char_hex_string

    subtractprivkeys(64_char_hex_string, 64_char_hex_string):
        returns 64_char_hex_string

    multiplypriv(64_char_hex_string, 64_char_hex_string):
        returns 64_char_hex_string

    multiplypub(pubkey_hex_string, 64_char_hex_string_privkey, output_compressed_pub=True):
        returns pubkey_hex_string

    addpubs(pub1_hex_string, pub2_hex_string, output_compressed_pub=True):
        returns pubkey_hex_string

    subtractpubs(pub1_hex_string, pub2_hex_string, output_compressed_pub=True):
        returns pubkey_hex_string

    pubtoaddress(pubkey_hex_string, address_prefix='00'):
        returns address_string

    validatepubkey(test_input):
        returns pubkey_hex_string if is_valid_pubkey else returns False

    wiftohex(wif_string):
        returns tuple of (64char_hex_string, 2_char_hexstr_prefix_byte, bool_was_it_compressed)

    privtohex(almost_any_input_type):
        returns 64_char_hex_string

    class Coin(hexstr_privkey_or_pubkey, priv_prefix='80', addr_prefix=2_char_hexstr_of_int-privprefix-minus-128):
        Holds info about a key, including:
            self.privprefix    (2_char_hexstr)
            self.pubprefix     (2_char_hexstr)
            self.priv          (64_char_hexstr) or False if pubkey used on initialization
            self.wifc          (wif_string_compressed) or False if pubkey used on initialization
            self.wifu          (wif_string_uncompressed) or False if pubkey used on initialization
            self.pubc          (hexstr_compressed)
            self.pubu          (hexstr_uncompressed)
            self.hash160c      (40_char_hex_string)
            self.hash160u      (40_char_hex_string)
            self.addrc         (compressed_address_string)
            self.addru         (uncompressed_address_string)


Signing and Verifying:

    sign(64_char_hexstr_hash, 64_char_hexstr_privkey, k=int(privtohex(genkey()),16)):
        returns DER_formatted_hex_string_signature_with_low_S

    verify(64_char_hash, hexstr_DER_sig, pubkey_hexstr, fail_on_high_S=False):
        returns bool_True_or_False

    signmsg(message_text_string_NOT_hash, 64_char_hexstr_privkey, indicate_compressed=True, k=int(privtohex(genkey()),16)):
        returns string_base64_encoded_signature

    verifymsg(message_text_string_NOT_hash, string_base64_encoded_signature):
        returns hex_string_pubkey


Stealth Address Payments:

    newstealthaddr(scanpriv=new_random, spend_priv=new_random, prefixbyte_check=1, prefixbyte='00'):
        returns tuple of (scan_64char_hexstr_priv, spend_64char_hexstr_priv, stealth_address_string)

    paystealth(stealth_addr_string, 64_char_ephemeral_privkey=random_new_key):
        returns tuple of (hexstr_pubkey_to_pay, hexstr_opreturn_data)

    receivestealth(scan_priv_hexstr, spend_priv_hexstr, hexstr_ephemeral_pubkey):
        returns hexstr_privkey


BIP 0032 Hierarchical Deterministic keys:

    class BIP32(hexstr_seed_or_xpub-xprv_string_or_omit_for_new_random_key, is_testnet_key=False):
        Holds info about a BIP32 key, as well as a few useful functions.
        Info includes:
            self.xprv            (xprv_str)
            self.xpub            (xpub_str)
            self.deserialized    (hex_str)
            self.wif             (wif_privkey_str)
            self.pub             (hexstr_compressed_pubkey)
            self.addr            (compressed_address_str)
            self.chaincode       (hexstr_chaincode)
            self.parentfpr       (hexstr_parent_short_fingerprint)
            self.fpr             (hexstr_self_short_fingerprint)
            self.depth           (int_self_depth)
            self.index           (int_self_index)

            self.ishard():
                returns bool_True_False

            self.child(path_string):
                returns string_xprv-xpub_for_input_path
                # path format = "m/1/4h/0"

            self[path]  aka  self.__getitem__(path):
                same as self.child() but returns BIP32 object instead of string

            self.__str__() and self.__repr__():
                returns xprv-xpub_string

        @staticmethods

        BIP32.ckd(xprv-xpub_string, int_new_child_index):
            returns xprv-xpub_string

        BIP32.genmaster(hexstr_seed, is_testnet=False):
            returns xprv_string

        BIP32.xprvtoxpub(xprv_string):
            returns xpub_string

        BIP32.crack(xpub_master_string, xprv_child_string, str_path_from_master_to_child):
            returns xprv_master_string
            # You must manually verify returned output against master pub string.
            # It outputs the resulting key without checking it against the master pubkey input.
            # So if the privkey entered doesn't belong to the master pubkey, the result will
            #   be bad.
            # This was left this way intentionally. If you want it to output False on a
            #   non-match, feel free to go change the code.


BIP 0039 mnemonics:

    class BIP39(wordlist_str_or_hexstr_or_entroy_int_for_new_random=128, bip32_pbkdf2_password=''):
        Holds info on a BIP39 mnemonic.  Currently only English, but other languages coming soon.
            self.hex            (hexstr)
            self.en             (string_english_wordlist_lowercase_with_single_space_inbetween)
            self.password       (string_bip32_pbkdf_password)
            self.enbip32seed    (hexstr_bip32_seed_for_english_words_and_self.password)

            self.setpassword(new_password_str):
                updates self.password and self.enbip32seed to reflect new input password

            self.__str__() and self.__repr__():
                returns english_wordlist_str

        @staticmethods:

        BIP39.hextowords(hexstr, lang='en'): # Do not change lang yet
            returns str_wordlist_from_hex_in_lang

        BIP39.wordstohex(wordlist_str):
            returns hex_string
            # Don't input anything besides English word list yet

        BIP39.Bip32Seed(wordlist_str, password=''):
            returns hexstr_bip32_seed


Electrum keys:

    class Electrum1(seed_hexstr_or_wordlist_str_or_omit_for_new_random):
        self.words        (wordlist_str)
        self.seed         (seed_hexstr)
        self.mpub         (hexstr)
        self.mpriv        (hexstr)

        self.child(index_int,change=False):
            returns tuple of (priv_wif_str, pubkey_hexstr, addr_str)

        self.priv(index_int,ischange=False):
            returns priv_wif_str

        self.pub(index_int,ischange=False):
            returns pubkey_hexstr

        self.address(index_int,ischange=False):
            returns address_str

        self.__str__() and self.__repr__():
            returns wordlist_str

        self[index]  aka  self.__getitem__(index):
            returns same tuple as self.child()
            # HOWEVER, it does not take more than one arg
            # If input arg is int/long, it returns main address index
            # If input arg is float, it returns change address of index int(input)

        @staticmethods

        Electrum1.hextowords():
            returns wordlist_str

        Electrum1.wordstohex():
            returns hexstr_seed

        Electrum1.crack(mpub_hexstr, privkey_any_format, index_of_privkey=None, indicies_to_try=100):
            returns hexstr_master_privkey if cracked otherwise False
            # If index_of_privkey (actual kwarg is just 'index') is None, it will iterate through
            # the first indicies_to_try (kwarg 'privtests') main and change keys to see if it's a
            # match for any of them and can crack the master private key.
            # If index is set to an int, it tries that index (main and change), and ONLY that index
            # before giving up.


    class Electrum2(seed_hexstr_or_wordlist_str_or_entropy_bits_or_omit_for_new_random_128bit):
        self.words        (wordlist_str)
        self.seed         (seed_hexstr)
        self.bip32xpub    (xpub_str of master public key)
        self.bip32xprv    (xprv_str of master private key)

        self.__str__() and self.__repr__():
            returns wordlist_str

        self[index]  aka  self.__getitem__(index):
            returns same tuple as Electrum1.child()
            # Does not take more than one arg.
            # If input arg is int/long, it returns main address index.
            # If input arg is float, it returns change address of index int(input).
            # If input arg is a str, it must be a BIP32 path (e.g. "m/1/2/3") and
            #   it will return info of the address that corresponds to that BIP32
            #   path using the master xprv key.

        @staticmethods

        Electrum2.hextowords():
            returns wordlist_str

        Electrum2.wordstohex():
            returns hexstr_seed

        Electrum2.crack(master_xpub_str, privkey_any_bitcoin_format_NOT_xprv, index_of_privkey=None, indicies_to_try=100):
            returns xprv_master_privkey_str if cracked otherwise False
            # If index_of_privkey (actual kwarg is just 'index') is None, it will iterate through
            # the first indicies_to_try (kwarg 'privtests') main and change keys to see if it's a
            # match for any of them and can crack the master private key.
            # If index is set to an int, it tries that index (main and change), and ONLY that index
            # before giving up.


Simple Bitcoin Transaction Scripting:

    Coming soon. The code is written, but it's not cleaned up enough for me to feel comfortable sticking it online for people to actually be using as a library for their projects.



###Requirements

The standard library, and pbkdf2 if that's not already in the standard library.


###Installation


#####For Ubuntu and other Debian Linux:

First make sure you have the requirements:

    sudo pip install pbkdf2

Then either do:

    sudo pip install simplebitcoinfuncs

or download/clone this repository and run:

    sudo python setup.py install


#####For non-Debian Linux:

You don't need any instructions.


#####For Windows

Recent versions of Python come with pip installed, so you should be able to run from cmd.exe:

    pip install pbkdf2

and then

    pip install simplebitcoinfuncs

or possibly

    python pip install pbkdf2

and

    python pip install simplebitcoinfuncs    

But if that doesn't work, download [this](https://bootstrap.pypa.io/get-pip.py) script and run it with python. That will install pip. Then follow the instructions above.

Alternatively, consider ditching Windows.


#####For Macs

I have no idea how Homebrew or anything else related to Macs works. If you're programming Python on OSX, the Linux instructions should be good enough. But for your own benefit, a non-Mac version of Linux. GNU/Linux. Free software for freedom and all that.



###After Installation

In your script, stick at the top:

    from simplebitcoinfuncs import *


You're done.

