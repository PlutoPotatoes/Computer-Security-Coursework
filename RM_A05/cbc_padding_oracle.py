#!/usr/bin/python3

"""
CBC padding oracle.

COMP 383
Assignment 5

Chris Cianci
"""


import secrets
from typing import Callable

from aes_cbc import decrypt_aes_128_cbc, encrypt_aes_128_cbc

from aes_ecb import random_key

from pkcs7 import pkcs7_pad, pkcs7_unpad

from util import base64_to_bytearray, bytearray_to_str

from xor import xor


_KEY = random_key()
_IV = random_key()
_STRINGS = [
    'TXkgbmFtZSBpcyBJbmlnbyBNb250b3lhLiBZb3Uga2lsbGVkIG15IGZhdGhl' +
    'ci4gUHJlcGFyZSB0byBkaWUuICA=',
    'WW91IGtlZXAgdXNpbmcgdGhhdCB3b3JkLiBJIGRvIG5vdCB0aGluayBpdCBt' +
    'ZWFucyB3aGF0IHlvdSB0aGluayBpdCBtZWFucy4=',
    'RGVhdGggY2Fubm90IHN0b3AgdHJ1ZSBsb3ZlLiBBbGwgaXQgY2FuIGRvIGlz' +
    'IGRlbGF5IGl0IGZvciBhIHdoaWxlLg==',
    'TGlmZSBpc24ndCBmYWlyLCBIaWdobmVzcy4gQW55b25lIHdobyBzYXlzIG90' +
    'aGVyd2lzZSBpcyBzZWxsaW5nIHNvbWV0aGluZy4=',
    'SW5jb25jZWl2YWJsZSE=',
    'QXMgeW91IHdpc2gu',
    'Tm8gbW9yZSByaHltZXMgbm93LCBJIG1lYW4gaXQuIEFueWJvZHkgd2FudCBhIHBlYW51dD8=',
    'Um9kZW50cyBPZiBVbnVzdWFsIFNpemU/IEkgZG9uJ3QgdGhpbmsgdGhleSBleGlzdC4=',
    'UGxlYXNlIHVuZGVyc3RhbmQgSSBob2xkIHlvdSBpbiB0aGUgaGlnaGVzdCByZXNwZWN0Lg==',
    'VGhlcmUncyBhIGJpZyBkaWZmZXJlbmNlIGJldHdlZW4gbW9zdGx5IGRlYWQg' +
    'YW5kIGFsbCBkZWFkLiBNb3N0bHkgZGVhZCBpcyBzbGlnaHRseSBhbGl2ZS4=',
]
_STRING = _STRINGS[secrets.randbelow(len(_STRINGS))]


def encrypted_str() -> str:
    """Provide a (randomly selected) encrypted string."""
    s = base64_to_bytearray(_STRING)
    p = pkcs7_pad(s)
    output = encrypt_aes_128_cbc(p, _KEY, _IV)
    return _IV, output


def check_padding(iv: bytearray, crypttext: bytearray) -> bool:
    """Decrypt a ciphertext, and return whether or not it has valid padding."""
    clear = decrypt_aes_128_cbc(crypttext, _KEY, iv)
    try:
        pkcs7_unpad(clear)
    except Exception:
        return False
    return True


def attack_cbc_padding_oracle(
            fn: Callable[[bytearray, bytearray], bool],
            iv: bytearray,
            ciphertext: bytearray
        ) -> bytearray:
    """Given only a padding oracle, decrypt a ciphertext."""
    # allocate a string to collect the plaintext
    plaintext = bytearray()
    block_size = 16
    print(len(ciphertext)//block_size)


    for curr_block in range(len(ciphertext)//block_size, 1, -1):
        block_text = bytearray()
        for n in range(block_size):
            print(f'n = {n}')
            empty_bytes = bytearray(15-n)
            found = False
            for x in range(1, 256):
                xor_bytes = empty_bytes.copy()
                xor_bytes.append(x)
                [xor_bytes.append(b^n+1) for b in block_text]
                padding_test = xor(ciphertext[block_size*(curr_block-2): block_size*(curr_block-1)], xor_bytes)

                padding_test.extend(ciphertext[block_size*(curr_block-1): block_size*curr_block])
                if fn(bytearray(block_size), padding_test):
                    block_text.insert(0,(n+1)^x)
                    found = True
                    print('gotem')
                    break
            if not found:
                print('default')
                block_text.insert(0,n+1)

        block_text.extend(plaintext)
        plaintext = block_text
    
    print('iv time')
    
    #get the final block using IV
    block_text = bytearray()
    for n in range(block_size):
        empty_bytes = bytearray(15-n)
        found = False
        for x in range(1, 256):
            xor_bytes = empty_bytes.copy()
            xor_bytes.append(x)
            [xor_bytes.append(b^(n+1)) for b in block_text]
            test_iv = xor(iv, xor_bytes)
            if fn(test_iv, ciphertext[0:block_size]):
                block_text.insert(0,(n+1)^x)
                found = True
                print('gotem')
                break
        if not found:
            block_text.insert(0,n+1)
    
    block_text.extend(plaintext)
    plaintext = block_text
    
    plaintext = bytearray_to_str(plaintext)
    plaintext = base64_to_bytearray(plaintext)


    #TODO

    return plaintext


if __name__ == '__main__':

    iv, encrypted = encrypted_str()
    decrypted = attack_cbc_padding_oracle(check_padding, iv, encrypted)
    print(f'decrypted = {decrypted}')
