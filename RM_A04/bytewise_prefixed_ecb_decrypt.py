#!/usr/bin/env python3

"""
Byte-at-a-time ECB decryption (Simple).

COMP383
Assignment 4 (Challenge 14)

Chris Cianci
"""


import math
from typing import Callable

from aes_ecb import encrypt_aes_128_ecb, random_key, random_pad

from detect_ecb import detect_ecb

from pkcs7 import pkcs7_pad

from util import \
        base64_to_bytearray, \
        bytearray_to_base64, \
        bytearray_to_hex, \
        str_to_bytearray


def build_prefixed_encryptifier() -> Callable[[str], str]:
    """Generate a function with 'static' variables."""
    unknown_prefix = random_pad(1, 16)  # THOUGHT EXPERIMENT: try > blocksize
    print(f"unknown_prefix = {len(unknown_prefix)}")
    unknown_key = random_key()
    secret_suffix = base64_to_bytearray(
        'SXQncyBiZWVuIGEgaGFyZCBkYXkncyBuaWdodCBBbmQgSSd2ZSBiZWVuIHdv' +
        'cmtpbmcgbGlrZSBhIGRvZy4gSXQncyBiZWVuIGEgaGFyZCBkYXkncyBuaWdo' +
        'dCwgSSBzaG91bGQgYmUgc2xlZXBpbmcgbGlrZSBhIGxvZy4gQnV0IHdoZW4g' +
        'SSBnZXQgaG9tZSB0byB5b3UsIEkgZmluZCB0aGUgdGhpbmdzIHRoYXQgeW91' +
        'IGRvIFdpbGwgbWFrZSBtZSBmZWVsIGFscmlnaHQu'
            )

    def encryptifier(cleartext: str) -> str:
        """Encrypt provided data plus (secret) static data."""
        nonlocal unknown_prefix
        nonlocal unknown_key
        nonlocal secret_suffix
        padtext = pkcs7_pad(
                unknown_prefix +
                str_to_bytearray(cleartext) +
                secret_suffix
            )
        return bytearray_to_base64(encrypt_aes_128_ecb(padtext, unknown_key))
    return encryptifier


def bytewise_prefixed_ecb_decrypt(fn: Callable[[str], str]) -> str:
    """With access to a function that encrypts, you can break it.

    Decrypt the secret suffix that is appended to your input by
    the encryption function, in the presence of an unknown prefix
    as well.
    """
    #TODO
    return decoded


if __name__ == '__main__':

    encryptifier = build_prefixed_encryptifier()

    secret = bytewise_prefixed_ecb_decrypt(encryptifier)

    print(f'decoded secret suffix = "{secret}"')
