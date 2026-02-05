#!/usr/bin/env python3

"""
Byte-at-a-time ECB decryption (Simple).

COMP383
Assignment 4 (Challenge 12)

Chris Cianci
"""


import math
from typing import Callable

from aes_ecb import encrypt_aes_128_ecb

from detect_ecb import detect_ecb

from pkcs7 import pkcs7_pad

from detect_ecb import random_key

from util import \
        base64_to_bytearray, \
        bytearray_to_base64, \
        bytearray_to_hex, \
        str_to_bytearray


def build_encryptifier() -> Callable[[str], str]:
    """Generate a function with 'static' variables."""
    unknown_key = random_key()
    secret_suffix = base64_to_bytearray(
        'WWVzdGVyZGF5LCBhbGwgbXkgdHJvdWJsZXMgc2VlbWVkIHNvIGZhciBhd2F5' +
        'LApOb3cgaXQgbG9va3MgYXMgdGhvdWdoIHRoZXkncmUgaGVyZSB0byBzdGF5' +
        'LApPaCwgSSBiZWxpZXZlIGluIHllc3RlcmRheQ=='
            )

    def encryptifier(cleartext: str) -> str:
        """Encrypt provided data plus (secret) static data."""
        nonlocal unknown_key
        nonlocal secret_suffix
        padtext = pkcs7_pad(str_to_bytearray(cleartext)+secret_suffix)
        return bytearray_to_base64(encrypt_aes_128_ecb(padtext, unknown_key))
    return encryptifier


def discover_block_size(fn: Callable[[str], str], limit: int = 40) \
        -> tuple[int, int]:
    """Find blocksize of accesible mystery function.

    Given a function that encrypts your input (plus its own),
    find its blocksize, and the length of the suffix it adds.
    """
    #TODO
    return blk, suf


def bytewise_ecb_decrypt(fn: Callable[[str], str]) -> str:
    """With access to a function that encrypts, you can break it.

    Decrypt the secret suffix that is appended to your input by
    the encryption function.
    """
    #TODO
    return decoded


if __name__ == '__main__':

    encryptifier = build_encryptifier()

    secret = bytewise_ecb_decrypt(encryptifier)

    print(f'decoded secret suffix = "{secret}"')
