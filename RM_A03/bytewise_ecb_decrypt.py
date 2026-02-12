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

from single_byte_xor import crack_single_byte_xor

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
    init = base64_to_bytearray(fn(''))
    start_len = len(init)  # type: ignore
    curr_block = base64_to_bytearray(fn('a'))
    payload_len = 1
    while len(curr_block) == start_len: #type:ignore
        payload_len +=1
        curr_block = base64_to_bytearray(fn('a'*payload_len))
    blk = len(curr_block) - start_len #type:ignore
    suf = start_len - (payload_len)

    return blk, suf


def bytewise_ecb_decrypt(fn: Callable[[str], str]) -> str:
    """With access to a function that encrypts, you can break it.

    Decrypt the secret suffix that is appended to your input by
    the encryption function.
    """
    #build dict
    blocksize, suffixLen = discover_block_size(fn)

    if not detect_ecb(base64_to_bytearray(fn("a"*blocksize*5)), blocksize):
        raise ValueError('oracle does not use ECB')
    cleartext = ''
    curr_block = 'a'*(blocksize-1)
    #i is where we are looking always
    i = suffixLen + (blocksize-(suffixLen%blocksize))
    for prefix_length in range(i-1, i-suffixLen-1, -1):
        #First we get out set of possible keys for the current window
        keys = dict()
        for c in range(256):
            block = curr_block + chr(c)
            keys[bytearray_to_hex(base64_to_bytearray(fn(block))[0:16])] = c
        #next we set up out window with the next secret character
        prefix = 'a'*prefix_length
        enc_block = bytearray_to_hex(base64_to_bytearray(fn(prefix))[i-16:i])
        #plug the encoded block into our set of keys
        next_char = keys[enc_block]

        #update our cleartext and curr block
        cleartext+=chr(next_char)
        curr_block = curr_block[1:] + chr(next_char)

    return cleartext


    


if __name__ == '__main__':

    encryptifier = build_encryptifier()
    print(discover_block_size(encryptifier))
    secret = bytewise_ecb_decrypt(encryptifier)

    print(f'decoded secret suffix = "{secret}"')
