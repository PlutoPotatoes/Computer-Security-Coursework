#!/usr/bin/env python3

"""
Detect AES in ECB mode.

COMP383
Assignment 3 (Challenge 8)

Chris Cianci
"""


import secrets

from aes_cbc import encrypt_aes_128_cbc

from aes_ecb import encrypt_aes_128_ecb, random_key, random_pad

from pkcs7 import pkcs7_pad  # , pkcs7_unpad

from util import str_to_bytearray


def detect_ecb(ciphertext: bytearray, blocksize: int = 16) -> bool:
    """Detect the use of ECB mode in a ciphertext."""
    #TODO
    return False


def encryption_oracle(cleartext: bytearray):
    """A function provided by the target. Encrypts either ECB or CBC."""
    pre = random_pad()
    post = random_pad()
    padtext = pkcs7_pad(pre + cleartext + post)
    k = random_key()
    ecb = (secrets.randbits(1) == 1)
    if ecb:
        # do ecb
        x = encrypt_aes_128_ecb(padtext, k)
    else:
        # do cbc
        iv = random_key()
        x = encrypt_aes_128_cbc(padtext, k, iv)
    return ecb, x


if __name__ == '__main__':

    # You requested an opportunity to try writing your own tests;
    # here's a great place to give it a shot!
    # (Hint: Looking at the ones I gave you in the previous assignments
    #        should provide a decent place to start...)

    pass
