#!/usr/bin/env python3

"""
Random access CTR mode.

COMP 383
Assignment 8

Chris Cianci
"""


from typing import Callable, Tuple

from aes_ctr import aes_128_ctr

from aes_ecb import random_key

from util import base64_to_bytearray, bytearray_to_str

from xor import xor


def build_edit_ctr() -> \
        Tuple[Callable[[bytearray], bytearray],
              Callable[[bytearray, int, bytearray | bytes], bytearray]]:
    """Generate a function with 'static' variables."""
    unknown_key = random_key()
    unknown_nonce = 0

    def encrypt(clear: bytearray) -> bytearray:
        encrypted = aes_128_ctr(clear, unknown_key, unknown_nonce)
        return encrypted

    def edit_ctr(ciphertext: bytearray,
                 offset: int,
                 newtext: bytearray | bytes) -> bytearray:
        """Seek into CTR encrypted data and make a change."""
        clear = aes_128_ctr(ciphertext, unknown_key, unknown_nonce)
        clear[offset:] = newtext
        encrypted = aes_128_ctr(clear, unknown_key, unknown_nonce)
        return encrypted
    return encrypt, edit_ctr



def break_random_access_ctr(
        fn: Callable[[bytearray, int, bytearray | bytes], bytearray],
        ciphertext: bytearray) -> bytearray:
    """(Ab)Use edit function to decipher CTR."""
    #encrypt zeros using the same keystream and xor them to get the original plaintext
    cleartext = bytearray(len(ciphertext))
    edit_text = fn(ciphertext, 0, cleartext)

    return xor(ciphertext, edit_text)


if __name__ == '__main__':

    # construct target functions
    encrypt_ctr, edit_ctr = build_edit_ctr()
    ct = encrypt_ctr(bytearray('smthsmthsmth', 'utf-8'))
    ct = edit_ctr(ct, 1, bytearray('pluh', 'utf-8'))
    pt = encrypt_ctr(ct)
    print(pt)

    # prepare (and provide) the original ciphertext
    filename = 'RM_A08/25.txt'
    encrypted = bytearray()
    with open(filename, 'r') as file:
        base64 = ''.join(file.readlines())
        clear = base64_to_bytearray(base64)
        encrypted = encrypt_ctr(clear)

    # attack the edit function to recover the plaintext
    plaintext = break_random_access_ctr(edit_ctr, encrypted)
    print(bytearray_to_str(plaintext))
