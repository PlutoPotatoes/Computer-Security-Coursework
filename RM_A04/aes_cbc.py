#!/usr/bin/env python3

"""
AES in CBC mode.

COMP383
Assignment 3 (Challenge 10)

Chris Cianci
"""


from aes_ecb import decrypt_aes_128_ecb, encrypt_aes_128_ecb

from pkcs7 import pkcs7_pad, pkcs7_unpad

from util import \
        base64_to_bytearray, \
        bytearray_to_base64, \
        bytearray_to_str, \
        str_to_bytearray

from xor import xor


def encrypt_aes_128_cbc(
        clear: bytearray,
        key: bytearray,
        initvec: bytearray) -> bytearray:
    """Encrypt a (pre-padded) payload via AES-CBC."""
    #TODO
    block_size = len(key)
    clear = pkcs7_pad(clear, block_size)
    blocks = [clear[i:i+block_size] for i in range(0, len(clear), block_size)]
    ciphertext = bytearray()

    prev = xor(xor(blocks[0], initvec), key)
    ciphertext.extend(prev)
    for i in range(1, len(blocks)):
        next = xor(xor(blocks[i],prev), key)
        ciphertext.extend(next)
        prev = next
    return ciphertext


def decrypt_aes_128_cbc(
        ciphered: bytearray,
        key: bytearray,
        initvec: bytearray) -> bytearray:
    """Decrypt a (pre-padded) payload via AES-CBC."""
    block_size = len(key)
    blocks = [ciphered[i:i+block_size] for i in range(0, len(ciphered), block_size)]
    cleartext = bytearray()
    for i in range(len(blocks)-1, 0, -1):
        decrypt_block = xor(blocks[i], blocks[i-1])
        decrypt_block = xor(decrypt_block, key)
        decrypt_block.extend(cleartext)
        cleartext = decrypt_block
    initial_block = xor(xor(blocks[0], initvec), key)
    initial_block.extend(cleartext)
    initial_block = pkcs7_unpad(initial_block)
    return initial_block


if __name__ == '__main__':

    # You requested an opportunity to try writing your own tests;
    # here's a great place to give it a shot!
    # (Hint: Looking at the ones I gave you in the previous assignments
    #        should provide a decent place to start...)


    cleartext = "This is a super secret encoded message"
    bytetext = bytearray(cleartext, 'utf-8')
    key = bytearray('YELLOW SUBMARINE', 'utf-8')
    initvec = bytearray('sixteencharacter', 'utf-8')
    ciphertext = encrypt_aes_128_cbc(bytetext, key, initvec)
    print(ciphertext)
    decoded = decrypt_aes_128_cbc(ciphertext, key, initvec)
    print(decoded)
    pass
