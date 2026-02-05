#!/usr/bin/env python3

"""
AES in ECB mode.

COMP383
Assignment 3 (Challenge 7)

Chris Cianci
"""


from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from pkcs7 import pkcs7_pad, pkcs7_unpad

from util import \
        base64_to_bytearray, \
        bytearray_to_base64, \
        bytearray_to_str, \
        str_to_bytearray


def encrypt_aes_128_ecb(clear: bytearray, key: bytearray) -> bytearray:
    """Encrypt with AES in ECB mode."""
    c = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = c.encryptor()
    ct = encryptor.update(clear) + encryptor.finalize()
    return bytearray(ct)


def decrypt_aes_128_ecb(ciphered: bytearray, key: bytearray) -> bytearray:
    """Decrypt with AES in ECB mode."""
    c = Cipher(algorithms.AES(key), modes.ECB())
    decryptor = c.decryptor()
    ct = decryptor.update(ciphered) + decryptor.finalize()
    return bytearray(ct)


def random_bytes(n: int) -> bytearray:
    """Generate a bytearray of random values."""
    #TODO -- WHEN YOU GET TO C11
    return None


def random_key(keysize: int = 16) -> bytearray:
    """Generate a bytearray of keysize random values."""
    #TODO -- WHEN YOU GET TO C11
    return None


def random_pad(min_len: int = 5, max_len: int = 10) -> bytearray:
    """Uniform integer in [min_len, max_len], then that many random bytes."""
    #TODO -- WHEN YOU GET TO C11
    return None


if __name__ == '__main__':

    # You requested an opportunity to try writing your own tests;
    # here's a great place to give it a shot!
    # (Hint: Looking at the ones I gave you in the previous assignments
    #        should provide a decent place to start...)
    key = bytearray('YELLOW SUBMARINE', 'utf-8')
    cleartext = "Who knows what this could say, you should probably give up"
    cleartext = bytearray(cleartext, 'utf-8')
    cleartext = pkcs7_pad(cleartext, len(key))
    ciphertext = encrypt_aes_128_ecb(cleartext, key)
    decoded = pkcs7_unpad(decrypt_aes_128_ecb(ciphertext, key))
    print(ciphertext)
    print(decoded)


    pass
