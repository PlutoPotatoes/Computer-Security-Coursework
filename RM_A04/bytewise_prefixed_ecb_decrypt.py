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

def check_duplicate_blocks(ciphertext: bytearray, block_size):
    detect = set()
    repeats = 0
    blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]
    [detect.add(bytearray_to_hex(block)) for block in blocks]
    if len(detect) != len(blocks):
        repeats = len(blocks) - len(detect) 
    return repeats

def bytewise_prefixed_ecb_decrypt(fn: Callable[[str], str]) -> str:
    """With access to a function that encrypts, you can break it.

    Decrypt the secret suffix that is appended to your input by
    the encryption function, in the presence of an unknown prefix
    as well.
    """
    ''' 
        need to find block size, len of prefix, len of suffix. Then bytewise decrypt for the suffix 
        by using the prefix as an offset and filtering the suffix through byte by byte
    '''
    #find the block size
    payload = 'a'
    initial_length = len(base64_to_bytearray(fn('')))
    curr_length = len(base64_to_bytearray(fn(payload)))
    while(curr_length == initial_length):
        payload += 'a'
        curr_length = len(base64_to_bytearray(fn(payload)))
    block_size = curr_length - initial_length
    combined_size = initial_length - len(payload)

    #check for repeating blocks in existing input
    empty_cryptext = base64_to_bytearray(fn(''))
    initial_repeats = check_duplicate_blocks(empty_cryptext, block_size) 

    #add a's until we get a repeating block, subtract block size to get the prefix size
    repeats = 0
    payload_size = 0
    while repeats <= initial_repeats:
        payload_size+=1
        test_cryptext = base64_to_bytearray(fn('a'*payload_size))
        repeats = check_duplicate_blocks(test_cryptext, block_size)
    prefix_length = block_size - (payload_size - (block_size*2))
    suffix_len = initial_length-prefix_length

    #subtract that to get the suffix size
    #solve like before

    cleartext = ''
    curr_block = 'a'*(block_size-1)
    #i is where we are looking always
    i = suffix_len + (block_size-(suffix_len%block_size)) + (block_size)
    for payload_length in range(i-block_size-1, i-suffix_len-1, -1):
        #First we get out set of possible keys for the current window
        keys = dict()
        for c in range(256):
            block = 'p'*(block_size-prefix_length)+ curr_block + chr(c)
            keys[bytearray_to_hex(base64_to_bytearray(fn(block))[block_size:block_size*2])] = c
        #next we set up out window with the next secret character
        payload = 'p'*(block_size-prefix_length) + 'a'*payload_length
        enc_block = bytearray_to_hex(base64_to_bytearray(fn(payload))[i-16:i])
        #plug the encoded block into our set of keys
        next_char = keys[enc_block]

        #update our cleartext and curr block
        cleartext+=chr(next_char)
        curr_block = curr_block[1:] + chr(next_char)


    #TODO
    return cleartext


if __name__ == '__main__':

    encryptifier = build_prefixed_encryptifier()

    secret = bytewise_prefixed_ecb_decrypt(encryptifier)

    print(f'decoded secret suffix = "{secret}"')
