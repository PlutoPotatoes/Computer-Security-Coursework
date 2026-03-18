#!/usr/bin/env python3

"""
AES in CBC mode.

COMP383
Assignment 3 (Challenge 10)

Chris Cianci
"""

from typing import Callable

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
        key: bytearray) -> bytearray:
    """Encrypt a (pre-padded) payload via AES-CBC."""
    #TODO
    block_size = len(key)
    clear = pkcs7_pad(clear, block_size)
    blocks = [clear[i:i+block_size] for i in range(0, len(clear), block_size)]
    ciphertext = bytearray()

    prev = xor(xor(blocks[0], key), key)
    ciphertext.extend(prev)
    for i in range(1, len(blocks)):
        next = xor(xor(blocks[i],prev), key)
        ciphertext.extend(next)
        prev = next
    return ciphertext


def decrypt_aes_128_cbc(
        ciphered: bytearray,
        key: bytearray) -> bytearray:
    """Decrypt a (pre-padded) payload via AES-CBC."""
    block_size = len(key)
    blocks = [ciphered[i:i+block_size] for i in range(0, len(ciphered), block_size)]
    cleartext = bytearray()
    for i in range(len(blocks)-1, 0, -1):
        decrypt_block = xor(blocks[i], blocks[i-1])
        decrypt_block = xor(decrypt_block, key)
        decrypt_block.extend(cleartext)
        cleartext = decrypt_block
    initial_block = xor(xor(blocks[0], key), key)
    initial_block.extend(cleartext)
    initial_block = pkcs7_unpad(initial_block)
    return initial_block

def crack_shared_iv_key_cbc(fn: Callable[[bytearray, bytearray], bytearray]) -> str:
    block_size = 16
    secret_key = bytearray('YELLOW SUBMARINE', 'utf-8')
    init_encrypt = fn(bytearray("this is a secrete message with many things to hide, i sure hope no one has my key", 'utf-8'), secret_key)
    '''
    first block of init encrypt should be completely unencrypted since the IV and key cancel eachother out
    meaning, we will know the first block. 

    using this we can create empty block, put that second, and put the first block after to create an xor chain that reveals the key.

    After this however we need to pass the padding check so we can tack the original 2nd and 3rd blocks back on to insure smooth decoding.
    '''
    #grab the unencrypted block so we can use it all over the place
    first_block = init_encrypt[0:block_size]

    #create initial payload
    sneaky = first_block
    sneaky.extend(b'\x00'*block_size)
    sneaky.extend(first_block)    

    #append the end of the functional text to the end to avoid padding errors and decrypt
    sneaky.extend(init_encrypt[block_size:])
    decrypt = decrypt_aes_128_cbc(sneaky, secret_key)
    
    #grab the key building blocks and xor for the key
    p1 = decrypt[0:block_size]
    p3 = decrypt[block_size*2:block_size*3]
    found_key = xor(p1, p3)

    return f'Found key {found_key} from text encoded with key {secret_key}'


if __name__ == '__main__':


    cleartext = "This is a super secret encoded message"
    bytetext = bytearray(cleartext, 'utf-8')
    key = bytearray('YELLOW SUBMARINE', 'utf-8')
    ciphertext = encrypt_aes_128_cbc(bytetext, key)
    decoded = decrypt_aes_128_cbc(ciphertext, key)

    print(crack_shared_iv_key_cbc(encrypt_aes_128_cbc))
    pass
