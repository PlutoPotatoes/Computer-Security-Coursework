#!/usr/bin/env python3

"""
AES in CTR mode.

COMP 383
Assignment 6

Chris Cianci
"""


from aes_ecb import encrypt_aes_128_ecb, random_key

from util import base64_to_bytearray, str_to_bytearray

from xor import xor


def aes_128_ctr(data: bytearray,
                key: bytearray,
                nonce: int) -> bytearray:
    """Generate a CTR keystream and XOR against the input.

    Note that 'encryption' and 'decryption' are the *same* operation!
    """
    # initialize the counter and the keystream
    ctr = 0
    keystream = bytearray()
    num_blocks = len(data)//16+1
    first = int.to_bytes(nonce, length=8, byteorder='little')
    #TODO: Generate the keystream
    #       Hint--look at the python documentation for int.to_bytes()
    for i in range(num_blocks):
        block = bytearray()
        ctr +=1
        second = int.to_bytes(ctr, length=8, byteorder='little')
        block.extend(first)
        block.extend(second)
        block = encrypt_aes_128_ecb(block, key)
        keystream.extend(block)


    # XOR the data with the keystream

    return xor(data, keystream[:len(data)])


if __name__ == '__main__':

    crypttext = base64_to_bytearray(
            'ML2iO9/LMpvDyW8yHGOqBqvMCrDxHRiKp78//sCbAH0Nz+DrZR' +
            'NSa4610kTbifftsvTZXDnwOj20bBUTuwbVkPLjrVnLZzycJdn5' +
            'h8el+4CszPS9rFx33vv7M2XvekRe/QjhCK5jmdNHUwM3178+G/' +
            '7g4FZEviHoHZdwtz8='
        )
    key = str_to_bytearray('YELLOW SUBMARINE')
    nonce = 0
    print(aes_128_ctr(crypttext, key, nonce))

    rk = random_key()
    rn = 999
    print(aes_128_ctr(aes_128_ctr(bytearray(
            b'Possible, probable, my black hen\n' +
            b'She lays eggs in the relative when\n' +
            b'She doesn\'t lay eggs in the positive now\n' +
            b'Because she\'s unable to postulate how\n'
            ), rk, rn
        ), rk, rn))
