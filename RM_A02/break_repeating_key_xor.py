#!/usr/bin/env python3

"""
Break repeating-key XOR.

COMP383
Assignment 2 (Challenge 6)

[PUT YOUR NAME HERE]
"""


from single_byte_xor import crack_single_byte_xor

from util import base64_to_bytearray, bytearray_to_str, str_to_bytearray

from xor import extend_key, xor


def hamming_dist(a: bytearray | str, b: bytearray | str) -> int:
    """Compute the Hamming distance (number of diff bits) between strings."""
    assert (len(a) == len(b))
    if isinstance(a, str):
        a = str_to_bytearray(a)
    if isinstance(b, str):
        b = str_to_bytearray(b)
    #TODO
    return None


def discover_block_size(
            byte_array: bytearray,
            max_block_size: int = 100,
            blocks_to_compare: int = 20,
        ):
    """Guess the most likely length of the unknown key."""
    #TODO
    return block_size


def crack_repeating_key_xor(encrypted: bytearray) -> str:
    """Extract an unknown key from a given crypttext."""
    block_size = discover_block_size(encrypted, blocks_to_compare=15)
    #TODO
    return key


if __name__ == '__main__':

    print('Test 1: Hamming distance')
    test_a = 'this is a test'
    test_b = 'wokka wokka!!!'
    test_result = 37
    h = hamming_dist(test_a, test_b)
    print(f'  hamming_dist("{test_a}","{test_b}") = {h}')
    print('  SUCCESS' if (h == test_result) else '  FAILURE')

    print('Test 2: 6.txt')
    filename = './6.txt'
    with open(filename, 'r') as file:
        encrypted_base64 = ''.join(line.strip() for line in file)
        encrypted_bytearray = base64_to_bytearray(encrypted_base64)
        key = crack_repeating_key_xor(encrypted_bytearray)
        print(f'  detected key = "{key}"')

        cleartext = bytearray_to_str(
                xor(
                    encrypted_bytearray,
                    extend_key(key, len(encrypted_bytearray))
                )
            )
        print('  =====\n')
        print(cleartext)
