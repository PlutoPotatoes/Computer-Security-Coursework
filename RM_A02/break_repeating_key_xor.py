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
from numpy import mean


def hamming_dist(a: bytearray | str, b: bytearray | str) -> int:
    """Compute the Hamming distance (number of diff bits) between strings."""
    dist = 0
    assert (len(a) == len(b))
    if isinstance(a, str):
        a = str_to_bytearray(a)
    if isinstance(b, str):
        b = str_to_bytearray(b)
    x = xor(a, b)
    for bit in x:
        dist+=bit.bit_count()

    return dist


def discover_block_size(
            byte_array: bytearray,
            max_block_size: int = 100,
            blocks_to_compare: int = 20,
        ):
    """Guess the most likely length of the unknown key."""
    '''
        The smallest hamming distance between sections of the text with a specific length is likely the key
    '''
    best = []
    for KEY_LENGTH in range(1,max_block_size):
        scores = []
        for index in range(0,len(byte_array), KEY_LENGTH):
            if index + 2*KEY_LENGTH > byte_array.__len__():
                break
            A = byte_array[index:index + KEY_LENGTH]
            B = byte_array[index + KEY_LENGTH:index + (2*KEY_LENGTH)]
            scores.append(hamming_dist(A,B)/(KEY_LENGTH* 4))
        mean_score = mean(scores)
        if(len(best) ==0):
            best.append((KEY_LENGTH, mean_score))
        for i in range(0, len(best)):
            if(best[i][1] > mean_score):
                best.insert(i,(KEY_LENGTH, mean_score))
                if(len(best) > 3):
                    best.pop()
                break
    return best

def crack_repeating_key_xor(encrypted: bytearray) -> str:
    """Extract an unknown key from a given crypttext."""
    block_size = discover_block_size(encrypted, blocks_to_compare=15)[0][0]
    key = ''
    #TODO
    for start in range(block_size):
        chunk = encrypted[start:block_size]
        key += ascii(crack_single_byte_xor(chunk)[0])

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
        print(discover_block_size(encrypted_bytearray))

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
