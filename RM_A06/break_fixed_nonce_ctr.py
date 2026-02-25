#!/usr/bin/env python3

"""
Break fixed-nonce CTR mode.

COMP 383
Assignment 6

Chris Cianci
"""


from aes_ctr import aes_128_ctr

from aes_ecb import random_key

from util import base64_to_bytearray, bytearray_to_str

from xor import extend_key, xor



def analyze_chars(ba: bytearray) -> float:
    """Penalize non-printable characters."""
    printable = 0.0
    for c in bytearray_to_str(ba):
        if (' ' <= c <= '~'):
            printable += 0.1    # punctuation is okay
        if ('A' <= c <= 'Z') or ('a' <= c <= 'z') or (c == ' '):
            printable += 0.9    # but actual letters are better
    printable /= len(ba)
    print_error = (1-printable)
    return print_error


def crack_single_byte_xor(array: bytearray) -> \
        tuple[int, bytearray, float]:
    """Find the single-byte key most likely to yield English text."""
    error_dict: dict[int, float] = {}
    for i in range(256):  # Update for CTR, check all the possibilities
        candidate = xor(array, extend_key(i, len(array)))
        error_dict[i] = analyze_chars(candidate)
    best_key = min(error_dict, key=error_dict.__getitem__)
    best_str = xor(array, extend_key(best_key, len(array)))
    best_err = error_dict[best_key]
    return best_key, best_str, best_err


def recover_fixed_nonce_ctr_keystream(data: list[bytearray]) -> bytearray:
    """Crack fixed nonce CTR mode.

    Given a list of strings encrypted with the same CTR keystream,
    recover them using the same method as for repeating key XOR.
    """
    # TODO
    index_letters = []
    key = bytearray()

    for line in data:
        index=0
        for c in line:
            if len(index_letters)<=index:
                index_letters.append(bytearray())
            index_letters[index].append(c)
            index+=1
    for letters in index_letters:
        char_key, str, err = crack_single_byte_xor(letters)
        key.append(char_key)

    return key


if __name__ == '__main__':

    key = random_key()
    nonce = 0
    filename = './20.txt'
    encrypted = []
    solved = []
    with open(filename, 'r') as file:
        for ln, line in enumerate(file):
            clear = base64_to_bytearray(line)
            encrypted.append(aes_128_ctr(clear, key, nonce))

    ctr_key = recover_fixed_nonce_ctr_keystream(encrypted)
    for ct in encrypted:
        print(xor(ct, ctr_key[:len(ct)]))

