#!/usr/bin/env python3

"""
Decrypt a string XORed against an unknown single byte.

COMP383
Assignment 1 (Challenge 3)

Ryan Morrell
"""

from typing import Final, Mapping

from util import bytearray_to_str, hex_to_bytearray

from xor import extend_key, xor

from collections import defaultdict

from scipy.spatial.distance import cosine
#from sklearn.metrics import mean_squared_error


_ENGLISH_FREQ: Final[Mapping[str, float]] = {
    # Frequency table copied from:
    #    http://www.data-compression.com/english.html
    'a': 0.0651738,
    'b': 0.0124248,
    'c': 0.0217339,
    'd': 0.0349835,
    'e': 0.1041442,
    'f': 0.0197881,
    'g': 0.0158610,
    'h': 0.0492888,
    'i': 0.0558094,
    'j': 0.0009033,
    'k': 0.0050529,
    'l': 0.0331490,
    'm': 0.0202124,
    'n': 0.0564513,
    'o': 0.0596302,
    'p': 0.0137645,
    'q': 0.0008606,
    'r': 0.0497563,
    's': 0.0515760,
    't': 0.0729357,
    'u': 0.0225134,
    'v': 0.0082903,
    'w': 0.0171272,
    'x': 0.0013692,
    'y': 0.0145984,
    'z': 0.0007836,
    ' ': 0.1918182
}

_ENGLISH_VECTOR = [0.1918182, 0.0651738, 0.0124248, 0.0217339, 
                   0.0349835, 0.1041442, 0.0197881, 0.0158610, 
                   0.0492888, 0.0558094, 0.0009033, 0.0050529, 
                   0.0331490, 0.0202124, 0.0564513, 0.0596302, 
                   0.0137645, 0.0008606, 0.0497563, 0.0515760,
                   0.0729357, 0.0225134, 0.0082903, 0.0171272,
                   0.0013692,0.0145984,0.0007836]

_ENGLISH_CHAR_MAPPING = {
    ' ': 0,
    'a': 1,
    'b': 2,
    'c': 3,
    'd': 4,
    'e': 5,
    'f': 6,
    'g': 7,
    'h': 8,
    'i': 9,
    'j': 10,
    'k': 11,
    'l': 12,
    'm': 13,
    'n': 14,
    'o': 15,
    'p': 16,
    'q': 17,
    'r': 18,
    's': 19,
    't': 20,
    'u': 21,
    'v': 22,
    'w': 23,
    'x': 24,
    'y': 25,
    'z': 26,
}


def char_freq(string: str, character: str) -> float:
    """Compute the (normalized) frequency of a character in a string."""
    # simply count the number of occurrences of a given char
    # and normalize
    count = 0
    for c in string:
        if c == character:
            count+=1
    return count/len(string)


def analyze_char_freq(string: str) -> float:
    """Check the frequency of English characters in a given string."""
    # forms a vector representing character frequencies and 
    # then calculates the cosine similarity between them
    counts = [0.0]*27
    for c in string:
        if c in _ENGLISH_FREQ.keys():
            counts[_ENGLISH_CHAR_MAPPING[c]]+=(1/len(string))
    return cosine(_ENGLISH_VECTOR, counts)


def crack_single_byte_xor(array: bytearray) -> \
        tuple[int, str, float]:
    """Find the single-byte key most likely to yield English text."""
    best = (0, "", 1.0)
    for key in range(256):
        cipher = extend_key(key, len(array))
        shiftedCiphertext = xor(array, cipher)
        text = bytearray_to_str(shiftedCiphertext)
        print(text)
        if text.isprintable() and text != '':
            print(key)
            score = analyze_char_freq(text)
            if text.isprintable() and score < best[2]:
                best = (key, text, score)
        

    return best


if __name__ == '__main__':

    crypttext = '3d1b1c0b02174e17011b4e0d0f00491a4e0c0b4e1d0b1c0701' + \
        '1b1d514e274e0f034e1d0b1c07011b1d404e2f000a4e0a0100491a4e0d0f' + \
        '02024e030b4e3d06071c020b17'
    crypttext_array = hex_to_bytearray(crypttext)

    k, s, e = crack_single_byte_xor(crypttext_array)
    print(f"best key:       '{ascii(k)}' ({k})  error = {e}")
    print(f"decoded string: '{s}'")
