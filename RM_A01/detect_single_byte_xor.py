#!/usr/bin/env python3

"""
Detect single-character XOR.

COMP383
Assignment 1 (Challenge 4)

Ryan Morrell
"""


from single_byte_xor import crack_single_byte_xor

from util import hex_to_bytearray


if __name__ == '__main__':

    filename = 'RM_A01/4.txt'
    best_lineno=0
    best_return = ""
    best_score = 1.0
    with open(filename, 'r') as file:
        for ln, line in enumerate(file):
            print(ln)
            #hexcode = line.removesuffix('\n')
            lineBytes = hex_to_bytearray(line)
            #This is decoding invalid bytes 0x89
            result = crack_single_byte_xor(lineBytes)
            score = result[2]
            if score < best_score:
                best_lineno = ln
                best_score = score
                best_return = result


        # best_return should be a tuple returned from crack_single_byte_xor()
        print(f'Found text on line {best_lineno}: "{best_return}"')
