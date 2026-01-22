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

    filename = './4.txt'
    best_lineno=0
    best_return = ""
    best_score = 1
    with open(filename, 'r') as file:
        for ln, line in enumerate(file):
            hexcode = line.strip()
            lineBytes = hex_to_bytearray(hexcode)
            #This is decoding invalid bytes 0x89
            best_return= crack_single_byte_xor(lineBytes)
            if best_return[2] < best_score:
                best_lineno = ln
                best_score = best_return[2]


        # best_return should be a tuple returned from crack_single_byte_xor()
        print(f'Found text on line {best_lineno}: "{best_return}"')
