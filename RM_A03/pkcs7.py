#!/usr/bin/env python3

"""
Implement PKCS#7 padding.

COMP383
Assignment 3 (Challenge 9,15)

Chris Cianci
"""
import util

def pkcs7_pad(payload: bytes, blocksize: int = 16) -> bytearray:
    """Add PKCS#7 padding to a string (up to blocksize)."""
    #TODO
    padded = bytearray(payload)
    padding = blocksize - len(padded)%blocksize
    padded.extend([padding]*padding)
    return padded
    


def pkcs7_unpad(byte_array: bytes) -> bytearray:
    """Strip off valid PKCS#7 padding, if present.

    Raise an Exception() if no valid padding found.
    """
    #TODO
    last = byte_array[len(byte_array)-1]
    for i in range(int(last)):
        if byte_array[-(i+1)] != last:
            return bytearray(byte_array)

    return bytearray(byte_array[:-int(last)])


if __name__ == '__main__':

    # You requested an opportunity to try writing your own tests;
    # here's a great place to give it a shot!
    # (Hint: Looking at the ones I gave you in the previous assignments
    #        should provide a decent place to start...)

    ba = pkcs7_pad(bytes([1,1,1,1,1,1,1,1,7, 6, 8]))
    print(len(ba))
    print(pkcs7_unpad(ba))

    pass
