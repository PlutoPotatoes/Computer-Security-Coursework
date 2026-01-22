#!/usr/bin/env python3

"""
Implement repeating-key XOR.

COMP383
Assignment 1 (Challenge 5)

Ryan Morrell
"""


from util import bytearray_to_hex, str_to_bytearray

from xor import extend_key, xor


if __name__ == '__main__':

    cleartext = \
        'You fool! You fell victim to one of the classic blunders---\n' + \
        'the most famous of which is "Never get involved in a land war\n' + \
        ' in Asia"---but only slightly less well-known is this:\n' + \
        '"Never go in against a Sicilian when death is on the line!"'
    key = 'OXY'

    cryptext_target = \
        '16372c6f3e362034786f01363a783f2a34356f2e302c2c3022782d207836' + \
        '213d79203e793b303c6f3b352e2b2a263b792d342c213c3c3d2b74627553' + \
        '3b303c6f35363c2c79293934202d2a6f373f6f2f31263b316f312a6f7a17' + \
        '2a2e3c3d783e2a2c7926362f20342f2a3c792636792e78352e363d6f2f38' + \
        '3d52792636790e2b302e7a7462753b3a2c7920363536782a23313e272c35' + \
        '3678352a2b2a6f2f3c233474243636383679262b793b30303c62536d163c' + \
        '393d2b6f3f366f31376f393e2e31373c2c792e780a263b3023313821782e' + \
        '273d376f3c3c2e2c316f312a6f37376f2c312a783526363c6e7a'

    # Use the functions you've already written!
    # (Nudge: If your extend_key() function doesn't yet do what you want
    #         for multi-byte keys, go fix it now.)
    fullKey = extend_key(key, len(cleartext))
    bytetext = str_to_bytearray(cleartext)
    ciphertext = xor(bytetext, fullKey)
    output_hex = bytearray_to_hex(ciphertext)

    print('Test 1: Encrypt with key="OXY"')
    print(f'  encrypted: {output_hex}')
    print(f'  target:    {cryptext_target}')
    print('  SUCCESS' if (output_hex == cryptext_target) else '  FAILURE')
