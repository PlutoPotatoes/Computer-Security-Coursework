#!/usr/bin/env python3

"""
Fixed XOR.

COMP383
Assignment 1 (Challenge 2)

Ryan Morrell
"""


from util import bytearray_to_hex, hex_to_bytearray, str_to_bytearray, bytearray_to_base64


def extend_key(key: bytearray | int | str, length: int) -> bytearray:
    """Coerce key to be a bytearray of appropriate size for the data."""
    if isinstance(key, int):
        extended_key = bytearray([key for i in range(length)])
    elif isinstance(key, str):
        key = str_to_bytearray(key)
        repetitions = (length//len(key))
        extended_key = key.__imul__(repetitions)
        extended_key.extend(key[:length-len(extended_key)])
    else:
        repetitions = (length//len(key))
        extended_key = key.__imul__(repetitions)
        extended_key.extend(key[:length-len(extended_key)])

    
    return extended_key


def xor(data: bytearray, key: bytearray) -> bytearray:
    """Compute bitwise XOR of two bytearrays."""
    assert len(data) == len(key)  # Don't be afraid of asserts
    #zip the two together and xor one by one into a byte object
    encoded = bytes(databyte^keybyte for (databyte, keybyte) in zip(data, key))
    return bytearray(encoded)


if __name__ == '__main__':

    testcase_a = '1c0111001f010100061a024b53535009181c'
    testcase_b = '686974207468652062756c6c277320657965'
    testcase_c = '746865206b696420646f6e277420706c6179'

    testcase_11 = '170a1a0b140a0a0b0d11094058585b021317'
    testcase_q = '6d7060716e707071776b733a22222178696d'

    byte_array_a = hex_to_bytearray(testcase_a)
    byte_array_b = hex_to_bytearray(testcase_b)

    print('Test 1: XOR(array,array)')
    a_xor_b = xor(byte_array_a, byte_array_b)
    a_xor_b_hex = bytearray_to_hex(a_xor_b)
    print(f'result: {a_xor_b_hex}')
    print(f'target: {testcase_c}')
    print('  SUCCESS' if (a_xor_b_hex == testcase_c) else '  FAILURE')

    print('Test 2: XOR(array,int)')
    a_xor_int = xor(byte_array_a, extend_key(11, len(byte_array_a)))
    a_xor_int_hex = bytearray_to_hex(a_xor_int)
    print(f'result: {a_xor_int_hex}')
    print(f'target: {testcase_11}')
    print('  SUCCESS' if (a_xor_int_hex == testcase_11) else '  FAILURE')

    print('Test 3: XOR(array,char)')
    a_xor_char = xor(byte_array_a, extend_key('q', len(byte_array_a)))
    a_xor_char_hex = bytearray_to_hex(a_xor_char)
    print(f'result: {a_xor_char_hex}')
    print(f'target: {testcase_q}')
    print('  SUCCESS' if (a_xor_char_hex == testcase_q) else '  FAILURE')
