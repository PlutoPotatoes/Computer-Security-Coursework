#!/usr/bin/env python3

"""
Conversion utilities to simplify data storage vs representation.

COMP383
Assignment 1 (Challenge 1)

Ryan Morrell
"""


import base64


def bytearray_to_hex(b: bytearray) -> str:
    """Render bytearray as hex string for printing."""
    return b.hex()


def hex_to_bytearray(hex_str: str) -> bytearray:
    """Parse hex string to bytearray for manipulation."""
    return bytearray.fromhex(hex_str)

def bytearray_to_base64(b: bytearray) -> str:
    """Render bytearray as base64 string for printing."""
    return base64.b64encode(b).decode('utf-8')



def base64_to_bytearray(b64: str) -> bytearray:
    """Parse base64 string to bytearray for manipulation."""
    return bytearray(base64.b64decode(b64))


def bytearray_to_str(b: bytearray) -> str:
    """Render bytearray as text string for printing."""
    return b.decode('utf-8', errors='ignore')


def str_to_bytearray(txt: str) -> bytearray:
    """Parse plain text string to bytearray for manipulation."""
    return bytearray(txt, 'utf-8')


if __name__ == '__main__':


    testcase_str = 'Io Triumphe! Io Triumphe! ' + \
        'Haben, swaben, Rebecca le animor, ' + \
        'Whoop-te, whoop-te, sheller-de-vere-de, ' + \
        'Boom-de, ral-de, I-de, pa ' + \
        'Honeka, heneka, wack-a, wack-a ' + \
        'Hob, dob, bolde, bara, bolde, bara ' + \
        'Con, slomade, hob-dab-rahi. ' + \
        'O! C! RAH!'
    testcase_hex = '496f20547269756d7068652120496f20547269756d70686521' + \
        '20486162656e2c2073776162656e2c2052656265636361206c6520616e69' + \
        '6d6f722c2057686f6f702d74652c2077686f6f702d74652c207368656c6c' + \
        '65722d64652d766572652d64652c20426f6f6d2d64652c2072616c2d6465' + \
        '2c20492d64652c20706120486f6e656b612c2068656e656b612c20776163' + \
        '6b2d612c207761636b2d6120486f622c20646f622c20626f6c64652c2062' + \
        '6172612c20626f6c64652c206261726120436f6e2c20736c6f6d6164652c' + \
        '20686f622d6461622d726168692e204f212043212052414821'
    testcase_base64 = 'SW8gVHJpdW1waGUhIElvIFRyaXVtcGhlISBIYWJlbiwgc3dhYm' + \
        'VuLCBSZWJlY2NhIGxlIGFuaW1vciwgV2hvb3AtdGUsIHdob29wLXRlLCBzaG' + \
        'VsbGVyLWRlLXZlcmUtZGUsIEJvb20tZGUsIHJhbC1kZSwgSS1kZSwgcGEgSG' + \
        '9uZWthLCBoZW5la2EsIHdhY2stYSwgd2Fjay1hIEhvYiwgZG9iLCBib2xkZS' + \
        'wgYmFyYSwgYm9sZGUsIGJhcmEgQ29uLCBzbG9tYWRlLCBob2ItZGFiLXJhaG' + \
        'kuIE8hIEMhIFJBSCE='
    

    print('Test 1: Round trip from/to plain text')
    byte_array = str_to_bytearray(testcase_str)
    str_string = bytearray_to_str(byte_array)
    print(f'  original:  "{testcase_str}"')
    print(f'  converted: "{str_string}"')
    print('  SUCCESS' if (testcase_str == str_string) else '  FAILURE')

    print('Test 2: Round trip from/to hex')
    byte_array = hex_to_bytearray(testcase_hex)
    hex_string = bytearray_to_hex(byte_array)
    print(f'  original:  {testcase_hex}')
    print(f'  converted: {hex_string}')
    print('  SUCCESS' if (testcase_hex == hex_string) else '  FAILURE')

    print('Test 3: Round trip from/to base64')
    byte_array = base64_to_bytearray(testcase_base64)
    base64_string = bytearray_to_base64(byte_array)
    print(f'  original:  {testcase_base64}')
    print(f'  converted: {base64_string}')
    print('  SUCCESS' if (testcase_base64 == base64_string) else '  FAILURE')

    print('Test 4: From hex to base64')
    byte_array = hex_to_bytearray(testcase_hex)
    base64_string = bytearray_to_base64(byte_array)
    print(f'  given:     {testcase_base64}')
    print(f'  converted: {base64_string}')
    print('  SUCCESS' if (testcase_base64 == base64_string) else '  FAILURE')

    print('Test 5: From base64 to hex')
    byte_array = base64_to_bytearray(testcase_base64)
    hex_string = bytearray_to_hex(byte_array)
    print(f'  given:     {testcase_hex}')
    print(f'  converted: {hex_string}')
    print('  SUCCESS' if (testcase_hex == hex_string) else '  FAILURE')
