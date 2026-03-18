#!/usr/bin/env python3

"""
CBC bitflipping attack.

COMP 383
Assignment 4

Chris Cianci
"""


from typing import Callable

from aes_ecb import random_key

from random import randint

from aes_ctr import aes_128_ctr

from pkcs7 import pkcs7_pad

from util import \
        base64_to_bytearray, \
        bytearray_to_base64, \
        str_to_bytearray

from xor import xor


_KEY = random_key()
_NONCE = randint(0,100)


def encrypt_userdata(s: str) -> str:
    """Embed a userdata tuple into a query string, and encrypt it."""
    if s.find('=') >= 0 or s.find(';') >= 0:
        raise Exception('Illegal characters in user string.')
    output = aes_128_ctr(
            str_to_bytearray(
                'comment1=lorem%20ipsum%20dolor;userdata=' + s +
                ';comment2=%20sit%20amet'), _KEY, _NONCE)
    return bytearray_to_base64(output)


def check_admin(crypttext: str) -> bool:
    """Decrypt a query string, and look for 'admin=true'."""
    b = base64_to_bytearray(crypttext)
    clear = aes_128_ctr(b, _KEY, _NONCE)
    print(f'clear = {clear}')
    if clear.find(b'admin=true') >= 0:
        return True
    else:
        return False


def ctr_bitflip(fn: Callable[[str], str]) -> str:

    #create ct with empty an spot
    chosen_text = bytearray(len(';admin=true')).decode('utf-8')
    ct = base64_to_bytearray(fn(chosen_text))

    #create identical text with our payload at the empty spot
    payload = bytearray(len('comment1=lorem%20ipsum%20dolor;userdata='))
    payload.extend(bytearray(';admin=true', 'utf-8'))

    #pad to correct length and xor
    payload.extend(bytearray(len(ct)- len(payload)))
    altered = xor(ct, payload)

    return bytearray_to_base64(altered)






if __name__ == '__main__':

    admin_profile = ctr_bitflip(encrypt_userdata)
    admin = check_admin(admin_profile)
    print(f'check_admin(): {admin}')
