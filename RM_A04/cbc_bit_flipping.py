#!/usr/bin/env python3

"""
CBC bitflipping attack.

COMP 383
Assignment 4

Chris Cianci
"""


from typing import Callable

from aes_ecb import random_key

from aes_cbc import decrypt_aes_128_cbc, encrypt_aes_128_cbc

from bytewise_prefixed_ecb_decrypt import discover_block_size

from pkcs7 import pkcs7_pad

from util import \
        base64_to_bytearray, \
        bytearray_to_base64, \
        str_to_bytearray

from xor import xor


_KEY = random_key()
_IV = random_key()


def encrypt_userdata(s: str) -> str:
    """Embed a userdata tuple into a query string, and encrypt it."""
    if s.find('=') >= 0 or s.find(';') >= 0:
        raise Exception('Illegal characters in user string.')
    output = encrypt_aes_128_cbc(pkcs7_pad(
            str_to_bytearray(
                'comment1=lorem%20ipsum%20dolor;userdata=' + s +
                ';comment2=%20sit%20amet')
        ), _KEY, _IV)
    return bytearray_to_base64(output)


def check_admin(crypttext: str) -> bool:
    """Decrypt a query string, and look for 'admin=true'."""
    b = base64_to_bytearray(crypttext)
    clear = decrypt_aes_128_cbc(b, _KEY, _IV)
    # print(f'clear = {clear}')
    if clear.find(b'admin=true') >= 0:
        return True
    else:
        return False


def cbc_bitflip_attack(fn: Callable[[str], str]) -> str:
    """Execute a bitflipping attack.

    Using what we know about consecutive blocks in CBC,
    create and inject a block containing ';admin=true;'.
    """
    #TODO
    return None


if __name__ == '__main__':

    admin_profile = cbc_bitflip_attack(encrypt_userdata)
    admin = check_admin(admin_profile)
    print(f'check_admin(): {admin}')
