#!/usr/bin/env python3

"""
ECB cut-and-paste.

COMP 383
Assignment 4 (Challenge 13)

Chris Cianci
"""

from typing import Callable

from aes_ecb import decrypt_aes_128_ecb, encrypt_aes_128_ecb, random_key

from pkcs7 import pkcs7_pad, pkcs7_unpad

from util import \
        base64_to_bytearray, \
        bytearray_to_base64, \
        bytearray_to_str, \
        str_to_bytearray


_KEY = random_key()


def query_to_dict(kvstr: str) -> dict[str, str]:
    """Convert key-value string to dictionary."""
    entries = kvstr.split('&')
    query_dict = dict()
    for entry in entries:
        pair = entry.split('=')
        query_dict[pair[0]] = pair[1]

    return query_dict


def dict_to_query(d: dict[str, str], order: list[str] | None) -> str:
    """Convert dictionary to key-value string."""
    query_string = ''
    if order:
        for key in order:
            query_string += key + "=" + d[key] + "&"
    else:
        for key in d.keys():
            query_string += key + "=" + d[key] + "&"
    query_string = query_string[:-1]
    return query_string


def profile_for(email: str) -> str:
    """Generate a profile kv string for given email.

    Because this is the attackee's function, return base64.
    """
    # Don't allow encoding special characters in email addresses.
    if '&' in email or '=' in email:
        raise Exception('Invalid characters in profile.')
    profile = {
        'email': email,
        'uid': '42',
        'role': 'user'
    }
    return bytearray_to_base64(encrypt_aes_128_ecb(pkcs7_pad(str_to_bytearray(dict_to_query(profile, None)), 16), _KEY))


def check_admin(encrypted_profile: str) -> bool:
    """Decrypt a given profile, and look for the {role: admin} entry.

    Because this is the attackee's function, the input is base64.
    """
    ct = base64_to_bytearray(encrypted_profile)
    decrypted_profile = decrypt_aes_128_ecb(ct, _KEY)
    print(decrypted_profile)
    profile_query = bytearray_to_str(pkcs7_unpad(decrypted_profile))
    profile = query_to_dict(profile_query)
    return profile['role']=='admin'


def make_fake_admin(fn: Callable[[str], str]) -> str:
    """Generate a ciphertext containing role=admin.

    Using only calls to "profile_for()", generate a ciphertext
    that will cause "check_admin()" to return True.

    1. create email that is exactly blocksize long. follow it with admin padded to block size. store the role admin block
    2. then create an email that pushes the role to it's own block. 
    3. replace this block with the stored role admin block
    """
    #find block length
    init = base64_to_bytearray(fn('a'))
    start_len = len(init)  # type: ignore
    curr_block = base64_to_bytearray(fn('a'))
    payload_len = 1
    while len(curr_block) == start_len: #type:ignore
        payload_len +=1
        curr_block = base64_to_bytearray(fn('a'*payload_len))
    block_size = len(curr_block) - start_len #type:ignore

    #create a payload 
    #1. pad 'email=' so the email will be at the start of a new block
    payload = pkcs7_pad(str_to_bytearray('email='), block_size)
    #2. create the email block where email=(padding) | admin(padding)
    role_block = pkcs7_pad(str_to_bytearray('admin'), block_size)
    payload.extend(role_block)
    #3. remove the 'email=' prefix so it passes the profile creation check
    cleaned_payload = payload.removeprefix(str_to_bytearray('email='))
    #4. create the profile
    profile = profile_for(bytearray_to_str(cleaned_payload))
    check_admin(profile)
    #isolate the 'admin(padding) block
    profile_bytes = base64_to_bytearray(profile)
    admin_block = profile_bytes[block_size:block_size*2]

    '''create account to manipulate:
    account needs to push the role block to it's own block
    ex. email=smthsmth(padding)&uid=smth&role=|user(padding)

    Note that we don't know the length of the userID, only the role. 
    1. create account with email='a'
    2. lengthen email until a new block is reached 
    3. add 'aaaa' to finish pushing the role to it's own block
    4. replace the role block with out own encrypted block
    '''
    email = 'aa'
    curr_block = base64_to_bytearray(fn(email))
    while len(curr_block) == start_len: #type:ignore
        email += 'a'
        curr_block = base64_to_bytearray(fn(email))
    email +='aaaa'
    account = base64_to_bytearray(fn(email))
    admin_account = account[:-16]
    admin_account.extend(admin_block)
    admin_account = bytearray_to_base64(admin_account)
    return admin_account


if __name__ == '__main__':

    print(f"role==admin? {check_admin(make_fake_admin(profile_for))}")
