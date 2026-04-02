#!/usr/bin/env python3

"""
SHA-1.

COMP 383
Assignment 9

Chris Cianci
"""


import hashlib
import struct

from aes_ecb import random_key
from aes_cbc import decrypt_aes_128_cbc, encrypt_aes_128_cbc


def leftrotate(value, shift):
    """Shift left with wrapping."""
    return ((value << shift) & 0xffffffff) | (value >> (32 - shift))


def sha1(message,
         ml=None,
         h0=0x67452301,
         h1=0xEFCDAB89,
         h2=0x98BADCFE,
         h3=0x10325476,
         h4=0xC3D2E1F0):
    """Generate the SHA1 hash of the input."""
    # Pre-processing:

    # ml = message length in bits (always a multiple of the number of bits
    # in a character).
    if ml is None:
        ml = len(message) * 8

    # append the bit '1' to the message e.g. by adding 0x80 if message
    # length is a multiple of 8 bits.
    message += b'\x80'

    # append 0 <= k < 512 bits '0', such that the resulting message length
    # in bits is congruent to -64 ≡ 448 (mod 512)
    while (len(message) * 8) % 512 != 448:
        message += b'\x00'

    # append ml, the original message length in bits, as a 64-bit
    # big-endian integer. Thus, the total length is a multiple of 512 bits.
    message += struct.pack('>Q', ml)
    # Process the message in successive 512-bit (64-byte) chunks:
    for i in range(0, len(message), 64):

        # break chunk into sixteen 32-bit big-endian words w[i], 0 <= j <= 15
        w = [0] * 80
        for j in range(16):
            w[j] = struct.unpack('>I', message[i + j * 4:i + j * 4 + 4])[0]

        # extend the sixteen 32-bit words into eighty 32-bit words:
        for j in range(16, 80):
            w[j] = leftrotate(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1)

        # Initialize hash value for this chunk:
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4

        # Main loop
        for j in range(80):
            if j <= 19:
                f = d ^ (b & (c ^ d))
                k = 0x5A827999
            elif 20 <= j <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= j <= 59:
                f = (b & c) | (d & (b | c))
                k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            temp = leftrotate(a, 5) + f + e + k + w[j] & 0xffffffff
            e = d
            d = c
            c = leftrotate(b, 30)
            b = a
            a = temp

        # Add this chunk's hash to result so far:
        h0 = (h0 + a) & 0xffffffff
        h1 = (h1 + b) & 0xffffffff
        h2 = (h2 + c) & 0xffffffff
        h3 = (h3 + d) & 0xffffffff
        h4 = (h4 + e) & 0xffffffff

    # Produce the final hash value (big-endian) as a 160 bit number:
    # (hexadecimal)
    return '%08x%08x%08x%08x%08x' % (h0, h1, h2, h3, h4)




def build_mac(plaintext:str):
    """Generate a function with 'static' variables."""
    unknown_key = random_key(16)
    iv = random_key(16)
    pt = bytearray(plaintext, 'utf-8')

    #generates mac for the plaintext, concats the two, encrypts with CBC and returns
    def mac_encrypt(pt):
        nonlocal unknown_key
        nonlocal iv
        message_mac = mac(pt) + pt
        return encrypt_aes_128_cbc(message_mac, unknown_key, iv)

    #decrypts and checks mac throws an error if mac doesn't match
    def mac_decrypt(ct):
        nonlocal unknown_key
        nonlocal iv
        full_message = decrypt_aes_128_cbc(ct, unknown_key, iv)
        message_mac = full_message[:40]
        pt = full_message[40:]
        print(pt)
        print(message_mac)
        print(mac(message=pt))
        if message_mac != mac(pt):
            raise Exception("Mac Address Does Not Match Message")
        
        return pt

    #generates SHA-1 MAC for a message using the unknown key
    def mac(message:bytearray)->bytearray:
        nonlocal unknown_key
        clear = unknown_key + message
        mac = bytearray(sha1(clear), 'utf-8')
        return mac
    
    def validate_mac(plaintext, given_mac):
        nonlocal unknown_key
        message_mac = mac(plaintext)
        return message_mac == given_mac


    return mac, validate_mac


if __name__ == '__main__':

    print('Test 1: Local SHA-1 matches library.')
    test_message = b'SpRiNg BrEaK!'
    local_hash = sha1(test_message)
    library_hash = hashlib.sha1(test_message).hexdigest()
    # print(local_hash)
    # print(library_hash)
    print('  SUCCESS' if (local_hash == library_hash) else '  FAILURE')


