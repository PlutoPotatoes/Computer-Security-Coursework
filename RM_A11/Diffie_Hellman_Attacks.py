from sha1 import sha1
from diffie_hellman import *
from aes_cbc import encrypt_aes_128_cbc, decrypt_aes_128_cbc
from random import randbytes, randint
from pkcs7 import pkcs7_unpad

#base diffie hellman keyswap, both sides get a shared secret to communicate
def unmeddled_keyswap(a_message, b_message, A_secret, B_secret)-> tuple[bytearray, bytearray]:
    # 1st shared parameters are used to find public keys to share
    a_public = dh_public_key(A_secret)
    b_public = dh_public_key(B_secret)

    shared_secret_a = dh_session(A_secret, b_public)
    shared_secret_b = dh_session(B_secret, a_public)

    a_key = bytearray(sha1(shared_secret_a.to_bytes(shared_secret_a.bit_length()//4+1)),'utf-8')[:16]
    b_key = bytearray(sha1(shared_secret_b.to_bytes(shared_secret_b.bit_length()//4+1)),'utf-8')[:16]
    if shared_secret_a != shared_secret_b:
        raise Exception('keys don\'t match')
    
    # 2nd both encrypt message using the hashed secret, IV could be different but it's public anyways
    iv = bytearray(randbytes(16))
    A_ct = encrypt_aes_128_cbc(bytearray(a_message, 'utf-8'), a_key, iv) + iv
    B_ct = encrypt_aes_128_cbc(bytearray(b_message, 'utf-8'), b_key, iv) + iv

    # 3rd both decrypt using their own secret
    A_pt = decrypt_aes_128_cbc(B_ct, a_key, iv)
    B_pt = decrypt_aes_128_cbc(A_ct, b_key, iv)

    A_pt = pkcs7_unpad(A_pt[:len(A_pt)-len(iv)])
    B_pt = pkcs7_unpad(B_pt[:len(B_pt)-len(iv)])

    if A_pt.decode() == b_message and B_pt.decode() == a_message:
        return (A_pt, B_pt)
    else:
        print(A_pt)
        print(B_pt)
        print(a_message)
        print(b_message)
        raise Exception('decode went wrong')
    
'''
Here a malicious attacker inctercepts at each step and offers their own public key to each party.

Neither party will be able to decrypt the other's message, 
but the middle man will have access to all messages

A and B secret keys will be generated randomly and only used for the inital session generation, 
but the middle man won't need the secrets at any point
'''
def middleman_attack(a_message, b_message, M_secret)-> tuple[bytearray, bytearray]:
    A_secret = randint(a=10, b=99)
    B_secret = randint(a=10, b=99)

    # Public keys are generated alongside the middleman's public key
    a_public = dh_public_key(A_secret)
    b_public = dh_public_key(B_secret)
    m_public = dh_public_key(M_secret)

    #The middle man then intercepts and replaces both public keys with their own
    shared_secret_a = dh_session(A_secret, m_public)
    shared_secret_b = dh_session(B_secret, m_public)

    # From then on both A and B procede as normal, unaware of the trick
    a_key = bytearray(sha1(shared_secret_a.to_bytes(shared_secret_a.bit_length()//4+1)),'utf-8')[:16]
    b_key = bytearray(sha1(shared_secret_b.to_bytes(shared_secret_b.bit_length()//4+1)),'utf-8')[:16]

    #our attacker then creates identical session keys for each sending party
    AM_key = dh_session(M_secret, a_public)
    AM_key = bytearray(sha1(AM_key.to_bytes(AM_key.bit_length()//4+1)),'utf-8')[:16]
    BM_key = dh_session(M_secret, b_public)
    BM_key = bytearray(sha1(BM_key.to_bytes(BM_key.bit_length()//4+1)),'utf-8')[:16]

    # both encrypt message using the hashed secret with M and a public iv
    iv = bytearray(randbytes(16))
    A_ct = encrypt_aes_128_cbc(bytearray(a_message, 'utf-8'), a_key, iv) + iv
    B_ct = encrypt_aes_128_cbc(bytearray(b_message, 'utf-8'), b_key, iv) + iv

    # However, neither can decrypt the other's message using their private key
    A_pt = decrypt_aes_128_cbc(B_ct, a_key, iv)
    B_pt = decrypt_aes_128_cbc(A_ct, b_key, iv)
    A_pt = pkcs7_unpad(A_pt[:len(A_pt)-len(iv)])
    B_pt = pkcs7_unpad(B_pt[:len(B_pt)-len(iv)])

    print(f'B\'s message decrytped by A: {A_pt}')
    print(f'A\'s message decrytped by B: {B_pt}')

    # Our attacker however... can decrypt both using their session key from earlier

    AM_pt = decrypt_aes_128_cbc(A_ct, AM_key, iv)
    BM_pt = decrypt_aes_128_cbc(B_ct, BM_key, iv)
    AM_pt = pkcs7_unpad(AM_pt[:len(AM_pt)-len(iv)])
    BM_pt = pkcs7_unpad(BM_pt[:len(BM_pt)-len(iv)])

    print(f'A\'s message decrytped by M: {AM_pt}')
    print(f'B\'s message decrytped by M: {BM_pt}')






if __name__ == '__main__':
    message_1 = 'this is a\'s message and it is secret'
    message_2 = 'this is b\'s message and it is secret'

    print(f'A normal keyswap decrypts for each party as follows: {unmeddled_keyswap(message_1, message_2, 3, 5)}')
    middleman_attack(message_1, message_2, 5)
    

