from libnum import invmod
from sympy import randprime
from sha1 import sha1

D = 0
Server_Cache = []
#oracle takes a message and public key,
#generates a private key and N and return the ciphertext
def encrypt_oracle(message:bytes, e:int=3):

    while True:
        try:
            p = randprime(2**1000, 2**1001)
            q = randprime(2**1000, 2**1001)
            assert type(p) == int and type(q) == int
            n = p * q
            et = ((p - 1) * (q - 1))

            # calc private key that we won't actually use but for completions sake :)
            D = invmod(e, et)
            break
        except(Exception):
            continue

    m = int(message.hex(), 16)
    #return ciphertext using different N but uniform e=3
    c = pow(m, e, n)
    return c, n, e, D

def decrypt_oracle(C, n):
    Server_Cache.append(sha1(C.to_bytes((C.bit_length() + 7) // 8)))
    if C in Server_Cache:
        raise KeyError('this message has already been decrypted')
    m = pow(C, D, n)
    return m

def UnpaddedOracleAttack(C, n, e):
    #first find an s with an inverse mod N
    S = 0
    while True:
        S= randprime(2, 1000)
        if S%n<=1:
            continue
        try:
            invmod(S, n)
            break
        except(Exception):
            continue
    assert type(S) == int

    #create and encrypt payload ciphertext
    C_prime = (pow(S, e, n) * C) % n
    P_prime = decrypt_oracle(C_prime, n)

    #recover P from P_Prime and convert from hexadecimal 
    P = (P_prime%n//S) % n
    hex_rep = hex(P)[2:]
    hex_rep = '0'*(len(hex_rep) % 2) + hex_rep
    return bytes.fromhex(hex_rep) 

if __name__ == "__main__":


    c, n, e, D = encrypt_oracle(b'42')
    p = UnpaddedOracleAttack(c, n, e)
    print(p)
    