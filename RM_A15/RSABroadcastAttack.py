from libnum import invmod
from sympy import randprime
from math import cbrt

#oracle takes a message and public key,
#generates a private key and N and return the ciphertext
def oracle(message:bytes, e:int=3):

    while True:
        try:
            p = randprime(2**100, 2**101)
            q = randprime(2**100, 2**101)
            assert type(p) == int and type(q) == int
            n = p * q
            et = ((p - 1) * (q - 1))

            # calc private key that we won't actually use but for completions sake :)
            d = invmod(e, et)
            break
        except(Exception):
            continue

    m = int(message.hex(), 16)
    #return ciphertext using different N but uniform e=3
    c = pow(m, e, n)
    return c, n
    
#find plaintext from 3 encryptions of the same message
def broadcast_attack(message:bytes):
    c0, n_0 = oracle(message=message)
    c1, n_1 = oracle(message=message)
    c2, n_2 = oracle(message=message)

    m_s_0 = n_1*n_2
    m_s_1 = n_0*n_2
    m_s_2 = n_0*n_1

    N_012 = n_0*n_1*n_2

    result =((c0 * m_s_0 * invmod(m_s_0, n_0)) +
            (c1 * m_s_1 * invmod(m_s_1, n_1)) +
            (c2 * m_s_2 * invmod(m_s_2, n_2))) % N_012
    p = cbrt(result)
    p = int(p)
    hex_rep = hex(p)[2:]
    hex_rep = '0'*(len(hex_rep) % 2) + hex_rep
    return bytes.fromhex(hex_rep)
    

if __name__ == "__main__":
    message = broadcast_attack(b'42')
    print(message)