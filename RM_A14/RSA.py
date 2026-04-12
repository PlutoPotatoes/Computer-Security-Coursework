from sympy import randprime

# def invmod(a, n):
#     t = 0
#     r = n
#     newt = 1
#     newr = a
#     while newr != 0:
#         q = r//newr
#         (t, newt) = (newt, t - q*newt)
#         (r, newr) = (newr, r-q*newr)
    
#     if r > 1:
#         raise(Exception('a is not invertable'))
#     if t< 0:
#         t = t+n
#     return t

def invmod(a, n):
    t = 0
    T = 1
    r = n
    R = a

    while R != 0:
        q = r // R

        t, T = (T, t - q * T)
        r, R = (R, r-q * R)

    if r > 1:
        raise ValueError('a is not invertible')

    if t < 0:
        t = t + n

    return t


def rsa():

    while True:
        try:
            p = randprime(2**1023, 2**1024)
            q = randprime(2**1023, 2**1024)
            assert type(p) == int and type(q) == int
            

            n = p * q
            et = ((p - 1) * (q - 1))
            e = 3

            if p%e==0 or q%e==0:
                continue


            # calc private key
            d = invmod(e, et)
            break
        except(Exception):
            continue

    return (e, n), (d, n)


def public_encrypt(e, n, message: bytes):
    m = int(message.hex(), 16)
    print(m)
    c = pow(m, e, n)
    print(c)

    return c

def private_encrypt(d, n, c):
    m = pow(c, d, n)
    hex_rep = hex(m)[2:]
    hex_rep = '0'*(len(hex_rep) % 2) + hex_rep
    return bytes.fromhex(hex_rep)

if __name__ == "__main__":
    print(invmod(17, 3120))
    (e, n), (d, n) = rsa()
    print(f'should be 1: {(e*d)%n}')
    c = public_encrypt(e, n, b'super secret message')
    m = private_encrypt(d, n, c)
    print(m)
