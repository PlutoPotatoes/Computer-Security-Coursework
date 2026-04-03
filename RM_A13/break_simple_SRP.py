import hashlib
import hmac
import random

N:int = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001
g:int = 2
k:int = 3

client_sk = random.randint(4, 25)
client_password = 'surely no one can guess this'

password_bank = ['coolguy123', 'password', '123445677', 'surely no one can guess this']

def client_simplified_srp(salt: bytes, B:int) -> tuple[int, hmac.HMAC]:
    a = client_sk
    A = pow(g, a, N)
    x = int(hashlib.sha256(bytearray(salt) + bytearray(client_password, 'utf-8')).hexdigest(), 16)
    u = int(hashlib.sha256(bytearray(A.to_bytes((A.bit_length() + 7) // 8) + bytearray(A.to_bytes((A.bit_length() + 7) // 8)))).hexdigest(), 16)
    S = pow(B, (a + u*x), N)
    S = S.to_bytes((S.bit_length() + 7) // 8)
    K = int(hashlib.sha256(S).hexdigest(), 16)
    mac = hmac.new(K.to_bytes((K.bit_length() + 7)//8), bytearray(salt), hashlib.sha256)

    return A, mac

def get_client_password() -> str:
    salt = random.randint(5, 1000)
    salt = salt.to_bytes((salt.bit_length() + 7) // 8)
    b = random.randint(0, 25)
    B = pow(g, b, N)
    
    #send false data to client to get a final shared secret hash
    A, mac = client_simplified_srp(salt, B)
    u = int(hashlib.sha256(bytearray(A.to_bytes((A.bit_length() + 7) // 8) + bytearray(A.to_bytes((A.bit_length() + 7) // 8)))).hexdigest(), 16)


    for password in password_bank:
        x = int(hashlib.sha256(bytearray(salt) + bytearray(password, 'utf-8')).hexdigest(), 16)
        v = pow(g, x, N)
        S = pow((A * pow(v,u,N)), b , N)
        S = S.to_bytes((S.bit_length() + 7)//8)
        K = int(hashlib.sha256(S).hexdigest(), 16)
        mac_guess = hmac.new(K.to_bytes((K.bit_length() + 7)//8), salt, hashlib.sha256)

        
        if hmac.compare_digest(mac.digest(), mac_guess.digest()):
            print(f'Found password with equivalent MAC verification: {password}')
            return password

    return "no password found"

if __name__ == '__main__':
    print(get_client_password())