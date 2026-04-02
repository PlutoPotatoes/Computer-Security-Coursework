from sha1 import sha1
from random import randint
import hashlib
import hmac

def SRP(I:str = 'rmorrell@oxy.edu', password:str = 'secretPassword',
        N:int = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001,
        g:int = 2, k:int = 3):
    
    #Private keys are generated for the connection, assume these are never shared and generated fresh for the session
    server_sk = randint(5, 20)
    client_sk = randint(5, 20)
    
    '''1. User Sign Up: Server uses password once alongside salt to store a unique hash and calculate v (S)'''
    #server calculates xH and x from password 
    hex_password = bytearray(password.encode('utf-8'))
    salt = bytearray(randint(0, 0xFFFFFFFFFF).to_bytes(10))
    salt_pass = salt + hex_password
    xH = hashlib.sha256(salt_pass)
    x = int(xH.hexdigest(), 16)

    #using x server finds v and stores it. x and xH can now be discarded so they can't be leaked
    #salt is saved for later sign in attempts
    v = pow(g, x, N)
    server_salt = salt

    '''2. Client sends login information along with freshly generated public key to the server initiating a login(C->S)'''
    username = I
    A = pow(g, client_sk, N)

    '''3. Server sends salt and public key to the user '''
    client_salt = server_salt
    B = (v*k + g**server_sk )%N

    '''4. with public keys shared, both parties calculate u'''
    uH = hashlib.sha256(bytearray(A.to_bytes((A.bit_length() + 7) // 8)) + bytearray(B.to_bytes((B.bit_length() + 7) // 8)))
    u = int(uH.hexdigest(), 16)

    '''5. Client generates their own xH and x, finds S and hashes S into K'''
    hex_password = bytearray(password.encode('utf-8'))
    salt_pass = client_salt + hex_password
    xH = hashlib.sha256(salt_pass)
    x = int(xH.hexdigest(), 16)

    Client_S = pow((B - k * pow(g,x, N)), (client_sk + u * x), N)
    Client_K = int(hashlib.sha256(Client_S.to_bytes((Client_S.bit_length() + 7) // 8)).hexdigest(),16)
    print(Client_K)

    '''6. Server finds it's own S and create it's own K'''
    Server_S = pow((A * pow(v,u,N)), server_sk , N)
    Server_K = int(hashlib.sha256(Server_S.to_bytes((Server_S.bit_length() + 7) // 8)).hexdigest(), 16)
    print(Server_K)
    '''
    7. Server and Client both calculate HMAC-SHA256 using K and salt
        if they match then the server will allow the client to log in successfully
    '''
    Client_MAC = hmac.new(Client_K.to_bytes((Client_K.bit_length() + 7) // 8), salt, hashlib.sha256)
    Server_MAC = hmac.new(Server_K.to_bytes((Server_K.bit_length() + 7) // 8), salt, hashlib.sha256)
    
    if hmac.compare_digest(Client_MAC.digest(), Server_MAC.digest()):
        print("Login successful")
        return True
    else:
        return False
    

if __name__ == '__main__':
    SRP()
    


