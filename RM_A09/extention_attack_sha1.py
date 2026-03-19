import struct
from sha1 import sha1, build_mac
from aes_cbc import encrypt_aes_128_cbc, decrypt_aes_128_cbc

def sha1_padding(ml):
    padding = b'\x80'
    while ((ml + len(padding)) * 8) % 512 != 448:
        padding += b'\x00'
    padding += struct.pack('>Q', ml * 8)
    return padding

    return message

#we are given the full plaintext (MAC_DIGEST||PLAINTEXT) not the key or the padding
def add_admin(full_plaintext, new_message, payload, verify):
    sha_state = full_plaintext[:40]
    old_message = full_plaintext[40:]
    h0 = int(sha_state[0:8], 16)
    h1 = int(sha_state[8:16], 16)
    h2 = int(sha_state[16:24], 16)
    h3 = int(sha_state[24:32], 16)
    h4 = int(sha_state[32:40], 16)

    for key_len in range(16, 17):
        print(key_len)
        padding = bytearray(sha1_padding(key_len + len(old_message)))

        total_len = (key_len+len(old_message)+len(padding)+len(payload)) *8
        
        new_mac = bytearray(sha1(payload, total_len, h0,h1,h2,h3,h4), 'utf-8')

        full_mac_messasge = old_message + padding + payload

        # print(full_payload)
        # print('')
        # print('')
        # print(full_plaintext)
        if verify(full_mac_messasge, new_mac):
            print(f"found valid mac for {new_message}: {new_mac}")
            return new_mac + old_message + padding + payload

    raise Exception("key is longer than expected")



if __name__=='__main__':
    message = bytearray("comment1=Io%20triumphe;userdata=foo;comment2=Haben%20swaben%20rebecca", 'utf-8')
    admin_message = message + bytearray(";admin=true;", 'utf-8')
    get_mac, validate_mac = build_mac(message.decode())
    message_mac = get_mac(message)
    full_plaintext = message_mac + message

    payload = add_admin(full_plaintext, admin_message, b';admin=true;', validate_mac)
    print(payload)