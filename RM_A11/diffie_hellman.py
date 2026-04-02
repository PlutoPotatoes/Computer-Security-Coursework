def dh_public_key(private_key: int,
                p= int('ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff', 16),
                g = 2
                ) -> int: 
    return pow(g, private_key, p)


def dh_session(private_key: int, public_key: int,
               p= int('ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff', 16),
                g = 2) -> int:
    return pow(public_key, private_key, p)

if __name__ == "__main__":
    a = 3
    b = 7

    a_pub = dh_public_key(a)
    b_pub = dh_public_key(b)

    a_session = dh_session(a, b_pub)
    b_session = dh_session(b, a_pub)

    print(f"session key A: {a_session}")
    print(f"session key B: {b_session}")

    if a_session == b_session:
        print("keys match")