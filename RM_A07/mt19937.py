#!/usr/bin/env python3

"""
Random number generation; Mersenne Twister (MT19937).

COMP 383
Assignment 7

Chris Cianci
"""


from typing import Callable
import time
import random
from xor import xor


def build_mt19937(seed: int) -> Callable[[], int]:
    """Generate a function with 'static' variables."""
    # set all the constants, as prescribed by the algorithm
    # TODO
    w = 32
    n = 624
    m = 397
    r = 31
    a = 0x9908B0DF
    u, d = 11, 0xFFFFFFFF
    s, b = 7, 0x9D2C5680
    t, c = 15, 0xEFC60000
    l = 18
    f = 1812433253

    # generate the masks from r
    lower_mask = (1<<r)-1
    upper_mask = lower_mask^d

    
    # generate the initial state vector and index
    x = [0 for i in range(n)]
    x[0] = seed
    for i in range(1, n):
        num = (f * (x[i-1] ^ (x[i-1] >> (w-2))) + i) 
        x[i] = num & d

    k = n+1 # invoke twist on very first external request

    def twist():
        """Twist the statevector after using all the entries."""
        nonlocal x

        for i in range(n):
            y = (x[i] & upper_mask) | (x[(i+1) % n] & lower_mask)

            z = y >> 1
            if (y%2) != 0:
                z = z^a
            x[i] = x[(i+m)%n] ^ z

        return

    def mt19937() -> int:
        """Yield the next pseudo-random number in the sequence."""
        nonlocal k
        # check if it's time to twist
        if k >= n:
            twist()
            k = 0
        # temper the next state value
        y = x[k]
        y = y^((y>>u)&d)
        y = y^((y<<s)&b)
        y = y^((y<<t)&c)
        num = y^(y>>l)
        k+=1
        return num

    return mt19937

def splice_mt19937(state: list[int]) -> Callable[[], int]:
    """Generate a function with 'static' variables."""
    # set all the constants, as prescribed by the algorithm
    # TODO
    w = 32
    n = 624
    m = 397
    r = 31
    a = 0x9908B0DF
    u, d = 11, 0xFFFFFFFF
    s, b = 7, 0x9D2C5680
    t, c = 15, 0xEFC60000
    l = 18
    f = 1812433253

    # generate the masks from r
    lower_mask = (1<<r)-1
    upper_mask = lower_mask^d

    k = n+1 # invoke twist on very first external request
    x = state
    def twist():
        """Twist the statevector after using all the entries."""
        nonlocal x

        for i in range(n):
            y = (x[i] & upper_mask) | (x[(i+1) % n] & lower_mask)

            z = y >> 1
            if (y%2) != 0:
                z = z^a
            x[i] = x[(i+m)%n] ^ z

        return

    def mt19937() -> int:
        """Yield the next pseudo-random number in the sequence."""
        nonlocal k
        # check if it's time to twist
        if k >= n:
            twist()
            k = 0
        # temper the next state value
        y = x[k]
        y = y ^ ((y >> u) & d)
        y = y ^ ((y << s) & b)
        y = y ^ ((y << t) & c)
        y = y ^ (y >> l)
        k+=1
        return y

    return mt19937

#This is what we discussed in class but all other implementations I can find are significantly more complex
#The one below works well for our 32 bit implementation.
def untemper_new(z: int):
    u, d = 11, 0xFFFFFFFF
    s, b = 7, 0x9D2C5680
    t, c = 15, 0xEFC60000
    l=18
    
    y = z ^ (z>>l)
    y = y ^ ((y<<t) & c)
    y = y ^ ((y<<s) & b)
    y = y ^ ((y>>u) & d)
    return y


def untemper(y: int):
    u, d = 11, 0xFFFFFFFF
    s, b = 7, 0x9D2C5680
    t, c = 15, 0xEFC60000
    l=18

    y ^= y >> l
    y ^= y << t & c
    for i in range(7):
        y ^= y << s & b
    for i in range(3):
        y ^= y >> u & d
    return y


def timestamp_random():
    seed = int(time.time()) - random.randint(40, 1000)
    generated = build_mt19937(seed)()

    current_time = int(time.time())
    offset = None
    for i in range(40, 1001):
        copy = build_mt19937(current_time-i)()
        if copy == generated:
            print(f"seed = {current_time-i}")
            offset = current_time-i
    print(f"actual seed = {seed}")
    if offset != None:
        print(f"Key was generated using time as a seed {offset} seconds ago")
        return True
    return False

def clone_mt19937():
    n = 624
    m = 397
    r = 31
    a = 0x9908B0DF
    u, d = 11, 0xFFFFFFFF
    lower_mask = (1<<r)-1
    upper_mask = lower_mask^d
    
    #create new RNG instance and generate a full state's worth of numbers
    rng = build_mt19937(int(time.time()))
    x = []
    for _ in range(n):
        #store the untempered version of the numbers
        num = rng()
        x.append(untemper(num))

    rng_copy = splice_mt19937(x)
    generated = [rng() for _ in range(n)]
    copied = [rng_copy() for _ in range(n)]

    print(f"copied rng output:  {copied[:4]}")
    print(f"initial generation: {generated[:4]}")

    return copied==generated

def mt19927_pad_encrypt(pt:bytearray, key:int):
    #instantiate our RNG
    rng = build_mt19937(key)
    #generate a keystream as long as the ciphertext
    n = len(pt)
    stream = bytearray()
    while len(stream)<n:
        val = rng() & 0xFF
        stream.append(val)
    ct = xor(pt, stream)
    return ct
    
def mt19927_pad_decrypt(ct:bytearray, key:int):
    rng = build_mt19937(key)

    n = len(ct)
    stream = bytearray()
    while len(stream)<n:
        val = rng() & 0xFF
        stream.append(val)
    
    pt = xor(ct, stream)
    return pt

def crack_mt19927_16(pt):
    seed = int(time.time()) & 0xFFFF
    ct = mt19927_pad_encrypt(bytearray(pt, 'utf-8'), seed)
    key = 0x0000
    while key < 0xFFFF:
        found = mt19927_pad_decrypt(ct, key)
        if mt19927_pad_decrypt(ct, key) == bytearray(pt, 'utf-8'):
            print(f"found message: {found}")
            print(f"found with key: {key}")
            return key
        key +=1


    return "Not mt19927 or not 16 bit"

if __name__ == '__main__':

    import numpy

    #C21
    '''seeds = range(100, 110)
    for s in seeds:
        rs = numpy.random.RandomState(s)
        nprng = lambda: rs.randint(0, 2**32, dtype=numpy.uint32)
        myrng = build_mt19937(s)
        for i in range(1500):
            # fail immediately (and loudly)
            # if we didn't get the right sequence.
            assert (nprng() == myrng())
    print('SUCCESS (no sequence errors encountered).')'''

    #C22
    timestamp_random()

    #C23
    print(clone_mt19937())

    #C24
    #key = int(time.time())
    #ct = mt19927_pad_encrypt(bytearray('Hello it is me', 'utf-8'), key)
    #pt = mt19927_pad_decrypt(ct, key)
    #key = crack_mt19927_16("hello it's me")
