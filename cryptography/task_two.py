import time
from ECDHCipher import *

def evaluate_performance(_k: int, _ecdh: ECDHCipher):
    # private keys of k bits
    alice_private_key = 2**_k - 1
    bob_private_key = 2**_k - 2

    # public keys
    start_time = time.time()
    alice_public_key = _ecdh.multiply_point(alice_private_key)
    end_time = time.time()
    alice_public_key_time = (end_time - start_time)*1000

    start_time = time.time()
    bob_public_key = _ecdh.multiply_point(bob_private_key)
    end_time = time.time()
    bob_public_key_time = (end_time - start_time)*1000

    # shared secret
    start_time = time.time()
    shared_key = _ecdh.multiply_point(alice_private_key, bob_public_key)
    end_time = time.time()
    shared_key_time = (end_time - start_time)*1000

    return [alice_public_key_time, bob_public_key_time, shared_key_time]


def main():
    # NIST Standards for Weierstrass Curves over prime fields
    a = -3
    b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
    gx = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
    gy = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
    security_level_to_prime = {
        128: 2**128 - 2**96 + 1,
        192: 2**192 - 2**64 - 1,
        256: 2**256 - 2**224 + 2**192 + 2**96 - 1,
    }

    for k in security_level_to_prime.keys():
        p = security_level_to_prime[k]
        ecdh = ECDHCipher(a, b, p, gx, gy)
        [alice_public_key_time, bob_public_key_time, shared_key_time] = evaluate_performance(k, ecdh)
        print(f'\n\nPerformance for {k}-bit prime:\nAlice Public Key Generation Time: {alice_public_key_time:.6f} ms\nBob Public Key Generation Time: {bob_public_key_time:.6f} ms\nShared Key Generation Time: {shared_key_time:.6f} ms')


main()







