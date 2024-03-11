# author: Asif Azad
# Date: 2020-12-26
# About: time evaluation of ECDHCipher; task 2


import time;
from ECDHCipher import ECDHCipher

def evaluate_performance(_ecdh: ECDHCipher):
    # private keys of k bits
    alice_private_key = 2**_ecdh.k - 1
    bob_private_key = 2**_ecdh.k - 2

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
    for security_level in range(3):
        ecdh = ECDHCipher(_security_level = security_level)
        ecdh.show_curve()

        [alice_public_key_time, bob_public_key_time, shared_key_time] = evaluate_performance(ecdh)
        print(f'\n\nPerformance for {ecdh.k}-bit prime:\nAlice Public Key Generation Time: {alice_public_key_time:.6f} ms\nBob Public Key Generation Time: {bob_public_key_time:.6f} ms\nShared Key Generation Time: {shared_key_time:.6f} ms')

main()







