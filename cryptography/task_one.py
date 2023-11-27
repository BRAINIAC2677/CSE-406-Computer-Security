import time
from BitVector import BitVector
from AESCipher import generate_round_key, aes_encrypt, aes_decrypt


def main():
    key = input("Enter key: ") 
    plain_text = input("Enter plain text: ")
    if len(key) < 16:
        key = key + (16 - len(key)) * ' '
    elif len(key) > 16:
        key = key[:16]
    
    start_time = time.time()
    initial_key = [[BitVector(intVal=ord(key[i*4+j]), size=8) for i in range(4)] for j in range(4)]
    generate_round_key(initial_key, 10)
    end_time = time.time()
    key_schedule_time = (end_time - start_time)*1000

    print(f'\nKey:\nIn ASCII: {key}\nIn HEX: {key.encode("utf-8").hex()}')
    print(f'\nPlain text:\nIn ASCII: {plain_text}\nIn HEX: {plain_text.encode("utf-8").hex()}')

    start_time = time.time()
    [cipher_text, cipher_hex] = aes_encrypt(key, plain_text)
    end_time = time.time()
    encryption_time = (end_time - start_time)*1000
    print(f'\nCipher text:\nIn ASCII: {cipher_text}\nIn HEX: {cipher_hex}')

    start_time = time.time()
    [decipher_text, decipher_hex] = aes_decrypt(key, cipher_text)
    end_time = time.time()
    decryption_time = (end_time - start_time)*1000
    print(f'\nDecipher text:\nIn ASCII: {decipher_text}\nIn HEX: {decipher_hex}')

    print(f'\n\nExecution Time Details:\nKey Schedule Time: {key_schedule_time:.6f} ms\nEncryption Time: {encryption_time:.6f} ms\nDecryption Time: {decryption_time:.6f} ms')

main()
