import socket 
import threading
from AESCipher import aes_encrypt, aes_decrypt
from ECDHCipher import NIST_STANDARD_CURVES, ECDHCipher, Point


def ecdh_key_exchange(_socket: socket, _security_level) -> int:
    nist_standard_curve = NIST_STANDARD_CURVES[_security_level]
    ecdh = ECDHCipher(_security_level)
    # send nist_staqndard_curve object to Bob
    _socket.send(str(nist_standard_curve).encode())
    # receive Bob's public key
    bob_public_key = _socket.recv(1024).decode()
    #convert Bob's public key to Point object
    bob_public_key = Point(int(bob_public_key.split(',')[0][1:]), int(bob_public_key.split(',')[1][:-1]))
    # generate Alice's private key
    alice_private_key = ecdh.generate_private_key()
    # generate Alice's public key
    alice_public_key = ecdh.multiply_point(alice_private_key)
    # send Alice's public key to Bob
    _socket.send(str(alice_public_key).encode())
    shared_key = ecdh.multiply_point(alice_private_key, bob_public_key)
    return shared_key.x


def send_message(_socket: socket, _shared_key_hex: str, _msg: str) -> None:
    [_msg, _ ] = aes_encrypt(_shared_key_hex, _msg)
    _socket.send(_msg.encode())


def receive_message(_socket: socket, _shared_key_hex: str) -> None:
    while True:
        msg = _socket.recv(1024).decode()
        [msg, _ ] = aes_decrypt(_shared_key_hex, msg)
        print(f"Received: {msg}")
        if msg == "q":
            break


def init_client_socket(_host: str, _port: int) -> socket:
    _socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    _socket.connect((_host, _port))
    return _socket


def chat(_socket: socket, _shared_key_hex: str) -> None:
    print("Bob connected")
    # create a thread to receive messages
    receive_thread = threading.Thread(target=receive_message, args=(_socket, _shared_key_hex))
    receive_thread.start()
    # send messages
    while True:
        msg = input()
        send_message(_socket, _shared_key_hex, msg)
        if msg == "q":
            receive_thread.join()
            break
    _socket.close()


if __name__ == "__main__":
    host = "localhost"
    port = 12349
    security_level = 0
    bob_socket = init_client_socket(host, port)
    shared_key = ecdh_key_exchange(bob_socket, security_level)
    shared_key = hex(shared_key)[2:]
    chat(bob_socket, shared_key)
