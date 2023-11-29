import socket
import threading
from AESCipher import aes_encrypt, aes_decrypt
from ECDHCipher import ECDHCipher, Point


def ecdh_key_exchange(_socket: socket) -> int:
    # receive nist_standard_curve object from Alice
    nist_standard_curve = _socket.recv(1024).decode()
    ecdh = ECDHCipher(_curve = eval(nist_standard_curve))
    # generate Bob's private key
    bob_private_key = ecdh.generate_private_key()
    # generate Bob's public key
    bob_public_key = ecdh.multiply_point(bob_private_key)
    # send Bob's public key to Alice
    _socket.send(str(bob_public_key).encode())
    # receive Alice's public key
    alice_public_key = _socket.recv(1024).decode()
    alice_public_key = Point(int(alice_public_key.split(',')[0][1:]), int(alice_public_key.split(',')[1][:-1]))
    shared_key = ecdh.multiply_point(bob_private_key, alice_public_key)
    return shared_key.x
    

def send_message(_socket: socket, _shared_key_hex: str, _msg: str) -> None:
    [_msg, _ ] = aes_encrypt(_shared_key_hex, _msg)
    _socket.send(_msg.encode())


def receive_message(_socket: socket, _shared_key_hex) -> None:
    while True:
        msg = _socket.recv(1024).decode()
        [msg, _ ] = aes_decrypt(_shared_key_hex, msg)
        print(f"Received: {msg}")
        if msg == "q":
            break


def init_server_socket(_host: str, _port: int) -> socket:
    _socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    _socket.bind((_host, _port))
    _socket.listen()
    return _socket


def chat(_socket: socket, _shared_key_hex: str) -> None:
    print("Alice connected")
    # create a thread to receive messages
    receive_thread = threading.Thread(target=receive_message, args=(_socket, _shared_key_hex))
    receive_thread.start()
    # send messages
    while True:
        msg = input()
        aes_encrypt(_shared_key_hex, msg)
        send_message(_socket, _shared_key_hex, msg)
        if msg == "q":
            receive_thread.join()
            break
    _socket.close()


if __name__ == "__main__":
    host = ""
    port = 12349
    server_socket = init_server_socket(host, port)
    alice_socket, alice_addr = server_socket.accept()
    shared_key = ecdh_key_exchange(alice_socket)
    shared_key = hex(shared_key)[2:]
    chat(alice_socket, shared_key)