# author: Asif Azad
# Date: 2020-12-26
# About: AES Encryption-128 and Decryption implementation 

from BitVector import *


Sbox = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)


InvSbox = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)


Mixer = [
    [BitVector(hexstring="02"), BitVector(hexstring="03"), BitVector(hexstring="01"), BitVector(hexstring="01")],
    [BitVector(hexstring="01"), BitVector(hexstring="02"), BitVector(hexstring="03"), BitVector(hexstring="01")],
    [BitVector(hexstring="01"), BitVector(hexstring="01"), BitVector(hexstring="02"), BitVector(hexstring="03")],
    [BitVector(hexstring="03"), BitVector(hexstring="01"), BitVector(hexstring="01"), BitVector(hexstring="02")]
]


InvMixer = [
    [BitVector(hexstring="0E"), BitVector(hexstring="0B"), BitVector(hexstring="0D"), BitVector(hexstring="09")],
    [BitVector(hexstring="09"), BitVector(hexstring="0E"), BitVector(hexstring="0B"), BitVector(hexstring="0D")],
    [BitVector(hexstring="0D"), BitVector(hexstring="09"), BitVector(hexstring="0E"), BitVector(hexstring="0B")],
    [BitVector(hexstring="0B"), BitVector(hexstring="0D"), BitVector(hexstring="09"), BitVector(hexstring="0E")]
]


ROUND_CONSTANTS = [
    BitVector(intVal=0, size=8),
    BitVector(intVal=1, size=8),
    BitVector(intVal=2, size=8),
    BitVector(intVal=4, size=8),
    BitVector(intVal=8, size=8),
    BitVector(intVal=16, size=8),
    BitVector(intVal=32, size=8),
    BitVector(intVal=64, size=8),
    BitVector(intVal=128, size=8),
    BitVector(intVal=27, size=8),
    BitVector(intVal=54, size=8)
]


def print_word(_label: str, _word: list[BitVector]):
    print(_label)
    for i in range(len(_word)):
        print(_word[i].get_bitvector_in_hex(), end=" ")
    print()


def print_matrix(_label: str, _matrix: list[list[BitVector]]):
    print(_label)
    for i in range(len(_matrix)):
        for j in range(len(_matrix[i])):
            print(_matrix[i][j].get_bitvector_in_hex(), end=" ")
        print()
    

def g(_word: list[BitVector], _round: int) -> list[BitVector]:
    #circular byte left shift
    _word = _word[1:] + [_word[0]]
    #byte substitution
    _word = [BitVector(intVal=Sbox[_word[i].intValue()], size=8) for i in range(len(_word))]
    #adding round constant
    _word[0] ^= ROUND_CONSTANTS[_round]
    return _word


def generate_round_key(_initial_key: list[list[BitVector]], _round: int) -> list[list[BitVector]]:
    # from column major order to row major order
    current_key = [[_initial_key[i][j] for i in range(len(_initial_key))] for j in range(len(_initial_key[0]))]
    for i in range(_round):
        addend = g(current_key[3], i+1)
        for j in range(len(current_key)):
            current_key[j] = [current_key[j][k] ^ addend[k] for k in range(len(current_key[j]))]
            addend = current_key[j]
    # from row major order to column major order
    updated_current_key = [[current_key[i][j] for i in range(len(current_key))] for j in range(len(current_key[0]))]
    return updated_current_key


def add_round_key(_state_matrix: list[list[BitVector]], _round_key: list[list[BitVector]])-> list[list[BitVector]]:
    assert len(_state_matrix) == len(_round_key) and len(_state_matrix[0]) > 0 and len(_state_matrix[0]) == len(_round_key[0])
    for i in range(len(_state_matrix)):
        for j in range(len(_state_matrix[i])):
            _state_matrix[i][j] ^= _round_key[i][j]
    return _state_matrix


def sub_bytes(_state_matrix: list[list[BitVector]]) -> list[list[BitVector]]:
    for i in range(len(_state_matrix)):
        for j in range(len(_state_matrix[i])):
            _state_matrix[i][j] = BitVector(intVal=Sbox[_state_matrix[i][j].intValue()], size=8)
    return _state_matrix


def inv_sub_bytes(_state_matrix: list[list[BitVector]]) -> list[list[BitVector]]:
    for i in range(len(_state_matrix)):
        for j in range(len(_state_matrix[i])):
            _state_matrix[i][j] = BitVector(intVal=InvSbox[_state_matrix[i][j].intValue()], size=8)
    return _state_matrix


def shift_rows(_state_matrix: list[list[BitVector]])-> list[list[BitVector]]:
    for i in range(len(_state_matrix)):
        _state_matrix[i] = _state_matrix[i][i:] + _state_matrix[i][:i]
    return _state_matrix


def inv_shift_rows(_state_matrix: list[list[BitVector]])-> list[list[BitVector]]:
    for i in range(len(_state_matrix)):
        _state_matrix[i] = _state_matrix[i][-i:] + _state_matrix[i][:-i]
    return _state_matrix


def mix_columns(_state_matrix: list[list[BitVector]]) -> list[list[BitVector]]:
    aes_modulus = BitVector(bitstring='100011011')
    updated_state_matrix = [[BitVector(intVal=0, size=8) for i in range(len(_state_matrix[0]))] for j in range(len(_state_matrix))]
    for i in range(len(_state_matrix)):
        for j in range(len(_state_matrix[i])):
            for k in range(len(_state_matrix[i])):
                # gf mdular multiplication
                updated_state_matrix[i][j] ^= Mixer[i][k].gf_multiply_modular(_state_matrix[k][j], aes_modulus, 8)
    return updated_state_matrix


def inv_mix_columns(_state_matrix: list[list[BitVector]]) -> list[list[BitVector]]:
    aes_modulus = BitVector(bitstring='100011011')
    updated_state_matrix = [[BitVector(intVal=0, size=8) for i in range(len(_state_matrix[0]))] for j in range(len(_state_matrix))]
    for i in range(len(_state_matrix)):
        for j in range(len(_state_matrix[i])):
            for k in range(len(_state_matrix[i])):
                # gf mdular multiplication
                updated_state_matrix[i][j] ^= InvMixer[i][k].gf_multiply_modular(_state_matrix[k][j], aes_modulus, 8)
    return updated_state_matrix


def block_plain_text(_plain_text: str) -> list[list[list[BitVector]]]:
    if len(_plain_text) % 16 != 0:
        _plain_text += " " * (16 - len(_plain_text) % 16)
    blocks: list[list[list[BitVector]]] = [] 
    for i in range(len(_plain_text) // 16):
        current_text = _plain_text[i*16:(i+1)*16]
        # column major order
        blocks.append([[BitVector(intVal=ord(current_text[k*4+j]), size=8) for k in range(4)] for j in range(4)])
    return blocks


def merge_blocks(_blocks: list[list[list[BitVector]]]) -> str:
    text: str = ""
    # column major order
    for block in _blocks:
        for j in range(len(block[0])):
            for i in range(len(block)):
                text += chr(block[i][j].intValue())
    text = text.rstrip()
    return text


def aes_block_encrypt(_state_matrix: list[list[BitVector]], _initial_key: list[list[BitVector]]) -> list[list[BitVector]]:
    _state_matrix = add_round_key(_state_matrix, _initial_key)
    for n_round in range(1, 10):
        _state_matrix = sub_bytes(_state_matrix)
        _state_matrix = shift_rows(_state_matrix)
        _state_matrix = mix_columns(_state_matrix)
        _state_matrix = add_round_key(_state_matrix, generate_round_key(_initial_key, n_round))
    _state_matrix = sub_bytes(_state_matrix)
    _state_matrix = shift_rows(_state_matrix)
    _state_matrix = add_round_key(_state_matrix, generate_round_key(_initial_key, 10))
    return _state_matrix


def aes_block_decrypt(_state_matrix: list[list[BitVector]], _initial_key: list[list[BitVector]]) -> list[list[BitVector]]:
    _state_matrix = add_round_key(_state_matrix, generate_round_key(_initial_key, 10))
    for n_round in range(9, 0, -1):
        _state_matrix = inv_shift_rows(_state_matrix)
        _state_matrix = inv_sub_bytes(_state_matrix)
        _state_matrix = add_round_key(_state_matrix, generate_round_key(_initial_key, n_round))
        _state_matrix = inv_mix_columns(_state_matrix)
    _state_matrix = inv_shift_rows(_state_matrix)
    _state_matrix = inv_sub_bytes(_state_matrix)
    _state_matrix = add_round_key(_state_matrix, _initial_key)
    return _state_matrix


def aes_encrypt(_key_text: str, _plain_text: str) -> str:
    assert len(_key_text) == 16
    state_matrices = block_plain_text(_plain_text)
    # column major order
    initial_key = [[BitVector(intVal=ord(_key_text[i*4+j]), size=8) for i in range(4)] for j in range(4)]
    cipher_matrices: list[list[list[BitVector]]] = []
    for state_matrix in state_matrices:
        cipher_matrices.append(aes_block_encrypt(state_matrix, initial_key))
    cipher_text = merge_blocks(cipher_matrices) 
    cipher_bv = BitVector(textstring=cipher_text)
    cipher_hex = cipher_bv.get_bitvector_in_hex()
    return [cipher_text, cipher_hex]


def aes_decrypt(_key_text: str, _cipher_text: str) -> str:
    assert len(_key_text) == 16
    state_matrices = block_plain_text(_cipher_text)
    # column major order
    initial_key = [[BitVector(intVal=ord(_key_text[i*4+j]), size=8) for i in range(4)] for j in range(4)]
    plain_matrices: list[list[list[BitVector]]] = []
    for state_matrix in state_matrices:
        plain_matrices.append(aes_block_decrypt(state_matrix, initial_key))
    plain_text = merge_blocks(plain_matrices) 
    plain_bv = BitVector(textstring=plain_text)
    plain_hex = plain_bv.get_bitvector_in_hex()
    return [plain_text, plain_hex]




