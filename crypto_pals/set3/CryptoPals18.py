import sys
import os
import struct
import math
import base64
sys.path.append('/mnt/c/Users/becga/Documents/crypto_pals')
from crypto_pals.set1 import CryptoPals7
from crypto_pals.set1 import GF28
from crypto_pals.set2.CryptoPals11 import generate_rand_IV
BLOCK_SIZE = 16
test_str = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
test_str = base64.b64decode(test_str)
def counter_function(ctr, nonce):
    bytes_str = struct.pack("<Q", ctr)
    key_stream_enc = nonce + CryptoPals7.modify_list_into_GF28(bytes_str)
    return key_stream_enc

def CTR_ENCRYPTION_MODE(encryption_alg, plaintext, key, ctr_func, nonce):
    nonce_curr = CryptoPals7.modify_list_into_GF28(nonce)
    number_blocks = math.ceil(len(plaintext) / BLOCK_SIZE)
    key_GF28 = CryptoPals7.modify_list_into_GF28(key)
    ctr = 0
    gf28_key_stream = []
    for idx in range(number_blocks):
        gf28_key_stream += encryption_alg(key_GF28, ctr_func(idx, nonce_curr))
    pt_GF28 = CryptoPals7.modify_list_into_GF28(plaintext)
    res = []
    for i in range(len(pt_GF28)):
        res.append(pt_GF28[i] + gf28_key_stream[i])
    return CryptoPals7.GF28_to_string(res)

def CTR_DECRYPTION_MODE(encryption_alg, ciphertext, key, ctr_func, nonce):
    return CTR_ENCRYPTION_MODE(encryption_alg, ciphertext, key, ctr_func, nonce)

def main():
    zero_nonce = bytearray([0] * (BLOCK_SIZE // 2))
    pt = CTR_DECRYPTION_MODE(CryptoPals7.encrypt_aes, test_str, "YELLOW SUBMARINE", counter_function, zero_nonce)
    print(pt)
    return

if __name__ == "__main__":
    main()