import os
import sys
from crypto_pals.set1 import CryptoPals7
from crypto_pals.set3 import CryptoPals18
from crypto_pals.set2.CryptoPals11 import generate_rand_AES_key, generate_rand_IV
# Lesson: Crypto is NOT magic sauce. Just because CTR is a "strong", "good"
# mode does not give you license to stop thinking about what it is actually
# doing under the hood.

STATIC_AES_KEY = generate_rand_AES_key()
STATIC_IV = generate_rand_IV()
BLOCK_SIZE = 16

def enc_user_data(plaintext):
    prepend_str = "comment1=cooking%20MCs;userdata="
    append_str = ";comment2=%20like%20a%20pound%20of%20bacon"
    disqualified = [';', '=']
    for character in disqualified:
        plaintext = plaintext.replace(character, "\"" + character + "\"")
    text_to_enc = prepend_str + plaintext + append_str
    res = CryptoPals18.CTR_ENCRYPTION_MODE(CryptoPals7.encrypt_aes, text_to_enc,
        STATIC_AES_KEY, CryptoPals18.counter_function, STATIC_IV)
    return res

def is_admin(enc_text):
    plaintext = CryptoPals18.CTR_DECRYPTION_MODE(CryptoPals7.encrypt_aes, enc_text,
        STATIC_AES_KEY, CryptoPals18.counter_function, STATIC_IV)
    args = plaintext.split(';')
    for arg in args:
        if arg == 'admin=true':
            return True
    return False

def main():
    padd_str = 'a' * 12
    res = enc_user_data(padd_str)
    starting_txt = len("comment1=cooking%20MCs;userdata=")
    insert_str = ";admin=true;"
    mod_res = bytearray(res, encoding='utf-8')
    for i in range(len(insert_str)):
        xor_out = ord(padd_str[i]) ^ ord(insert_str[i])
        mod_res[starting_txt + i] = ord(res[starting_txt + i]) ^ xor_out
    print(is_admin(mod_res))
    return


if __name__ == "__main__":
    main()

