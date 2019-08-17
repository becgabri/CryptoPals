import sys
import base64
from crypto_pals.set1 import CryptoPals7
from crypto_pals.set2.CryptoPals11 import generate_rand_AES_key, generate_rand_IV
# LESSON: Not only is AES 128 in CBC mode w/ no auth possible to decrypt BUT it is also
# malleable
AES_KEY = generate_rand_AES_key()
IV = generate_rand_IV()
BLOCK_SIZE = 16

def enc_user_data(plaintext):
    prepend_str = "comment1=cooking%20MCs;userdata="
    append_str = ";comment2=%20like%20a%20pound%20of%20bacon"
    disqualified = [';', '=']
    for val in disqualified:
        plaintext = plaintext.replace(val, "\"" + val + "\"")
    text_to_enc = prepend_str + plaintext + append_str
    res = CryptoPals7.ENCRYPTION_CBC_MODE(IV, AES_KEY, text_to_enc, CryptoPals7.encrypt_aes)
    return res

def is_admin(enc_text):
    decrypted = CryptoPals7.DECRYPTION_CBC_MODE(IV, AES_KEY, enc_text, CryptoPals7.decrypt_aes)
    args = decrypted.split(';')
    for pair in args:
        if pair == 'admin=true':
            return True
    return False

def main():
    print("Beginning attack... ")
    normal_block = enc_user_data('a' * BLOCK_SIZE)
    encrypted_string = CryptoPals7.modify_list_into_GF28(normal_block[1 * BLOCK_SIZE: 2 * BLOCK_SIZE])
    a_string = CryptoPals7.modify_list_into_GF28('a' * 16)
    pt_string = CryptoPals7.modify_list_into_GF28(';admin=true;' + 'a' * 4)
    modified_block = []
    for idx in range(BLOCK_SIZE):
        modified_block.append(encrypted_string[idx] + a_string[idx] + pt_string[idx])
    modified_text = CryptoPals7.GF28_to_string(modified_block)
    admin_text = normal_block[:BLOCK_SIZE] + modified_text + normal_block[2*BLOCK_SIZE:]
    print("Result of ciphertext on oracle is: {}".format(is_admin(admin_text)))
    return



if __name__ == "__main__":
    main()
