import sys
import base64
sys.path.append('/mnt/c/Users/becga/Documents/crypto_pals')
from crypto_pals.set1 import CryptoPals7
from crypto_pals.set2.CryptoPals11 import generate_rand_AES_key
# LESSON: ECB is incredibly unsafe if you have access even to just
# the cipher text and some knowledge of the plaintext
# ECB allows you to get back encrypted blocks that can be freely moved
# to get other valid ciphertext. This is VERY bad
GLOBAL_AES_KEY = generate_rand_AES_key()

def parse_url_string(url_str):
    if type(url_str) is not str:
        raise TypeError("URL string is not a string")
    url_dict = {}
    # split
    pairs = url_str.split('&')
    for pair in pairs:
        split_key = pair.split('=')
        if len(split_key) != 2:
            raise ValueError("Incorrect format")
        url_dict[split_key[0]] = split_key[1]
    return url_dict

def strip_offending_chars(string_unsafe):
    string_unsafe.replace('&','')
    string_unsafe.replace('=','')

def profile_for(user):
    return_str = []
    user.replace('&', '')
    user.replace('=', '')
    return_str.append('email=' + user)
    return_str.append('uid=10')
    return_str.append('role=user')

    return "&".join(return_str)

def encrypt_profile(profile):
    import pdb; pdb.set_trace()
    return CryptoPals7.encryption_mode_ECB(GLOBAL_AES_KEY, profile, CryptoPals7.encrypt_aes)

def decrypt_and_parse_encrypted_prof(profile):
    decrypted_text = CryptoPals7.decryption_mode_ECB(GLOBAL_AES_KEY, profile, CryptoPals7.decrypt_aes)
    results = parse_url_string(decrypted_text)
    print(results)

def main():
    # step 1 : get role= to be at end of block
    cipher_text = encrypt_profile(profile_for("UrBaseRUs@a.z"))
    admin = "a" * 10 + "admin" + str(bytearray([11] * 11), encoding='utf-8')

    enc_admin = encrypt_profile(profile_for(admin))[16:16*2]
    crafted_text = cipher_text[:-16] + enc_admin
    decrypt_and_parse_encrypted_prof(crafted_text)
    return

if __name__ == "__main__":
    main()