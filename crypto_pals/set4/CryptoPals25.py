import sys
import os
sys.path.append('/mnt/c/Users/becga/Documents/crypto_pals')
import base64
from crypto_pals.set3 import CryptoPals18
from crypto_pals.set2 import CryptoPals11
from crypto_pals.set1 import GF28, CryptoPals7
import random
BLOCK_SIZE = 16
def gen_random_nonce():
    nonce = bytearray([0] * (BLOCK_SIZE // 2))
    for idx in range(CryptoPals18.BLOCK_SIZE // 2):
        nonce[idx] = random.randint(0, 255)
    return nonce

def key_file_read(key_file):
    with open(key_file, "rb") as key_file:
        key_material = key_file.readlines()
    if len(key_material) < 2:
        print("ERROR: KEY FILE IS NOT OF THE PROPER FORM")
        return False
    key = key_material[0].strip()
    nonce = key_material[1].strip()
    return (key, nonce)

def seek_and_reencrypt_api(ct, key_f, offset, replace_text):
    # read in the key, format is
    # KEY \n
    # NONCE \n
    key, nonce = key_file_read(key_f)
    key_in_gf28 = CryptoPals7.modify_list_into_GF28(key)
    nonce_in_gf28 = CryptoPals7.modify_list_into_GF28(nonce)

    if (len(ct) - offset) < len(replace_text):
        return False

    key_stream_input = []
    start_block = offset // 16
    end_block = (offset + len(replace_text)) // 16
    for idx in range(start_block, end_block + 1):
        temp_val = CryptoPals18.counter_function(idx, nonce_in_gf28)
        padd_to_add = CryptoPals7.encrypt_aes(key_in_gf28, temp_val)
        key_stream_input.extend(padd_to_add)

    start_idx = offset % 16
    end_idx = ((offset + len(replace_text)) % 16) + ((end_block - start_block) * 16)

    key_stream_input = key_stream_input[start_idx:end_idx]
    pt_in_GF28  = CryptoPals7.modify_list_into_GF28(replace_text)
    input = []
    for idx, _ in enumerate(key_stream_input):
        input.append(key_stream_input[idx] + pt_in_GF28[idx])

    result = ct[:start_idx] + CryptoPals7.GF28_to_string(input)
    if (end_idx + 1) < len(ct):
        result = result + ct[end_idx:]

    return result

# encrypts a file and writes the file, stores the key in key_file
def enc_file(pt, key_file, new_file):
    aes_key = CryptoPals11.generate_rand_AES_key()
    nonce = gen_random_nonce()
    ct_file = CryptoPals18.CTR_ENCRYPTION_MODE(CryptoPals7.encrypt_aes, pt, aes_key, CryptoPals18.counter_function, nonce)
    with open(new_file, "w") as write_f:
        write_f.write(ct_file)
    with open(key_file, "wb") as write_key:
        write_key.write(aes_key + b"\n" + nonce + b"\n")
    return

def dec_file(ct_file, key_file):
    key, nonce = key_file_read(key_file)
    """
    read_ct = ""
    with open(ct_file, "r") as ct_r:
        read_ct = ct_r.read()
    """
    plain_file = CryptoPals18.CTR_DECRYPTION_MODE(CryptoPals7.encrypt_aes, ct_file, key, CryptoPals18.counter_function, nonce)
    print(plain_file)
    return

def main():
    with open("25.txt", "r") as read_b64:
        res = read_b64.read()
    res = base64.b64decode(res)
    res = CryptoPals7.decryption_mode_ECB("YELLOW SUBMARINE", res, CryptoPals7.decrypt_aes)
    enc_file(res, "key_25.txt", "ct_25.txt")
    txt = ""
    with open("ct_25.txt", "r") as curr_r:
        txt = curr_r.read()
    print(txt)
    zeroed_pt = bytearray([57] * len(txt))
    new_res = seek_and_reencrypt_api(txt, "key_25.txt", 0, zeroed_pt)
    #dec_file(new_res, "key_25.txt")
    recovered_txt = ""

    for idx,_ in enumerate(new_res):
        recovered_txt += chr((ord(txt[idx]) ^ ord(new_res[idx]) ^ 57) % 256)
    print(recovered_txt)

    return

if __name__ == "__main__":
    main()
