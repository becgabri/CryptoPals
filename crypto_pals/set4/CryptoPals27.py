import os
import sys
sys.path.append('/mnt/c/Users/becga/Documents/crypto_pals')
from crypto_pals.set2.CryptoPals11 import generate_rand_AES_key
from crypto_pals.set1 import CryptoPals7
import string

STATIC_AES_KEY = generate_rand_AES_key()
STATIC_IV = STATIC_AES_KEY

def enc_url_params(params):
    for character in params:
        if not character in string.ascii_letters:
            raise ValueError("Error -- can only encode ascii characters not " + params)
    return CryptoPals7.ENCRYPTION_CBC_MODE(STATIC_IV, STATIC_AES_KEY,params,CryptoPals7.encrypt_aes)

def dec_verify(ctext):
    plaintxt= ""
    try:
        plaintxt = CryptoPals7.DECRYPTION_CBC_MODE(STATIC_IV, STATIC_AES_KEY,ctext,CryptoPals7.encrypt_aes)
    except ValueError:
        info = str(sys.exc_info()[1])
        info = info.replace("Padding Error:", "")
        print("An error occurred, attempted decrypted plaintext was {}".format(info))
        plaintxt = info
    for character in plaintxt:
        if not character in string.ascii_letters:
            print("Character is non-ascii, the text is {}".format(plaintxt))
            return plaintxt
    return "Successfully Decrypted"

def main():
    blocks = "a" *  (16 * 3)
    ct = enc_url_params(blocks)
    modified = [ct[x] for x in range(64)]
    for i in range(16, 32):
        #del modified[-16:]
        modified[i] = chr(0)
    for i in range(32, 48):
        modified[i] = modified[i-32]
    result = dec_verify("".join(modified))
    result = [x for x in result]
    if len(result) < 48:
        print("ERROR -- length of PT is not right")

    # grab the key
    key = [chr(0)] * 16
    for i in range(16):
        num_k = (ord(result[i]) ^ ord(result[i+32])) % 256
        if num_k < 0:
            num_k *= -1
        key[i] = chr(num_k)
    check_key = bytearray(0)
    for number in key:
        check_key.append(ord(number))
    print("Recovered key was: {}".format(check_key))
    print("AES KEY is {}".format(STATIC_AES_KEY))
    return

if __name__ == "__main__":
    main()