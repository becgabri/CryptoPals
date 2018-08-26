import sys
sys.path.append('/mnt/c/Users/becga/Documents/crypto_pals')
from crypto_pals.set1 import CryptoPals7
import random

def generate_rand_AES_key():
    aes_key = bytearray(16)
    for idx in range(16):
        aes_key[idx] = random.randrange(256)
    return aes_key

def generate_rand_IV():
    IV = []
    for __ in range(16):
        IV.append(str(random.randrange(256)))
    return "-".join(IV)

def encryption_oracle(input):
    padd_front = random.randrange(5,10)
    padd_front_text = ""
    feed_input = ""
    for i in range(padd_front):
        padd_front_text += chr(random.randrange(256))
    feed_input = padd_front_text + input

    padd_back = random.randrange(5,10)
    for i in range(padd_back):
        feed_input += chr(random.randrange(256))

    ### If the IV is not generated no matter what
    # this would introduce a side channel

    IV = generate_rand_IV()
    key = generate_rand_AES_key()

    # randomly choose ECB or CBC now
    decision = random.randrange(2)
    if (decision == 0):
        # ECB
        print("Used: ECB mode")
        res = CryptoPals7.encryption_mode_ECB(key, feed_input,
            CryptoPals7.encrypt_aes)
        return res
    else:
        # CBC
        print("Used: CBC mode")
        res = CryptoPals7.ENCRYPTION_CBC_MODE(IV, key, feed_input,
            CryptoPals7.encrypt_aes)
        return res

def detection_oracle(blackbox):
    # 5-10 bytes before
    guess_str = "a" * (11 + (16 * 2))
    encrypted_text = blackbox(guess_str)
    same_strs = {}
    for i in range(0, len(guess_str), 16):
        if not encrypted_text[i:i+16] in same_strs:
            same_strs[encrypted_text[i:i+16]] = 0
        same_strs[encrypted_text[i:i+16]] += 1
    if max(same_strs.values()) > 1:
        print("From Detection Oracle: ECB mode")
        return "ECB"
    else:
        print("From Detection Oracle: CBC mode")
        return "CBC"


if __name__ == "__main__":
    use_detection_oracle = input("Would you like to use the detection_oracle?")
    if use_detection_oracle.startswith("y") or use_detection_oracle.startswith("Y"):
        detection_oracle(encryption_oracle)
    else:
        input_str = input("Please give some input to encrypt: ")
        result = encryption_oracle(input_str)
        print("The encryption oracle says:\n {}".format(result))