import sys
import base64
from crypto_pals.set1 import CryptoPals7
from crypto_pals.set2.CryptoPals11 import encryption_oracle, generate_rand_AES_key, detection_oracle

AES_RAND_KEY = generate_rand_AES_key()
append_this = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
append_this = base64.b64decode(append_this)

def close_oracle_copy(plaintext):
    if type(plaintext) is str:
        plaintext = plaintext + str(append_this, encoding='utf-8')
        res = CryptoPals7.encryption_mode_ECB(AES_RAND_KEY, plaintext, CryptoPals7.encrypt_aes)
        plaintext = plaintext[:len(plaintext) - len(append_this)]
    else:
        plaintext.extend(append_this)
        res = CryptoPals7.encryption_mode_ECB(AES_RAND_KEY, bytes(plaintext), CryptoPals7.encrypt_aes)
        del plaintext[-1 * len(append_this):]
    return res

# cipher is a function with parameters (key, text)
def find_block_size(mode, cipher, key):
    result = mode(key,'a', cipher)
    return len(result)

def find_oracle_copy_block_size(oracle):
    curr_size = 0
    while len(oracle([ord('a')] * (curr_size + 1))) - \
        len(oracle([ord('a')] * curr_size)) <= 1 and curr_size < 25:
        curr_size = curr_size + 1

    # now get difference, this is the block size
    # [it won't work if it's a stream cipher]
    return len(oracle([ord('a')] * (curr_size + 1))) - \
        len(oracle([ord('a')] * curr_size))

def main():
    # figure out how much padding there is
    # ensure its ECB
    block_size = find_oracle_copy_block_size(close_oracle_copy)
    print("Guessed size of blocks {}".format(block_size))
    mode_str = detection_oracle(close_oracle_copy)
    if mode_str == "CBC":
        print("Is not ECB, try again")
        return
    # next, do the actual breaking
    unknown_str_len = len(append_this)
    plaintext = ""
    while len(plaintext) < unknown_str_len:
        # recover each p.t. byte
        known_len = len(plaintext)
        # [ padding A ] [ text you know ] | [ text you don't ]
        # want unknown byte at front to always be in pos. rem 7
        quot_rem = divmod(known_len, block_size)
        # padd until you hit a remainder that is that high
        padding = bytearray([ord('A')] * (block_size - 1 - quot_rem[1]))
        assert type(padding) is bytearray
        val_to_match = close_oracle_copy(padding)[block_size * quot_rem[0]:block_size * (quot_rem[0] + 1)]
        if len(plaintext) > 0:
            padding.extend(bytearray(plaintext,encoding='utf-8'))
        for i in range(256):
            padding.append(i)
            if len(padding) < 16:
                print("something is wrong here.....")
            current_restext = close_oracle_copy(padding[-16:])
            if val_to_match == current_restext[:16]:
                plaintext += str(bytearray([i]), encoding='utf-8')
                break
            padding.pop()
    print(plaintext)
    return


if __name__ == "__main__":
    main()
