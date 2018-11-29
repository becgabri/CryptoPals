import sys
import base64
import random
from crypto_pals.set1 import CryptoPals7
from crypto_pals.set2.CryptoPals11 import generate_rand_AES_key, detection_oracle
from crypto_pals.set2.CryptoPals12 import find_oracle_copy_block_size

AES_RAND_KEY = generate_rand_AES_key()
append_this = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
append_this = base64.b64decode(append_this)
# arbitrary imposed limit because I don't want to
# deal with time issues
prepend_array = bytearray()
prepend_length = random.randrange(50)
for __ in range(prepend_length):
    prepend_array.append(random.randrange(256))

def modified_oracle_copy(plaintext_array):
    test_arr = []
    mod_pt_arr = plaintext_array
    if type(plaintext_array) is list:
        mod_pt_arr = bytearray(plaintext_array)
    try:
        test_arr = prepend_array + mod_pt_arr + append_this
    except TypeError:
        import pdb; pdb.set_trace()
    res = CryptoPals7.encryption_mode_ECB(AES_RAND_KEY, test_arr, CryptoPals7.encrypt_aes)
    return res

def main():
    # from CryptoPals12
    # -------------------------------------------------
    # figure out how much padding there is
    # ensure its ECB
    block_size = find_oracle_copy_block_size(modified_oracle_copy)
    #TODO modify the detection oracle function
    #mode_str = detection_oracle(modified_oracle_copy)
    #if mode_str == "CBC":
    #    print("Is not ECB, try again")
    #    return
    # ----------------------------------------------------

    number_blocks = 0
    no_extend = modified_oracle_copy(bytearray())
    one_extend = modified_oracle_copy(bytearray([ord('a')]))
    # jump by 16's, checking size
    while no_extend[number_blocks * block_size: (number_blocks + 1) * block_size] == \
        one_extend[number_blocks * block_size: (number_blocks + 1) * block_size]:
        number_blocks += 1

    padd_out = 0
    while one_extend[block_size * number_blocks: block_size * (number_blocks + 1)] != no_extend[block_size * number_blocks: block_size * (number_blocks + 1)]:
        padd_out += 1
        no_extend = one_extend
        one_extend = modified_oracle_copy(bytearray([ord('a')] * (padd_out + 1)))

    # takes advantage that until you "pad out" all the way the last block will
    # change values
    # from [random beg] [ padding ] [unknown str] | [ more unknown str ]
    # to [random beg] [padding] | [unknown str]

    # this is why we need to delete one
    # modified from CryptoPals12
    # ---------------------------------------------------
    unknown_str_len = len(append_this)
    plaintext = ""
    while len(plaintext) < unknown_str_len:
        # recover each p.t. byte
        known_len = len(plaintext)
        # [ padding A ] [ text you know ] | [ text you don't ]
        # want unknown byte at front to always be in pos. rem 7
        quot_rem = divmod(known_len, block_size)
        # padd until you hit a remainder that is that high
        padd_out_begin = bytearray([ord('A')] * padd_out)
        padding = padd_out_begin + bytearray([ord('A')] * (block_size - 1 - quot_rem[1]))
        val_to_match = modified_oracle_copy(padding)
        adj_amt = 0
        if padd_out != 0:
            adj_amt += 1
        val_to_match = val_to_match[block_size * (number_blocks + quot_rem[0] + adj_amt):block_size * (quot_rem[0] + 1 + number_blocks + adj_amt)]
        if len(plaintext) > 0:
            padding.extend(bytearray(plaintext,encoding='utf-8'))
        for i in range(256):
            padding.append(i)
            if len(padding) < 16:
                print("something is wrong here.....")
            current_restext = modified_oracle_copy(padd_out_begin + padding[-16:])
            if val_to_match == current_restext[(number_blocks + 1) * block_size:(number_blocks + 2) * block_size]:
                plaintext += str(bytearray([i]), encoding='utf-8')
                break
            padding.pop()
    print(plaintext)
    return

if __name__ == "__main__":
    main()