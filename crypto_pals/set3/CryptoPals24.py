# 14 bytes * 8 = 112 bits problem: you need 624 to recover state
#AAAAAAAAA characters
import sys
import random
import CryptoPals21
import CryptoPals23
# specifies
# upper_limit and lower_limit are bit indices
# Effects: takes a value and extracts parts corresponding to bit indices
# ***returns it as a value in the range upper_limit - lower_limit
def extract_component(value, upper_limit, lower_limit):
    decrement_val = value >> lower_limit
    mask = ((1 << (upper_limit - lower_limit)) - 1)
    return decrement_val & mask

def mersenne_stream_ciper(seed, pt_bytes):
    if int.bit_length(seed) > 16:
        raise ValueError("Seed must be less than or equal to 16 bits long")
    twister = CryptoPals21.MersenneTwister19937(seed)
    # this gives you 32 bit = 4 byte output
    ct_text = b""
    extracted = twister.extract_num()
    curr_idx = 3
    #byte_msk = (1 << 8) - 1
    for pt in pt_bytes:
        val_add = extract_component(extracted, 8 * (curr_idx + 1), 8 * curr_idx)
        ct_text += bytes([pt ^ val_add])
        if curr_idx == 0:
            extracted = twister.extract_num()
            curr_idx = 3
        else:
            curr_idx -= 1
    return ct_text

def crack_seed(ciphertext):
    known_states = []
    recover_32 = 0
    idx = 0
    byte_msk = (1 << 8) - 1
    for i in range(len(ciphertext) - 14, len(ciphertext)):
        print("{}".format(i))
        # add to 32 bit num result from generator
        recovered_block = ciphertext[i] ^ ord('A')
        recover_32 = recover_32 | (recovered_block << (8 * (3 - (i % 4))))
        if (i + 1) % 4 == 0:
            known_states.append(recover_32)
            recover_32 = 0
    # you may have been on an awkward byte boundary so you should probably look for
    # matches in the second block you've seen
    padd = 'A' * len(ciphertext)
    for poss_seed in range(1, 2**16 + 1):
        # check 4 bytes at least
        cseed = CryptoPals21.MersenneTwister19937(poss_seed)
        marker = (len(ciphertext) - 14) % 4
        quotient = (len(ciphertext) - 14) // 4
        known_st_marker = 0
        # quotient + 1 jumps into the current block
        for num in range(quotient + 1):
            output_stream = cseed.extract_num()
        if marker != 0:
            output_stream = cseed.extract_num()
            known_st_marker = 1
        is_correct = True
        while known_st_marker < len(known_states):
            if known_states[known_st_marker] != output_stream:
                is_correct = False
                break
            output_stream = cseed.extract_num()
            known_st_marker += 1
        if is_correct:
            return poss_seed
    return -1

def main():
    plaintext = ""
    numb_characters = random.randint(1, 30)
    for i in range(numb_characters):
        plaintext += chr(random.randint(0,255))
    plaintext += ('A' * 14)
    # up to 16 bit
    key = random.randint(0, 2**16 - 1)
    print("The key is {}".format(key))
    pt_bytes = bytes(plaintext, encoding='utf-8')
    print("Plaintext is: {}".format(pt_bytes))
    ciphertext = mersenne_stream_ciper(key, pt_bytes)
    print("Trying to crack cipher. First Try: Brute force binary search")
    crack_s = crack_seed(ciphertext)
    print("{}".format(crack_s))


if __name__ == "__main__":
    main()