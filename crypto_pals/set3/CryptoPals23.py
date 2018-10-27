import sys
import random
sys.path.append("/mnt/c/Users/becga/Documents/crypto_pals")

from crypto_pals.set3 import CryptoPals21
mask_largest_val = (1 << 64) - 1
## these are the original mersenne constants
constants_mersenne = {
    'u': 11,
    'd': 0xFFFFFFFF,
    's': 7,
    'b': 0x9D2C5680,
    't': 15,
    'c': 0xEFC60000,
    'l': 18,
}
#####################
def reverse_left_shift(norm, const, mask=mask_largest_val):
    curr_block_len = int.bit_length(norm)
    xor_block = norm & (2**const - 1)
    for i in range(0, curr_block_len, const):
        xor_block = norm & (((1 << const) - 1) << i)
        #mask_in_block = mask & (((2**const) - 1) << i)
        norm = norm ^ ((xor_block << const) & mask)
        #xor_block = (norm & (2**(i + const) - 1)) >> i
    return norm

def reverse_right_shift(norm, const, mask=mask_largest_val):
    result = norm
    # get number in c bit chunks
    c_block_ones = (1 << const) - 1
    num_const_segments = int.bit_length(norm) // const
    rem_segment = int.bit_length(norm) - (num_const_segments * const)
    for curr_block in range(1, num_const_segments):
        known_block = result & (c_block_ones << int.bit_length(norm) - (const * (curr_block)))
        result = result ^ ((known_block >> const) & mask)
    # you need to deal with the remainder take the last block, truncate it and add it
    if rem_segment != 0 and num_const_segments >= 1:
        partial_block = result & ((1 << const + rem_segment) - 1)
        return result ^ ((partial_block >> const) & mask)
    else:
        return result

def untemper(mersenne_output):
    recovered_val = reverse_right_shift(mersenne_output, constants_mersenne['l'])
    recovered_val = reverse_left_shift(recovered_val, constants_mersenne['t'], constants_mersenne['c'])
    recovered_val = reverse_left_shift(recovered_val, constants_mersenne['s'], constants_mersenne['b'])
    recovered_val = reverse_right_shift(recovered_val, constants_mersenne['u'], constants_mersenne['d'])
    return recovered_val

def recover_prediction():
    seed_twister = CryptoPals21.MersenneTwister19937(2)
    state_recovered = []
    for m in range(624):
        output = seed_twister.extract_num()
        state_recovered.append(untemper(output))
    print("Finished.")

    unrelated_twister = CryptoPals21.MersenneTwister19937(0)
    unrelated_twister.overwrite_state(state_recovered)
    for i in range(2):
        print("Original Merisenne Twister {}".format(seed_twister.extract_num()))
        print("Overwritten State {}".format(unrelated_twister.extract_num()))
    return

def main():
    recover_prediction()

# aahhhh heck ya
if __name__ == "__main__":
    main()