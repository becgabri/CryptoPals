import sys, getopt
from crypto_pals.set1.build_subtable import create_table
import os
import json
from crypto_pals.set1 import GF28
import math
import copy
import base64
import os.path


# DISCLAIMER: This is an AES implementation that was made for fun. There are NO
# guarantees on this software being secure or correct ... good thing I never signed that
# foot shooting agreement ... 
BYTES_PER_WORD = 4
WORDS_PER_STATE = 4
filename = os.path.join(os.path.dirname(__file__), "AES_sub_bytes.txt")
ROUNDS = 10

# takes a round index and returns a round constant for key expansion
# that represents a poly of degree
# less than 4 with elements from GF28
def get_round_constant(round_idx):
    if (round_idx < 1):
        raise ValueError("Index should be higher for calling round constant")
    round_res = [GF28.GF28(0)] * 4
    round_res[0] = GF28.GF28(1 << (round_idx - 1))
    return round_res

# fixing this to let the offset determine which row somehthing actually is
MIX_MTX = [2, 3, 1, 1, 1, 2, 3, 1, 1, 1, 2, 3, 3, 1, 1, 2]
for idx, val in enumerate(MIX_MTX):
    MIX_MTX[idx] = GF28.GF28(val)
# TODO write a matrix inverse function
INV_MIX_MTX = [14, 11, 13, 9, 9, 14, 11, 13, 13, 9, 14, 11, 11, 13, 9, 14]
for idx, val in enumerate(INV_MIX_MTX):
    INV_MIX_MTX[idx] = GF28.GF28(val)
SUBS_TABLE = {}
INV_SUBS_TABLE = {}
if not (os.path.exists(filename)):
    create_table()
with open(filename, 'r') as sub_r:
    both_tables = json.loads(sub_r.read())
    SUBS_TABLE = both_tables[0]
    INV_SUBS_TABLE = both_tables[1]

def print_GF28_list(list_t):
    print('|'.join([str(item.number) for item in list_t]))
    return
# 1) Build up substituion matrix --
# assume for now that the name of subst. table
# is sub_table
# Modifies: state
def inv_sub_bytes(state):
    for idx, byte in enumerate(state):
        state[idx] = GF28.GF28(INV_SUBS_TABLE[str(byte.number)], True)
    return

# Requires: state is an array of length 16 of GF28 elements
# Modifies: state
def sub_bytes(state):
    for idx, byte in enumerate(state):
        state[idx] = GF28.GF28(SUBS_TABLE[str(byte.number)], True)
    return

# each shift in a row
# can be represented as attempting to cycle through the
# indices, (x + 1) mod 4,(x + 2) mod 4, (x + 3) mod 4
# this function shifts elements through a row by step 
# until reaching the original index
def cycle_shift(state, row, col, step):
    misplaced_elt = (state[row + col], col)
    while (misplaced_elt[1] + step) % 4 != col:
            new_col = (misplaced_elt[1] + step) % 4
            tmp = (state[new_col + row], new_col)
            state[new_col + row] = misplaced_elt[0]
            misplaced_elt = tmp
    # do the last step
    state[row + col] = misplaced_elt[0]

# Requires: state is an array of length 16 of GF28 elements
# Modifies: N/A
# Returns: the new state that should be recorded
def shift_rows(state):
    # only values this should be are 0, 4, 8, and 12
    for shift_out in range(1,4):
        row_selector = shift_out*4
        cycle_shift(state, row_selector, 0, 4-shift_out)
        # needed because x - 2 mod 4 has disjoint cycles (02)(13)
        # whereas x-1 = x + 3 mod 4and x-3 = x + 1 mod 4 are both
        # one cycle ie (0321) and (0123)
        if shift_out == 2:
            cycle_shift(state, row_selector, 1, 4-shift_out)
           
    return

# Requires: state is an array of length 16 of GF28 elements
# Modifies: N/A
# Returns: the new state that should be recorded
def inv_shift_rows(state):
    # only values this should be are 0, 4, 8, and 12
    for shift_out in range(1,4):
        row_selector = shift_out*4
        cycle_shift(state, row_selector, 0, shift_out)

        if shift_out == 2:
            cycle_shift(state, row_selector, 1, shift_out)

    return


# multiply each column of state matrix by the
# mix mtx (4 x 4)
# Modifies: N/A
# Returns: New state that should be recorded
def mix_cols(state):
    new_state = [GF28.GF28(0)] * 16
    for row in range(0,4):
        for col in range(0,4):
            index = 4 * row + col
            # row from mix mtrx,
            # col from state mtrx
            new_state[index] = GF28.dot_prod_in_GF28(MIX_MTX[4 * row: 4 * (row + 1)],
                state[col:16:4])
    return new_state

# Modifies: N/A
# Returns: new state array of GF28 elts. (length 16)
def inv_mix_cols(state):
    new_state = [GF28.GF28(0)] * 16
    for row in range(0,4):
        for col in range(0,4):
            index = 4 * row + col
            # row from mix mtrx,
            # col from state mtrx
            new_state[index] = GF28.dot_prod_in_GF28(INV_MIX_MTX[4 * row: 4 * (row + 1)],
                state[col:16:4])
    return new_state

# Requires: state is an array of 16 bytes
# key is an array of 16
# words in key are XOR'ed with COLUMNS
# of the state
def add_round_key(state, key):
    for idx, val in enumerate(state):
        quot_rem = divmod(idx, 4)
        state[idx] = state[idx] + key[quot_rem[1] * 4 + quot_rem[0]]
        #result[idx] = state[idx] + key[idx]

# takes an array of length 4 and rotates it s.t.
# the first byte is last and everything else is shifted once
# Note: this modifies the argument that is passed to it
def rotate_key_word(key_word):
    first_byte = key_word.pop(0)
    key_word.append(first_byte)

def key_expansion(key):
    expanded_key = [GF28.GF28(0)] * ((WORDS_PER_STATE * (ROUNDS + 1)) * BYTES_PER_WORD)
    # fill out the first four words with (4 * 8 = 32 bytes) the initial key
    for i in range(len(key)):
        expanded_key[i] = key[i]
    # fill out now according to the rule:
    # if it's a multiple of four, take the previous word, circular shift back once,
    # and then take each byte through the subst. table before XOR'ing with the
    # round constant
    # otherwise, leave it the same
    # then XOR the previous byte with the one NK back
    iterator = 4 * BYTES_PER_WORD
    # this takes place PER WORD (so operating on 4 bytes at a time)
    while (iterator < len(expanded_key)):
        prev_word = expanded_key[iterator - BYTES_PER_WORD:iterator]
        if iterator % (4 * BYTES_PER_WORD) == 0:
            rotate_key_word(prev_word)
            sub_bytes(prev_word)
            some_const = get_round_constant(math.floor(iterator / (BYTES_PER_WORD * WORDS_PER_STATE)))
            for idx, byte in enumerate(prev_word):
                prev_word[idx] = prev_word[idx] + some_const[idx]
        word_four_back = expanded_key[iterator - (4 * BYTES_PER_WORD):iterator - (3 * BYTES_PER_WORD)]
        new_word = [GF28.GF28(0)] * 4
        for idx in range(iterator,iterator + BYTES_PER_WORD):
            it = idx % 4
            expanded_key[idx] = prev_word[it] + word_four_back[it]
        iterator += BYTES_PER_WORD
    return expanded_key
# plaintext is already in GF28
def fill_state_array(text):
    state_arr = [GF28.GF28(0)] * 16
    for idx, elt_GF28 in enumerate(state_arr):
        quot_rem = divmod(idx, 4)
        state_arr[idx] = text[quot_rem[1] * 4 + quot_rem[0]]
    return state_arr
#to do, integrate this into aes encryption function
def unscramble_state(state_arr):
    state_output = [GF28.GF28(0)] * 16
    for idx, GF28_elt in enumerate(state_arr):
        quot_rem = divmod(idx, 4)
        state_output[quot_rem[1] * 4 + quot_rem[0]] = state_arr[idx]
    return state_output

def GF28_to_string(list_GF28):
    res = []
    for elt in list_GF28:
        res.append(chr(elt.number))
    return "".join(res)


def PKCS_padd(array_GF28): 
    padding = 16 - (len(array_GF28) % 16)
    array_GF28.extend([GF28.GF28(padding)] * padding)
    return array_GF28

# input is an array of state that has been unscrambled
def strip_PKCS_padding(array_GF28):
    padding_amount = (array_GF28[-1]).number
    # checks from set2 challenge 15

    if padding_amount > 16 or padding_amount == 0:
        raise ValueError("Padding Error:" + GF28_to_string(array_GF28))
    # validate padding
    last_valid_idx = len(array_GF28) - 1
    for i in range(1, padding_amount):
        if array_GF28[last_valid_idx - i].number != padding_amount:
            raise ValueError("Padding Error:" + GF28_to_string(array_GF28))
    # strip padding
    return array_GF28[:-1 * padding_amount]

# right now only 128 bit keys are accepted
# key and plaintext must be arrays of GF28 elts
# returns the cipher text as an array of GF28 elts
def encrypt_aes(key, plaintext):
    key_padd = key_expansion(key)
    state = fill_state_array(plaintext)

    add_round_key(state, key_padd[:4 * BYTES_PER_WORD])
    for round in range(1, 10):
        sub_bytes(state)
        shift_rows(state)
        state = mix_cols(state)
        add_round_key(state, key_padd[round * (4 * BYTES_PER_WORD): (round + 1) * (4 * BYTES_PER_WORD)])

    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, key_padd[ROUNDS * (4 * BYTES_PER_WORD):])

    return unscramble_state(state)
# key and ciphertext MUST be arrays of GF28 elts
# returns plaintext as an array of GF28 elts
def decrypt_aes(key, ciphertext):
    key_padd = key_expansion(key)
    state = fill_state_array(ciphertext)

    add_round_key(state, key_padd[ROUNDS * (4 * BYTES_PER_WORD):])
    for round in range(1, 10):
        inv_shift_rows(state)
        inv_sub_bytes(state)
        add_round_key(state, key_padd[(ROUNDS - round) * (4 * BYTES_PER_WORD):(ROUNDS + 1 - round) * (4 * BYTES_PER_WORD)])
        state = inv_mix_cols(state)
    # inverse sub, inverse shift, add round key, end
    inv_sub_bytes(state)
    inv_shift_rows(state)
    add_round_key(state, key_padd[0:(4 * BYTES_PER_WORD)])

    return unscramble_state(state)

def modify_list_into_GF28(original_list):
    modified_list = []
    if isinstance(original_list, bytes) or isinstance(original_list, bytearray):
        for i in range(len(original_list)):
            modified_list.append(GF28.GF28(original_list[i]))
    elif isinstance(original_list, str):
        for i in range(len(original_list)):
            modified_list.append(GF28.GF28(ord(original_list[i])))
    else:
        raise TypeError("input is of an unsupported type")
    return modified_list

def modify_IV_into_GF28(text_IV):
    # we only accept a string for this that is an integer (between 0 and 255)
    # each integer should be delimited by dashes (i.e. -) and there should be 16
    # integers
    result_in_GF28 = []
    if type(text_IV) is bytearray:
        for i in text_IV:
            result_in_GF28.append(GF28.GF28(i))
        return result_in_GF28
    values = text_IV.split('-')
    if (len(values)) != 16:
        raise ValueError("IV is not correct length for AES")
    for let in values:
        result_in_GF28.append(GF28.GF28(int(let)))
    return result_in_GF28

# Plain Text is arbitrary length
# encryption_alg is a function that has signature
# def func_name(key, plaintext)
# where the parameters supplied are self_explanatory
def encryption_mode_ECB(key, plaintext, encryption_alg):
    # uses PKCS 7 padding
    # modify key and plaintext
    plaintext_in_GF28 = modify_list_into_GF28(plaintext)
    key_in_GF28 = modify_list_into_GF28(key)

    # use PKCS 7 padding
    PKCS_padd(plaintext_in_GF28)

    ciphertext_blocks = []
    for block in range(0, len(plaintext_in_GF28), 16):
        segment = plaintext_in_GF28[block:block + 16]
        ciphertext_blocks.extend(encryption_alg(key_in_GF28, segment))
    ciphertext = GF28_to_string(ciphertext_blocks)
    return ciphertext

# ciphertext IS a multiple of 16
def decryption_mode_ECB(key, ciphertext, decryption_alg):
    deciphered_blocks = []
    ciphertext_in_GF28 = modify_list_into_GF28(ciphertext)
    key_in_GF28 = modify_list_into_GF28(key)
    for block in range(0, len(ciphertext_in_GF28), 16):
        deciphered_blocks.extend(decryption_alg(key_in_GF28, ciphertext_in_GF28[block: block + 16]))

    plaintext = GF28_to_string(strip_PKCS_padding(deciphered_blocks))
    return plaintext


# Requires: encryption alg is a function with signature
# (key, text), it should also return a string of
def ENCRYPTION_CBC_MODE(IV, key, text, encryption_alg):
    # modify key and plaintext
    plaintext_in_GF28 = modify_list_into_GF28(text)
    # use PKCS 7 padding
    PKCS_padd(plaintext_in_GF28)

    key_in_GF28 = modify_list_into_GF28(key)
    IV_in_GF28 = modify_IV_into_GF28(IV)

    iteration = IV_in_GF28

    ciphertext = ""
    for block in range(0, len(plaintext_in_GF28), 16):
        segment = plaintext_in_GF28[block:block + 16]

        for it in range(len(segment)):
            iteration[it] = segment[it] + iteration[it]
        iteration = encryption_alg(key_in_GF28, iteration)
        ciphertext += GF28_to_string(iteration)
    return ciphertext

def DECRYPTION_CBC_MODE(IV, key, text, decryption_alg):
    ciphertext_in_GF28 = modify_list_into_GF28(text)
    IV_in_GF28 = modify_IV_into_GF28(IV)
    key_in_GF28 = modify_list_into_GF28(key)
    plaintext_blocks = []
    if (len(ciphertext_in_GF28) % 16) != 0:
        raise ValueError("Length of string is not a multiple of block size")
    for block in range(0, len(ciphertext_in_GF28), 16):
        previous_segment = ciphertext_in_GF28[block - 16:block] if block >= 16 else IV_in_GF28
        segment = ciphertext_in_GF28[block: block + 16]
        res = decryption_alg(key_in_GF28, segment)
        for idx, elt in enumerate(res):
            res[idx] = res[idx] + previous_segment[idx]
        plaintext_blocks.extend(res)
    plaintext = GF28_to_string(strip_PKCS_padding(plaintext_blocks))
    return plaintext


def main(inputFile, keyFile, mode, type_t, isBase64):
    key = ""
    input_text = ""
    if not os.path.exists(inputFile) or not os.path.exists(keyFile):
        raise OSError("Path not found")
    with open(inputFile, 'r') as in_f:
            input_text = in_f.read()
    with open(keyFile, 'r') as in_key:
        key = in_key.read().strip('\n')
    if mode == "ECB":
        if len(key) != 16:
            raise ValueError('Key needs to be length 16')
        if type == "encrypt":
            res = encryption_mode_ECB(key, input_text, encrypt_aes)
            if isBase64:
                print(base64.b64encode(res))
            else:
                print(res)
        else:
            if isBase64:
                modified_text = base64.b64decode(input_text)
            res = decryption_mode_ECB(key, modified_text, decrypt_aes)
            print(res)
    elif mode == "CBC":
        print("Please provide an input file for IV")
        iv_f = input("IV File (or None if you want to input from command line): ")
        iv_input = ""
        if iv_f == "None":
            iv_input = input("Provide 16 digits, delimited by dashes: ")
        else:
            if not os.path.exists(iv_f):
                raise OSError("IV file does not exist")
            with open(iv_f, 'r') as input_file:
                iv_input = input_file.read()
                iv_input.strip()
                #if len(iv_input) != 16:
                #    raise ValueError("IV input is not correct length for AES")
        if type_t == "encrypt":
            res = ENCRYPTION_CBC_MODE(iv_input, key, input_text, encrypt_aes)
            if isBase64:
                print(base64.b64encode(res))
            else:
                print(res)
        else:
            if isBase64:
                decoded_input = base64.b64decode(input_text)
            res = DECRYPTION_CBC_MODE(iv_input, key, decoded_input, decrypt_aes)
            print(res)
    else:
        print("Mode {} has not been implemeted".format(mode))
        return

if __name__ == "__main__":
    try:
        input_file = ""
        b64 = False
        mode = ""
        type_t = ""
        key = ""
        opts, other_args = getopt.getopt(sys.argv[1:], 'bi:m:t:k:')
    except getopt.GetoptError:
        print("Format is python3 {} -i [input_file] -k [key file] -m [mode (ex. ECB)] -t [encrypt/decrypt] [-b/--base64]".format(sys.argv[0]))
        sys.exit(1)
    for opt, arg in opts:
        if opt in ("-i", "--inputFile"):
            input_file = arg
        elif opt in ("-m", "--mode"):
            mode = arg
        elif opt in ("-t", "--type"):
            type_t = arg
        elif opt in ("-k", "--key"):
            key = arg
        elif opt in ("-b", "--base64"):
            b64 = True
    if input_file == "" or mode == "" or type =="":
        print("Format is python3 {} -i [input_file] -k [key file] -m [mode (ex. ECB)] -t [encrypt/decrypt] [-b/--base64]".format(sys.argv[0]))
        sys.exit(1)
    main(input_file, key, mode, type_t, b64)
