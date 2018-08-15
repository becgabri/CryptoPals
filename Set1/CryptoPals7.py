from build_subtable import create_table
import os
import json
import GF28
import math
import base64
import sys, getopt, os.path

BYTES_PER_WORD = 4
WORDS_PER_STATE = 4
filename = "AES_sub_bytes.txt"
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

# 1) Build up substituion matrix --
# assume for now that the name of subst. table
# is sub_table
# Modifies: state
def inv_sub_bytes(state):
    for idx, byte in enumerate(state):
        state[idx] = GF28.GF28(INV_SUBS_TABLE[str(byte.number)])
    return

# Requires: state is an array of length 16 of GF28 elements
# Modifies: state
def sub_bytes(state):
    for idx, byte in enumerate(state):
        state[idx] = GF28.GF28(SUBS_TABLE[str(byte.number)])
    return

# Requires: state is an array of length 16 of GF28 elements
# Modifies: N/A
# Returns: the new state that should be recorded
def inv_shift_rows(state):
    # only values this should be are 0, 4, 8, and 12
    new_state = [GF28.GF28(0)] * 16;
    modified_start_idx = 0
    for shift_out in range(0,4):
        for inner_idx in range(0,4):
            new_idx = modified_start_idx + ((inner_idx + shift_out) % 4)
            new_state[new_idx] = state[modified_start_idx + inner_idx]
        modified_start_idx += 4
    return new_state

# Requires: state is an array of length 16 of GF28 elements
# Modifies: N/A
# Returns: the new state that should be recorded
def shift_rows(state):
    # only values this should be are 0, 4, 8, and 12
    new_state = [GF28.GF28(0)] * 16
    modified_start_idx = 0
    for shift_out in range(0,4):
        for inner_idx in range(0,4):
            new_idx = modified_start_idx + ((inner_idx - shift_out) % 4)
            new_state[new_idx] = state[modified_start_idx + inner_idx]
        modified_start_idx += 4
    return new_state


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
    result = [GF28.GF28(0)] * 16
    for idx, val in enumerate(result):
        quot_rem = divmod(idx, 4)
        result[idx] = state[idx] + key[quot_rem[1] * 4 + quot_rem[0]]
        #result[idx] = state[idx] + key[idx]
    return result

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

def restructure_output(state_arr):
    string_output = [""] * 16
    for idx, GF28_elt in enumerate(state_arr):
        quot_rem = divmod(idx, 4)
        string_output[quot_rem[1] * 4 + quot_rem[0]] = chr(state_arr[idx].number)
    return "".join(string_output)

# right now only 128 bit keys are accepted
# the plaintext MUST be 16 bytes long (as is true with all AES algorithms)
# returns the cipher text as a string
def encrypt_aes(key, plaintext):
    key_padd = key_expansion(key)
    state = fill_state_array(plaintext)

    state = add_round_key(state, key_padd[:4 * BYTES_PER_WORD])
    for round in range(1, 10):
        sub_bytes(state)
        state = shift_rows(state)
        state = mix_cols(state)
        state = add_round_key(state, key_padd[round * (4 * BYTES_PER_WORD): (round + 1) * (4 * BYTES_PER_WORD)])

    sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, key_padd[ROUNDS * (4 * BYTES_PER_WORD):])

    return restructure_output(state)

def decrypt_aes(key, ciphertext):
    key_padd = key_expansion(key)
    state = fill_state_array(ciphertext)

    state = add_round_key(state, key_padd[ROUNDS * (4 * BYTES_PER_WORD):])
    for round in range(1, 10):
        state = inv_shift_rows(state)
        inv_sub_bytes(state)
        state = add_round_key(state, key_padd[(ROUNDS - round) * (4 * BYTES_PER_WORD):(ROUNDS + 1 - round) * (4 * BYTES_PER_WORD)])
        state = inv_mix_cols(state)
    # inverse sub, inverse shift, add round key, end
    inv_sub_bytes(state)
    state = inv_shift_rows(state)
    state = add_round_key(state, key_padd[0:(4 * BYTES_PER_WORD)])

    return restructure_output(state)

def modify_key_into_GF28(original_key):
    modified_key = []
    if isinstance(original_key, bytes) or isinstance(original_key, bytearray):
        for i in range(len(original_key)):
            modified_key.append(GF28.GF28(original_key[i]))
    elif isinstance(original_key, str):
        for i in range(len(original_key)):
            modified_key.append(GF28.GF28(ord(original_key[i])))
    else:
        raise TypeError("key is of an unsupported type")
    return modified_key

# Plain Text is arbitrary length
# encryption_alg is a function that has signature
# def func_name(key, plaintext)
# where the parameters supplied are self_explanatory
def encryption_mode_ECB(key, plaintext, encryption_alg):
    # uses PKCS 7 padding
    # modify key and plaintext
    plaintext_in_GF28 = []
    key_in_GF28 = modify_key_into_GF28(key)

    if isinstance(plaintext, str):
        for idx,char in enumerate(plaintext):
             plaintext_in_GF28.append(GF28.GF28(ord(char)))
    elif isinstance(plaintext, bytes) or isinstance(plaintext, bytearray):
        for idx, char in enumerate(plaintext):
             plaintext_in_GF28.append(GF28.GF28(char))
    else:
        raise TypeError("plaintext is of an unsupported type")

    ciphertext = ""
    for block in range(0, len(plaintext_in_GF28), 16):
        segment = plaintext_in_GF28[block:block + 16]
        if len(segment) < 16:
            # padd out the text to the correct size
            padding = 16 - len(segment)
            segment += (chr(padding) * padding)
        ciphertext += encryption_alg(key_in_GF28, segment)
    return ciphertext

# ciphertext IS a multiple of 16
def decryption_mode_ECB(key, ciphertext, decryption_alg):
    plaintext = ""
    ciphertext_in_GF28 = []
    key_in_GF28 = []

    if isinstance(key, bytes) or isinstance(key, bytearray):
        for i in range(len(key)):
            key_in_GF28.append(GF28.GF28(key[i]))
    elif isinstance(key, str):
        for i in range(len(key)):
            key_in_GF28.append(GF28.GF28(ord(key[i])))
    else:
        raise TypeError("key is of an unsupported type")

    if isinstance(ciphertext, str):
        for idx,char in enumerate(ciphertext):
             ciphertext_in_GF28.append(GF28.GF28(ord(char)))
    elif isinstance(ciphertext, bytes) or isinstance(ciphertext, bytearray):
        for idx, char in enumerate(ciphertext):
             ciphertext_in_GF28.append(GF28.GF28(char))
    else:
        raise TypeError("ciphertext is of an unsupported type")
    for block in range(0, len(ciphertext_in_GF28), 16):
        plaintext += decryption_alg(key_in_GF28, ciphertext_in_GF28[block: block + 16])
    return plaintext


def main(inputFile, keyFile, mode, type):
    key = ""
    input_text = ""
    if not os.path.exists(inputFile) or not os.path.exists(keyFile):
        raise OSError("Path not found")
    with open(inputFile, 'r') as in_f:
        input_text = base64.b64decode(in_f.read())
    with open(keyFile, 'r') as in_key:
        key = in_key.read().strip('\n')
    if mode == "ECB":
        if len(key) != 16:
            raise ValueError('Key needs to be length 16')
        if type == "encrypt":
            res = encryption_mode_ECB(key, input_text, encrypt_aes)
            print(res)
        else:
            res = decryption_mode_ECB(key, input_text, decrypt_aes)
            print(res)
            #print(base64.b64decode(res))
    else:
        print("Mode {} has not been implemeted".format(mode))
        return

if __name__ == "__main__":
    try:
        input_file = ""
        mode = ""
        type = ""
        key = ""
        opts, other_args = getopt.getopt(sys.argv[1:], 'i:m:t:k:')
    except getopt.GetoptError:
        print("Format is python3 {} -i [input_file] -k [key file] -m [mode (ex.ECB)] -t [encrypt/decrypt]".format(sys.argv[0]))
        sys.exit(1)
    for opt, arg in opts:
        if opt in ("-i", "--inputFile"):
            input_file = arg
        elif opt in ("-m", "--mode"):
            mode = arg
        elif opt in ("-t", "--type"):
            type = arg
        elif opt in ("-k", "--key"):
            key = arg
    if input_file == "" or mode == "" or type =="":
        print("Format is python3 {} -i [input_file] -k [key file] -m [mode (ex.ECB)] -t [encrypt/decrypt]".format(sys.argv[0]))
        sys.exit(1)
    main(input_file, key, mode, type)