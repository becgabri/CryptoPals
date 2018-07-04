#!/usr/bin/python3
import sys, getopt
import os.path
import binascii
import math
import string
from CryptoPals1 import hexXOR

letter_frequencies = {}

def unique(test):
    make_it = set()
    for elt in test:
        make_it.add(elt)
    return list(make_it)
def asciiToHexBytes(convert_str):
    return bytes(convert_str, encoding='UTF-8')

def hexToAsciiPrint(byte_hex_str):
    print("{}".format(binascii.unhexlify(byte_hex_str).decode('utf-8')))

def dot_prod(vector1, vector2):
    if len(vector1) == len(vector2):
        return sum([vector1[x] * vector2[x] for x in range(len(vector1))])
    else:
        print("Failed same length check for dot product")
        sys.exit(2)

# string-t is string of ascii values and encrypt val is a byte
def decrypt(string_t, encrypt_val):
    # recall, xor undoes itself so just XOR out the same value
    #convert string of vals to hex string
    byte_pad = bytearray(len(string_t))
    for i in enumerate(byte_pad):
        i = encrypt_val

    val = hexXOR(asciiToHexBytes(string_t), byte_pad)

    hexToAsciiPrint(val)

    # now ram this through?
def cosine_sim(vector1, vector2):
    # vectors with correct matched up values

    len_1 = math.sqrt(dot_prod(vector1, vector1))
    len_2 = math.sqrt(dot_prod(vector2, vector2))
    if len_1 == 0 or len_2 == 0:
        return 0.0
    return float(dot_prod(vector1, vector2)) / (len_1 * len_2)


def xorBrute(string_input):
    populate_freq()
    # try and encrypt with a variety of byte values
    if len(string_input) % 2 != 0:
        print("Invalid input format, expecting hex string")
        sys.exit(2)
    str_len = len(string_input) / 2
    possible_vals = []
    charset = [str(x) for x in range(10)]
    charset.extend([a for a in string.ascii_lowercase[0:6]])
    for val1 in charset:
        for val2 in charset:
            possible_vals.append(val1 + val2)
    tests = []
    dictionary_vect = [letter_frequencies[letter] for letter in string.ascii_uppercase]
    # get from 00 to ff
    for test_enc in possible_vals:
        new_str = test_enc * int(str_len)
        decryption = hexXOR(string_input, new_str)
        decryption = binascii.unhexlify(decryption)
        #if test_enc == '35' and any(x == 106 for x in decryption):
    #    import pdb; pdb.set_trace()
        if any(x < 9 or (x > 13 and x < 32) or x > 122  for x in decryption):
            #print("Contains non viable characters: {}".format(decryption))
            decryption = bytes(int(str_len))
        # find frequencies
        test_vect = [ (decryption.count(bytes(val, encoding='utf-8')) +
             decryption.count(bytes(val.lower(), encoding='utf-8')))
            / float(len(decryption)) for val in string.ascii_uppercase]
        tests.append(cosine_sim(test_vect, dictionary_vect))
        #if tests[-1] > 0.50:
        #    xor_pad = possible_vals[len(tests) - 1] * int(str_len)
        #    hexToAsciiPrint(hexXOR(xor_pad, decryptThis))
        #    print("Test value is {}".format(tests[-1]))
    assert(len(tests) == 256)
    unique_res = unique(tests)
    if len(unique_res) == 1 and tests[0] == 0.0:
        return
    #grab index of max and then decrypt
    #do this for top 5
    #what i want is cosine sim....
    index_del = tests.index(max(tests))
    char_enc = possible_vals[index_del]
    assert(len(tests) == len(possible_vals))
    print("Start round")
    while tests[index_del] != 0.0:
        #print("{} most likely option".format(i))
        del tests[index_del]
        del possible_vals[index_del]
        # i know if you are writing this with a break you should
        # really just use a for loop :P
        xor_pad = str(char_enc) * int(str_len)
        final_res = hexXOR(xor_pad, string_input)
        hexToAsciiPrint(final_res)

        index_del = tests.index(max(tests))
        char_enc = possible_vals[index_del]

def populate_freq():
    with open("letter_freq.txt", "r") as letDict:
        for line in letDict.readlines():
            line = line.strip()
            if line == "":
                continue
            character, freq = line.split(" ")
            letter_frequencies[character] = float(freq)


def main(input_file, mode):
    decryptThis = ""
    if os.path.exists(input_file):
        with open(input_file, "r") as input:
            decryptThis = input.read().strip()
    if len(decryptThis) == 0:
        print("There is nothing in input file or input path does not exist. Quitting...")
        sys.exit(2)
    if mode == "brute-force":
        xorBrute(decryptThis)

if __name__ == "__main__":
    try:
        input_file = ""
        mode = ""
        opts, leftover_args = getopt.getopt(sys.argv[1:], 'i:m:')
    except getopt.GetoptError:
        print("Format is {} -i [input_file] -m mode".format(sys.argv[0]))
        sys.exit(2)
    # unpack the arguments
    for opt, arg in opts:
        if opt in ("-i", "--inputFile"):
            input_file = arg
        if opt in ("-m", "--mode"):
            mode = arg
    if input_file == "" or mode == "":
        print("Incorrect format: python3 {} -i [input_file] -m mode".format(sys.argv[0]))
        sys.exit(2)
    main(input_file, mode)