#!/usr/bin/python3
import sys, getopt
import os.path
import binascii
import math
import string
from crypto_pals.set1.CryptoPals1 import hexXOR

dictionary_vect = [ 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.18093922651933703, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.012430939226519336, 0.0, 0.0, 0.0, 0.0, 0.004143646408839779, 0.0, 0.0013812154696132596, 0.0, 0.0013812154696132596, 0.0013812154696132596, 0.0, 0.0, 0.0, 0.0013812154696132596, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0013812154696132596, 0.0, 0.0027624309392265192, 0.0027624309392265192, 0.0013812154696132596, 0.0013812154696132596, 0.0, 0.0, 0.0013812154696132596, 0.0, 0.012430939226519336, 0.0013812154696132596, 0.0013812154696132596, 0.0013812154696132596, 0.0013812154696132596, 0.0027624309392265192, 0.0, 0.0, 0.0013812154696132596, 0.0027624309392265192, 0.0013812154696132596, 0.0027624309392265192, 0.0, 0.0013812154696132596, 0.004143646408839779, 0.0, 0.0013812154696132596, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.06077348066298342, 0.016574585635359115, 0.019337016574585635, 0.024861878453038673, 0.06077348066298342, 0.008287292817679558, 0.026243093922651933, 0.04005524861878453, 0.06629834254143646, 0.004143646408839779, 0.015193370165745856, 0.026243093922651933, 0.023480662983425413, 0.06629834254143646, 0.06767955801104972, 0.020718232044198894, 0.0013812154696132596, 0.027624309392265192, 0.03729281767955801, 0.06906077348066299, 0.026243093922651933, 0.006906077348066298, 0.013812154696132596, 0.0027624309392265192, 0.016574585635359115, 0.0013812154696132596, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]

letter_frequencies = {}
allowed_characters = []
for x in string.ascii_letters:
    allowed_characters.append(x)
for x in string.whitespace:
    allowed_characters.append(x)
for extra_char in "?!',-#@$%&()":
    allowed_characters.append(extra_char)
allowed_characters.append('"')
allowed_characters = set(allowed_characters)
#allowed_characters = set(string.printable)

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

# string input is bytes argument
# returns a list of byte encodings where the similarity was above 0 with some other
# stipulations, ALL ARE REPRESENTED AS INTEGERS
def xorBrute(string_input):
    populate_freq()
    # try and encrypt with a variety of byte values
    tests = []

    dictionary_vect = []
    for byte_val in range(256):
        byte_ctr = bytes([byte_val])
        if byte_ctr.isalpha():
            letter = byte_ctr.decode(encoding='utf-8')
            dictionary_vect.append(letter_frequencies[letter.upper()])
        else:
            dictionary_vect.append(0.0)
    for test_enc in range(256):
        # need a byte array of the length of the string input
        new_str = bytes([test_enc] * len(string_input))
        decryption = hexXOR(int.to_bytes(int(string_input, 16)), new_str)
        #decryption = binascii.unhexlify(decryption)

        if any(chr(x) not in string.printable for x in decryption):
            decryption = bytes(len(string_input))
        # find frequencies
        frequency_vect = []
        for byte_val in range(256):
            byte_let = bytes([byte_val])
            frequency_vect.append(decryption.count(byte_let))
        frequency_vect = [ val / float(len(decryption)) for val in frequency_vect]
        tests.append((test_enc, cosine_sim(frequency_vect, dictionary_vect)))
    assert(len(tests) == 256)
    most_likely_encoding = sorted(tests, key=lambda value: value[1], reverse=True)
    all_non_zero = []
    for pair in most_likely_encoding:
        if pair[1] > 0.1:
            all_non_zero.append(pair[0])
            #xor_pad = bytes([pair[0]] * len(string_input))
            #final_res = hexXOR(xor_pad, string_input)
            #hexToAsciiPrint(binascii.hexlify(final_res))
    return all_non_zero

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
        plaintext = binascii.unhexlify(decryptThis)
        results = xorBrute(binascii.unhexlify(decryptThis))
        for res in results:
            xor_pad = bytes([res] * len(plaintext))
            final_res = hexXOR(xor_pad, plaintext)
            hexToAsciiPrint(binascii.hexlify(final_res))

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
