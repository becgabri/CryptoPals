import sys
import base64
import binascii
import math
from crypto_pals.set1.CryptoPals2 import hexXOR
from crypto_pals.set1.CryptoPals3 import xorBrute, hexToAsciiPrint
from crypto_pals.set1.permutation import perm

def count_ones(integer):
    count_ones = 0
    for i in range(integer.bit_length()):
        bit_mask = 1 << i
        if bit_mask & integer != 0:
            count_ones = count_ones + 1
    return count_ones

def hamming_dist(string1, string2):
    if type(string1) is str:
        string1 = string1.encode()
    if type(string2) is str:
        string2 = string2.encode()
    if not type(string1) is bytes or not type(string2) is bytes:
        raise TypeError("Hamming distance only accepts byte arguments")
    # xor the byte string representation of the strings
    res = int.from_bytes(string1, byteorder='big') ^ \
        int.from_bytes(string2, byteorder='big')
    # change the integer to a byte array and then count
    return count_ones(res)

def crack_single_key(key_len, plaintext):
    print("Attempting key length {}...".format(key_len))
    encrypted_with_sameKey = []
    # key_pair[0] is the key length
    for index in range(key_len):
        encrypted_with_sameKey.append(plaintext[index::key_len])
    # solve each one individually and reconstruct
    candidates = []
    could_not_get_enc_val = False
    for group in encrypted_with_sameKey:
        possible_enc_vals = xorBrute(group)
        if not possible_enc_vals:
            could_not_get_enc_val = True
        else:
            candidates.append([possible_enc_vals[0]])
    if could_not_get_enc_val:
        print("Could not get any more values")
    #[[],[],[]]
    # list is key_pair long
    possible_keys = perm(candidates)
    # this is bytes
    testtextHex = plaintext

    for idx,key in enumerate(possible_keys):
        padding = bytes(key * math.ceil(len(testtextHex) / len(key)))
        padding = padding[:len(testtextHex)]
        final_res = hexXOR(padding, testtextHex)
        print("Key index in array: {}".format(idx))
        if key_len < 10: 
            print("Beginning of potential plaintext: {}".format((final_res[0:2*key_len]).decode('utf-8')))
        else:
            print("Beginning of potential plaintext: {}".format((final_res[0:10]).decode('utf-8'))) 
        #for i in range(0, len(final_res) - key_len + 1, key_len):
        #    print('{}\n {}'.format((i // key_len), (final_res[i:i+key_len]).decode('utf-8')))
    if len(possible_keys) == 0:
        return
    resp = input("Input best guess key index (-1 for none): ")
    key_guess = int(resp)
    
    if key_guess < len(possible_keys) and key_guess >= 0:
        key = possible_keys[key_guess]
        padding = bytes(key * math.ceil(len(testtextHex) / len(key)))
        padding = padding[:len(testtextHex)]
        final_res = hexXOR(padding, testtextHex)
        result = bytearray()
        for i in range(0, len(final_res) - key_len + 1, key_len):
            result += bytearray(final_res[i:i+key_len])
        print("{}\nKey: {}".format(result.decode('utf-8'), bytes(key).decode('utf-8')))
        return True
    else:
        print("Did not find a key, continuing...")
        return False 

def crack_vigenere(plaintext):
    likely_key_lens = []
    for key_length in range(2,41):
        sum_hamming_dist = 0
        for it in range(4):
            sum_hamming_dist += hamming_dist(plaintext[it * key_length : (it + 1) * key_length], plaintext[(it + 1) * key_length : (it + 2) * key_length])
        sum_hamming_dist = sum_hamming_dist / (4.0 * key_length)
        if (type(sum_hamming_dist) == 'NoneType'):
            raise TypeError("NoneType is incorrect, should be int")
        #dist = hamming_dist(first_k_bytes, second_k_bytes) / float(key_length)
        likely_key_lens.append((key_length, sum_hamming_dist))
    # we do want the default here because closer to 0 is better
    sorted_list = sorted(likely_key_lens, key=lambda pair: pair[1])
    sorted_list = sorted_list[0:10]

    for key_pair in sorted_list:
        if crack_single_key(key_pair[0], plaintext):
            return
        
def main():
    """
    test_str1 = "this is a test"
    test_str2 = "wokka wokka!!!"
    print("This is the distance between the test strings:")
    print("{}".format(hamming_dist(test_str1, test_str2)))
    """
    if len(sys.argv) != 2:
        print("Usage is python3 {} [inputFile]".format(sys.argv[0]))
        return
    else:
        with open(sys.argv[1], 'r') as file:
            crack_vigenere(base64.b64decode(file.read()))






if __name__ == "__main__":
    main()
