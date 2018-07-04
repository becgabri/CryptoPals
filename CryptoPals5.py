# Crypto Challenge 5 --- this one is for basically a vigenere
import sys
import os
import math
from CryptoPals1 import hexXOR

def repeatXOR(key, plaintext):
    padding = key * (math.ceil(len(plaintext) / len(key)))
    padding = padding[0:len(plaintext)]
    word = hexXOR(padding.encode().hex(), plaintext.encode().hex())
    string_res = word.decode()
    print(string_res)
    return

# writes to [plainttext_enc.[format]]
def main():
    # sys.argv is [program name] [args]
    if (len(sys.argv) != 3):
        print("Usage is python3 {} [input key] [plaintext]".format(sys.argv[0]));
        return
    if (os.path.isfile(sys.argv[1]) and os.path.isfile(sys.argv[2])):
        with open(sys.argv[1], 'r') as input_key:
            with open(sys.argv[2], 'r') as file_obj:
                repeatXOR(input_key.read().strip(), file_obj.read().strip())
        return

if __name__ == "__main__":
    main()