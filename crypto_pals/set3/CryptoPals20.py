import base64
import sys
sys.path.append('/mnt/c/Users/becga/Documents/crypto_pals')
from crypto_pals.set1 import CryptoPals6
from crypto_pals.set3 import CryptoPals19
from crypto_pals.set2.CryptoPals11 import generate_rand_AES_key

FILENAME = "20.txt"
all_lines = []
BLOCK_SIZE = 16
AES_KEY = generate_rand_AES_key()

def main():
    with open(FILENAME, 'r') as readit:
        read_buf = readit.readlines()
        for line in read_buf:
            all_lines.append(line.strip())
        CryptoPals19.decode_and_encr(all_lines)
        for idx, line in enumerate(all_lines):
            all_lines[idx] = bytearray(line, encoding='utf-8')

        smallest_line = min(all_lines, key=lambda b: len(b))
        smallest_num = len(smallest_line)
        compressed_text = ""
        new_list = []
        for line in all_lines:
            new_list.append(line[:smallest_num])

        full_list = []
        for line in new_list:
            full_list += line
        decrypt_text = CryptoPals6.crack_single_key(len(smallest_line), full_list)
        import pdb; pdb.set_trace()
        for idx,orig_add in enumerate(all_lines):
            decrypt_text[idx] = decrypt_text[idx] + orig_add[smallest_num:]
        while True:
            # take in input
            for idx,line in enumerate(decrypt_text):
                print("{}: {}".format(idx, line))
            decrypt_all = input("Enter a guess for character: [idx_in_list] [idx_in_str] [expected letter]")
            space_delimited = decrypt_all.split(" ")

            idx_start = 0
            if (len(space_delimited) == 4):
                idx_start = 1
            idx_list = int(space_delimited[idx_start])
            idx_str = int(space_delimited[idx_start + 1])
            exp_let = space_delimited[idx_start + 2]
            if exp_let == "space":
                exp_let = ' '
            if idx_list < len(decrypt_text) and idx_str < len(decrypt_text[idx_list]):
                difference = (ord(exp_let) - decrypt_text[idx_list][idx_str]) % 256
                for idx, val in enumerate(decrypt_text):
                    if idx_str < len(decrypt_text[idx]):
                        decrypt_text[idx][idx_str] =  (val[idx_str] + difference) % 256

if __name__ == "__main__":
    main()