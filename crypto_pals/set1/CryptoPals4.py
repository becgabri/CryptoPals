from crypto_pals.set1.CryptoPals3 import xorBrute
import sys
import string, binascii


def test_ioc(test_bytes):
    whole_len = 0
    sum = 0
    for let in string.ascii_uppercase:
        test_byte_letter = bytes(let, encoding='utf-8')
        assert(len(test_byte_letter) == 1)
        charac = test_bytes.count(test_byte_letter)
        test_byte_letter = bytes(let.lower(), encoding='utf-8')
        assert(len(test_byte_letter) == 1)
        charac = charac + test_bytes.count(test_byte_letter)
        whole_len = whole_len + charac
        sum = sum + (charac * (charac - 1))
        charac = 0
    if whole_len < 2:
        return 0
    return sum / (float(whole_len) * (whole_len - 1))



if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage is python3 {} [input_file]".format(sys.argv[0]))
        sys.exit(1)
    file_open = sys.argv[1]
    with open(file_open, "r") as file_in:
        for line in file_in.readlines():
            line = line.strip()
            byte_lines = binascii.unhexlify(line)
            if test_ioc(byte_lines) > 0.05:
                xorBrute(byte_lines)
