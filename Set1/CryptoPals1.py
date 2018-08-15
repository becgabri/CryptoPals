#!/usr/bin/python
# this uses PYTHON 3
import sys
import binascii

def hexToRaw(hex_str):
    raw = binascii.unhexlify(hex_str)
    return base64.b64encode(raw)

# supports regular string arguments OR byte arguments NOT regular string args
# returns a byte string
def hexXOR(arg1, arg2):
    if arg1 is str:
        arg1 = arg1.encode()
    if arg2 is str:
        arg2 = arg2.encode()

    res = int.from_bytes(arg1, byteorder='big') ^ int.from_bytes(arg2, byteorder='big')
    return res.to_bytes((res.bit_length() + 7) // 8, byteorder='big')
    #binascii.hexlify(res.to_bytes(total_len, byteorder='big'))

def main():
    test1 = "1c0111001f010100061a024b53535009181c"
    test2 = "686974207468652062756c6c277320657965"
    result_test = hexXOR(binascii.unhexlify(test1), binascii.unhexlify(test2))

    print(binascii.hexlify(result_test))
    """
    if len(sys.argv) != 2:
        print("You screwed up, son")
        return
    else:
        print(hexToRaw(sys.argv[1]))
    """
if __name__ == "__main__":
    main()
