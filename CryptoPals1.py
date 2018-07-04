#!/usr/bin/python
# this uses PYTHON 3
import sys
import binascii

def hexToRaw(hex_str):
    raw = binascii.unhexlify(hex_str)
    return base64.b64encode(raw)

def hexXOR(arg1, arg2):
    # TODO change this to XOR based on how many bytes are given
    # if there are more than can be supported on the platform, you need
    # to do this multiples times --- or maybe not because from_bytes does some
    # fancy ish under the hood
    assert(len(arg1) == len(arg2))
    total_len = int(len(arg1) / 2)
    opa = binascii.unhexlify(arg1)
    opb = binascii.unhexlify(arg2)

    res = int.from_bytes(opa, byteorder='big') ^ int.from_bytes(opb, byteorder='big')
    return binascii.hexlify(res.to_bytes(total_len, byteorder='big'))

def main():
    test1 = "1c0111001f010100061a024b53535009181c"
    test2 = "686974207468652062756c6c277320657965"
    print(hexXOR(test1, test2))
    """
    if len(sys.argv) != 2:
        print("You screwed up, son")
        return
    else:
        print(hexToRaw(sys.argv[1]))
    """
if __name__ == "__main__":
    main()
