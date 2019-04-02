#!/usr/bin/python
import sys
import binascii

def hexToRaw(hex_str):
    raw = binascii.unhexlify(hex_str)
    return base64.b64encode(raw)

# supports regular string arguments OR byte arguments NOT regular string args
# returns a byte string
def hexXOR(arg1, arg2):
    if len(arg1) != len(arg2):
        raise ValueError("Hex XOR arguments should be the same")
    import pdb; pdb.set_trace()
    max_len = max(len(arg1), len(arg2))

    res = int.from_bytes(arg1, byteorder='big') ^ int.from_bytes(arg2, byteorder='big')
    return res.to_bytes(max_len, byteorder='big')

def main():
    test1 = "1c0111001f010100061a024b53535009181c"
    test2 = "686974207468652062756c6c277320657965"
    result_test = hexXOR(binascii.unhexlify(test1), binascii.unhexlify(test2))

    print(binascii.hexlify(result_test))
    
if __name__ == "__main__":
    main()
