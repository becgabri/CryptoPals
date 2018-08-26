import os
import json
import math
from . import GF28
filename = "AES_sub_bytes.txt"

def create_table():
    with open(filename, 'w') as holder:
        subst = {}
        inverse = {}
        for num in range(256):
            num = GF28.GF28(num, bypass_modcheck=True)
            # works with 0 b/c of hack in GF28.py
            byte_stuff = num.inverse()
            res = GF28.GF28()
            for i in range(5):
                res = res + byte_stuff
                byte_stuff.rotate_bit()
            res = res + GF28.GF28(0x63)
            if num.number > 256 or res.number > 256:
                raise ValueError("Num or res out of range")
            subst[num.number] = res.number
            inverse[res.number] = num.number
        holder.write(json.dumps([subst, inverse]))

def main():
    if not os.path.exists(filename):
        create_table()
    else:
        print("Table already exists. Quitting...")
    return

if __name__ == "__main__":
    main()