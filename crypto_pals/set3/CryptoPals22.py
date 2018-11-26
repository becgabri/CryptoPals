import random
import time
import sys
import os
import math
from crypto_pals.set3 import CryptoPals21

def twisting_generate():
    time.sleep(random.randint(40,1000))
    seed_for_mt = int(time.time())
    print("Seed for mersenne {}".format(seed_for_mt))
    mt = CryptoPals21.MersenneTwister19937(seed_for_mt)
    time.sleep(random.randint(40,1000))
    return mt.extract_num()

def crack_mersenne():
    with open("Mersenne_output.txt", "r") as read_f:
        extractor = read_f.read().split("\n")
    separate_nums = []
    for line in extractor:
        separate_nums.append(line.split(": ")[1])
    separate_nums[0] = int(separate_nums[0].strip())
    separate_nums[1] = int(math.floor(float(separate_nums[1].strip())))
    separate_nums[2] = int(math.ceil(float(separate_nums[2].strip())))

    middle_ctr = int(math.ceil((separate_nums[2] - separate_nums[1]) / 2))
    for i in range(middle_ctr):
        # try increasing
        itr_large = separate_nums[1] + middle_ctr + i
        mt_front = CryptoPals21.MersenneTwister19937(itr_large)
        if mt_front.extract_num() == separate_nums[0]:
            print("Value of seed was {}".format(itr_large))
            return
        else:
            itr_small = separate_nums[1] + middle_ctr - i
            mt_back = CryptoPals21.MersenneTwister19937(itr_small)
            if mt_back.extract_num() == separate_nums[0]:
                print("Value of seed was {}".format(itr_small))
                return
    print("Could not find value :( Failed.)")


def main():
    start = time.time()
    result = twisting_generate()
    end = time.time()
    print("Result output of PRNG is: {}".format(result))
    with open("Mersenne_output.txt", "w") as wr_file:
        wr_file.write("Result is: {}\n Start Time is: {} \n End Time is: {}".format(result,start, end))
    print("Cracking File...")
    crack_mersenne()
    return

if __name__ == "__main__":
    if os.path.exists("Mersenne_output.txt"):
        print("Cracking File...")
        crack_mersenne()
    else:
        print("Generating File....")
        main()
