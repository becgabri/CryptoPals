import sys
import copy
import math

BLOCK_SIZE = 512
PROCESS_LIMIT = BLOCK_SIZE // 8
# TODO:
def all_lower(x, y, z):
    return x < 2**32 and y < 2**32 and z < 2**32

def Majority(x,y,z):
    if not all_lower(x,y,z):
        raise ValueError("Must be byte_words")
    return (x & y) ^ (y & z) ^ (x & z)

def Parity(x,y,z):
    if not all_lower(x,y,z):
        raise ValueError("Must be byte_words")
    return x ^ y ^ z

def Change(x,y,z):
    if not all_lower(x,y,z):
        raise ValueError("Must be byte_words")
    return (x & y) ^ (~x & z)

def function_split(identifier, arg1, arg2, arg3):
    if identifier < 20:
        return Change(arg1, arg2, arg3)
    elif identifier < 40:
        return Parity(arg1, arg2, arg3)
    elif identifier < 60:
        return Majority(arg1, arg2, arg3)
    else:
        return Parity(arg1, arg2, arg3)

def rotate_left_shift(val, shift_val, word_size):
    tmp = (val << shift_val) | (val >> (word_size - shift_val))
    return tmp & ((1 << word_size) - 1)

#takes message as an integer
def padd_message(message_as_int, num_characters):
    message_as_int = (message_as_int << 1) | 1

    # l + 1 + k = 448 mod 512 so,
    # k = 448 - l - 1 (mod 512) ??
    zero_chars = (448 - (num_characters * 8) - 1) % 512
    message_as_int = message_as_int << zero_chars
    message_as_int = (message_as_int << 64) | (num_characters * 8)

    return message_as_int

# create a 80 32 bit word array from a 512 bit block or 16 32 bit vals
def create_word_schedule(block):
    word_schedule = []
    for i in range(BLOCK_SIZE - 32, -1, -32):
        word_schedule.append((block >> i) & (2**32 - 1))
    for t in range(16, 80):
        word_schedule.append(rotate_left_shift(word_schedule[t-3] ^ word_schedule[t-8] \
            ^  word_schedule[t-14] ^ word_schedule[t-16], 1, 32))
    return word_schedule

class SHA1:
    def __init__(self):
        self.hash_vals = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]
        self.constants = [
            0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6
        ]
        self.blocks_processed = 0
        self.message = b""
        # TODO update the class to support adding blocks
    def update_hashes(self, hash_bytes, blocks):
        if self.message != b"" or self.blocks_processed != 0:
            raise ValueError("Can only update initial hashes once before actual message is added")
        self.blocks_processed += blocks
        hash_val = int.from_bytes(hash_bytes, byteorder='big')
        if hash_val.bit_length() > 160:
            raise ValueError("Hash size is incorrect")
        hashes = 5 * [0]
        for idx in range(5):
            #hashes[5 - idx - 1]
            hashes[5 - idx - 1] = (hash_val >> (32 * idx)) & ((1 << 32) - 1)
        for i in range(len(hashes)):
            self.hash_vals[i] = hashes[i]
        return

    def return_constant(self,idx):
        if idx <= 19:
            return self.constants[0]
        elif idx <= 39:
            return self.constants[1]
        elif idx <= 59:
            return self.constants[2]
        else:
            return self.constants[3]

    def parse_to_blocks(self):
        message_as_int = int.from_bytes(self.message, byteorder='big')
        message_as_int = padd_message(message_as_int, len(self.message) + (self.blocks_processed * (512 // 8)))
        message_blocks = []
        blocks_calc = int(math.ceil(message_as_int.bit_length() / BLOCK_SIZE))
        for i in range((blocks_calc-1)*BLOCK_SIZE, -1, -BLOCK_SIZE):
            tmp = (message_as_int >> i) & ((1 << BLOCK_SIZE) - 1)
            message_blocks.append(tmp)

        return message_blocks

    def Sum(self):
        # do parsing
        message_blocks = self.parse_to_blocks()
        for block in message_blocks:
            # this will come pretty directly from the NIST document
            words = create_word_schedule(block)
            # [a, b, c, d, e] [0, 1, 2, 3, 4]
            working_vars = copy.copy(self.hash_vals)
            for t in range(80):
                temp_word = rotate_left_shift(working_vars[0],5,32) + function_split(t,
                    working_vars[1], working_vars[2], working_vars[3]) + working_vars[4] + \
                    words[t] + self.return_constant(t)
                temp_word = temp_word & ((1 << 32)- 1)
                working_vars[4] = working_vars[3]
                working_vars[3] = working_vars[2]
                working_vars[2] = rotate_left_shift(working_vars[1], 30, 32)
                working_vars[1] = working_vars[0]
                working_vars[0] = temp_word
            for i in range(5):
                self.hash_vals[i] = (self.hash_vals[i] + working_vars[i]) & ((1<<32) - 1)
        final_res = 0

        for i in range(len(self.hash_vals)):
            final_res = final_res | (self.hash_vals[4 - i] << (32 * i))
        if final_res.bit_length() > 160:
            raise ValueError("Error, bit length for message is too large")
        return final_res.to_bytes(160 // 8, byteorder='big')

    def Update(self, message_to_add):
        add_to_msg = message_to_add
        if type(message_to_add) is str:
            add_to_msg = str.encode(message_to_add)

        if (len(self.message) + len(add_to_msg) + self.blocks_processed) > ((2**64) / 2**3):
            raise ValueError("The message must be less than 2**64 bits long.")
        else:
            self.message += add_to_msg
        return

# msg schedule 32 bit 80 words
# 5 working variables of 32 bits
# hash val of 5 32 bit words

def main():
    print("Testing SHA-1\n Message \'abc\'")
    message_digest1 = SHA1()
    message_digest1.Update('abc')
    result = message_digest1.Sum()
    print("Digest:", hex(int.from_bytes(result,byteorder='big')))
    test2 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    print("Message ", test2)
    message_digest2 = SHA1()
    message_digest2.Update(test2)
    result2 = message_digest2.Sum()
    print("Digest:", hex(int.from_bytes(result2,byteorder='big')))
    return

if __name__ == "__main__":
    main()
