import sys
import math
# msg digest developed by Ron Rivest
# it informed the design for MD5 and SHA1 -- it is literally obsolete
    # please please don't use this... remember this came even before MD5
# code is adapted from implementation at https://tools.ietf.org/html/rfc1320]
# CURRENTLY STILL DEBUGGING

BLOCK_SIZE = 512
def Majority(x,y,z):
    return (x & y) | (y & z) | (x & z)

def Conditional(x,y,z):
    return (x & y) | ((~x) & z)

def Parity(x,y,z):
    return x ^ y ^ z

#takes message as an integer --  from SHA1 code
def padd_message(message_as_int, num_characters):
    message_as_int = (message_as_int << 1) | 1

    # l + 1 + k = 448 mod 512 so,
    # k = 448 - l - 1 (mod 512) ??
    zero_chars = (448 - (num_characters * 8) - 1) % 512
    message_as_int = message_as_int << zero_chars
    end_blocks = (num_characters * 8) & ((1 << 64) - 1)
    end_blocks = ((end_blocks & ((1 << 32) - 1)) << 32) | (end_blocks >> 32)
    message_as_int = (message_as_int << 64) | end_blocks

    return message_as_int

def rotate_left_shift(val, shift_val, word_size):
    tmp = (val << shift_val) | (val >> (word_size - shift_val))
    return tmp & ((1 << word_size) - 1)

class MD4():
    def __init__(self):
        # low order bytes are first
        # 4 bytes each * 4 words * 8 bits = 4 * 32 = 4 * (30 + 2) = 128
        self.hash_vals = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]
        self.message = bytearray()
        self.blocks_processed = 0

    def update_hash(self, state_to_update_with, blocks):
        if self.message != b"" or self.blocks_processed != 0:
            raise ValueError("Can only update before Update function is called and can only update once")
        for i in range(4):
            self.hash_vals[4 - i - 1] = state_to_update_with >> (32 * i) & ((1 << 32) - 1)
        self.blocks_processed += blocks
        return

    # from SHA again, they are the same
    def parse_to_blocks(self):
        message_as_int = int.from_bytes(self.message, byteorder='big')
        message_as_int = padd_message(message_as_int, len(self.message) + (self.blocks_processed * (512 // 8)))
        message_blocks = []
        blocks_calc = int(math.ceil(message_as_int.bit_length() / BLOCK_SIZE))
        for i in range((blocks_calc-1)*BLOCK_SIZE, -1, -BLOCK_SIZE):
            tmp = (message_as_int >> i) & ((1 << BLOCK_SIZE) - 1)
            message_blocks.append(tmp)
        return message_blocks

    def round_one_func(self, idx_to_ch, b, c, d, val_x_k, shift):
        self.hash_vals[idx_to_ch] = self.hash_vals[idx_to_ch] + \
            Conditional(b, c, d) + val_x_k
        self.hash_vals[idx_to_ch] = self.hash_vals[idx_to_ch] & ((1 << 32) - 1)
        self.hash_vals[idx_to_ch] = rotate_left_shift(self.hash_vals[idx_to_ch], shift, 32)
        return
    # self.hash_vals[a, b, c, d]
    # self.hash_vals[0, 1, 2, 3]
    def round_one(self, X):
        for i in range(0,16,4):
            self.round_one_func(0, self.hash_vals[1], self.hash_vals[2],
                self.hash_vals[3], X[i], 3)
            self.round_one_func(3, self.hash_vals[0], self.hash_vals[1],
                self.hash_vals[2], X[i+1], 7)
            self.round_one_func(2, self.hash_vals[3], self.hash_vals[0],
                self.hash_vals[1], X[i+2], 11)
            self.round_one_func(1, self.hash_vals[2], self.hash_vals[3],
                self.hash_vals[0], X[i+3], 19)

        return

    def round_two_func(self, idx_to_ch, b, c, d, val_x_k, shift):
        self.hash_vals[idx_to_ch] = self.hash_vals[idx_to_ch] + \
            Majority(b,c,d) + val_x_k + 0x5a827999
        self.hash_vals[idx_to_ch] = self.hash_vals[idx_to_ch] & ((1 << 32) - 1)
        self.hash_vals[idx_to_ch] = rotate_left_shift(self.hash_vals[idx_to_ch], shift, 32)
        return

    def round_two(self, X):
        for i in range(4):
            self.round_two_func(0, self.hash_vals[1],self.hash_vals[2],
                self.hash_vals[3], X[i], 3)
            self.round_two_func(3, self.hash_vals[0], self.hash_vals[1],
                self.hash_vals[2], X[i + 4], 5)
            self.round_two_func(2, self.hash_vals[3], self.hash_vals[0],
                self.hash_vals[1], X[i + 8], 9)
            self.round_two_func(1, self.hash_vals[2], self.hash_vals[3],
                self.hash_vals[0], X[i + 12], 13)

        return

    def round_three_func(self, idx_to_ch, b, c, d, val_x_k, shift):
        self.hash_vals[idx_to_ch] = self.hash_vals[idx_to_ch] + \
            Parity(b,c,d) + val_x_k + 0x6ed9eba1
        self.hash_vals[idx_to_ch] = self.hash_vals[idx_to_ch] & ((1 << 32) - 1)
        self.hash_vals[idx_to_ch] = rotate_left_shift(self.hash_vals[idx_to_ch], shift, 32)
        return

    def round_three(self, X):
        for i in [0,2,1,3]:
            self.round_three_func(0, self.hash_vals[1], self.hash_vals[2],
                self.hash_vals[3], X[i], 3)
            self.round_three_func(3, self.hash_vals[0], self.hash_vals[1],
                self.hash_vals[2], X[i + 8], 9)
            self.round_three_func(2, self.hash_vals[3], self.hash_vals[0],
                self.hash_vals[1], X[i + 4], 11)
            self.round_three_func(1, self.hash_vals[2], self.hash_vals[3],
                self.hash_vals[0], X[i + 12], 15)
        return

    def Update(self, msg):
        if type(msg) is str:
            msg = str.encode(msg)
        self.message += msg
        return

    def Sum(self):
        number = int.from_bytes(self.message, byteorder='big')
        blocks = self.parse_to_blocks()
        for idx, block in enumerate(blocks):
            saved_vals = []
            for i in range(len(self.hash_vals)):
                saved_vals.append(self.hash_vals[i])
            X = []
            for i in range(15, -1, -1):
                # reverse the order, this is so stupid
                word = (block >> (i *32)) & ((1 << 32) - 1)
                # function padd_message already switches the length bits correctly
                if idx == len(blocks) - 1 and (i == 1 or i == 0):
                    X.append(word)
                else:
                    reversed = 0
                    for j in range(4):
                        byte_of_word = (word >> (8 * j)) & ((1 << 8) - 1)
                        reversed += (byte_of_word << (8 * (3 - j)))
                    X.append(reversed)
            # ROUND 1
            self.round_one(X)
            # ROUND 2
            self.round_two(X)
            # ROUND 3
            self.round_three(X)
            for i in range(len(self.hash_vals)):
                self.hash_vals[i] = (self.hash_vals[i] + saved_vals[i]) & ((1 << 32) - 1)
        final_res = bytearray(16)
        for i in range(0, 16, 4):
            state_idx = i // 4
            # great, reversing order again
            final_res[i] = self.hash_vals[state_idx] & 0xff
            final_res[i+1] = (self.hash_vals[state_idx] >> 8) & 0xff
            final_res[i+2] = (self.hash_vals[state_idx] >> 16) & 0xff
            final_res[i+3] = (self.hash_vals[state_idx] >> 24) & 0xff

        return final_res

def main():
    # test1
    test1 = MD4()
    test1.Update("1234567890" * 8)
    result1 = test1.Sum()
    print(result1)
    result_hex = int.from_bytes(result1, byteorder='big')
    print(hex(result_hex))
    return

if __name__ == "__main__":
    main()
