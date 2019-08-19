#### SHA 256 CONSTANTS ####
# size of blocks in bits
BLOCK_SIZE = 512
WORD_SIZE = 32
BLOCK_SIZE_IN_BYTES = BLOCK_SIZE >> 3
#### SHA 256 OPERATORS FUNCTIONING ON 32 BITS
import copy

def debug_oversize(*x):
    for word in x:
        if (word >> 32) > 0:
            raise ValueError("Rotate right takes words of <= 32 bits")

# rotate the 32 bit word x by y 
def rotr(x, y):
    debug_oversize(x)
    end = x & ((1 << y) - 1)
    total = x >> y
    total |= (end << (32 - y))
    return total

def ch(x,y,z):
    debug_oversize(x,y,z)
    return (x & y) ^ (~x & z) 

def maj(x,y,z):
    debug_oversize(x,y,z)
    return (x & y) ^ (y & z) ^ (x & z)

def sigma0(x):
    val = rotr(x,2) ^ rotr(x,13) ^ rotr(x,22)
    return val

def sigma1(x):
    val = rotr(x,6) ^ rotr(x, 11) ^ rotr(x,25)
    return val

def phi0(x):
    val = rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)
    return val

def phi1(x):
    val = rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)
    return val

INITIAL_HASHES = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372,
    0xa54ff53a, 0x510e527f, 0x9b05688c,
    0x1f83d9ab, 0x5be0cd19
]

class SHA256:
    def __init__(self):
        self.hash_vals = copy.copy(INITIAL_HASHES)
        self.constants = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
            0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
            0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
            0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
            0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        ]

        self.msg_blocks = 0
        self.current_message = b""

    #### #####
    # SHA 256 PADDING
    def padd(self):
        length_in_bytes = len(self.current_message)
        actual_msg_len = length_in_bytes*8
        if actual_msg_len > (1 << 64):
            raise ValueError("Message must be less than 2*64 in length")
        quot = length_in_bytes // BLOCK_SIZE_IN_BYTES
        rem = length_in_bytes - (quot * BLOCK_SIZE_IN_BYTES)
        x = self.current_message[quot*BLOCK_SIZE_IN_BYTES:]
        x_as_an_int = 0
        for i in range(rem-1, -1, -1):
            x_as_an_int += x[i] << ((rem - 1 - i)*8)
        num_zeroes = (448 - (rem * 8) - 1) % 512
        padded_msg = (x_as_an_int << 1) | 1
        padded_msg = padded_msg << num_zeroes
        padded_msg = (padded_msg << 64) | actual_msg_len
        #assert(padded_msg < (1 << BLOCK_SIZE))
        number_blocks = BLOCK_SIZE_IN_BYTES if padded_msg.bit_length() <= BLOCK_SIZE else 2*BLOCK_SIZE_IN_BYTES
        self.current_message = self.current_message[:self.msg_blocks*BLOCK_SIZE_IN_BYTES] + padded_msg.to_bytes(number_blocks, byteorder="big")
        return

    def prepare_word_schedule(self, word_schedule):
        word_mask = (1 << 32) - 1
        for t in range(16, 64):
            res = (phi1(word_schedule[t-2]) + word_schedule[t-7]) & word_mask
            res = (res + phi0(word_schedule[t-15])) & word_mask
            res = (res + word_schedule[t-16]) & word_mask
            word_schedule.append(res)
        return

    # starting idx specifies starting idx into the byte array of the current message
    def process_blocks(self, starting_idx):
        word_mask = (1 << 32) - 1
        # turn the bytes to integers
        total_to_process = ((len(self.current_message) - starting_idx)*8) // BLOCK_SIZE
        for i in range(total_to_process):
            # 512 bits = 2**9 / 2**3 = 2**6 = 64 bytes wow.... 
            byte_section = self.current_message[starting_idx + BLOCK_SIZE_IN_BYTES*i: starting_idx + (BLOCK_SIZE_IN_BYTES*(i+1))]
            word_schedule = []
            for itr in range(0,len(byte_section), 4):
                word = int.from_bytes(byte_section[itr:itr+4], byteorder="big")
                word_schedule.append(word)
            
            self.prepare_word_schedule(word_schedule) 
            assert(len(word_schedule) == 64)

            working_vars = {
                'a': self.hash_vals[0],
                'b': self.hash_vals[1],
                'c': self.hash_vals[2],
                'd': self.hash_vals[3],
                'e': self.hash_vals[4],
                'f': self.hash_vals[5],
                'g': self.hash_vals[6],
                'h': self.hash_vals[7],
            }
            for t in range(64):
                temp_word_one = working_vars['h'] + sigma1(working_vars['e']) & word_mask
                temp_word_one = (temp_word_one + ch(working_vars['e'], working_vars['f'], working_vars['g'])) & word_mask
                temp_word_one = (temp_word_one + self.constants[t]) & word_mask
                temp_word_one = (temp_word_one + word_schedule[t]) & word_mask
                temp_word_two = (sigma0(working_vars['a']) + maj(working_vars['a'], working_vars['b'], working_vars['c'])) & word_mask

                working_vars['h'] = working_vars['g']
                working_vars['g'] = working_vars['f']
                working_vars['f'] = working_vars['e']
                working_vars['e'] = (working_vars['d'] + temp_word_one) & word_mask
                working_vars['d'] = working_vars['c']
                working_vars['c'] = working_vars['b']
                working_vars['b'] = working_vars['a']
                working_vars['a'] = (temp_word_one + temp_word_two) & word_mask

            self.hash_vals[0] = (self.hash_vals[0] + working_vars['a']) & word_mask
            self.hash_vals[1] = (self.hash_vals[1] + working_vars['b']) & word_mask
            self.hash_vals[2] = (self.hash_vals[2] + working_vars['c']) & word_mask
            self.hash_vals[3] = (self.hash_vals[3] + working_vars['d']) & word_mask
            self.hash_vals[4] = (self.hash_vals[4] + working_vars['e']) & word_mask
            self.hash_vals[5] = (self.hash_vals[5] + working_vars['f']) & word_mask
            self.hash_vals[6] = (self.hash_vals[6] + working_vars['g']) & word_mask
            self.hash_vals[7] = (self.hash_vals[7] + working_vars['h']) & word_mask

        return total_to_process

    def Update(self, msg):
        if not type(msg) is bytes:
            raise TypeError("Can only update with byte values")
        current_rem = (len(self.current_message)*8) - (self.msg_blocks * 512) 
        self.current_message += msg
        total_added = current_rem + (len(msg)*8) 
        if total_added > BLOCK_SIZE:
            # 1 block = 512 bits = 64 bytes 
            idx = self.msg_blocks * BLOCK_SIZE_IN_BYTES
            number_of_blocks = self.process_blocks(idx)
            self.msg_blocks = self.msg_blocks + number_of_blocks
        return

    def Sum(self):
        self.padd()
        # need to process last block now and        
        blocks = self.process_blocks(self.msg_blocks*BLOCK_SIZE_IN_BYTES)
        
        # take the internal hash values and flip them
        final_res = 0
        for i in range(len(self.hash_vals)):
            final_res += self.hash_vals[i] << ((len(self.hash_vals) - 1 - i)*WORD_SIZE)
        return final_res

def test():
    test1 = SHA256()
    test1.Update(b"abc")
    hex_res = hex(test1.Sum())
    print("Test 'abc': {}".format(hex_res))
    test2 = SHA256()
    test2.Update(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
    hex_res_two = hex(test2.Sum())
    print("Test 'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq': {}".format(hex_res_two))
   
if __name__ == "__main__":
    test()
