import random

class MersenneTwister19937:
    def __init__(self, seed):
        self.parameters = {
            'a': 0x9908B0DF,
            'm': 397,
            'r': 31,
            'word_size': 32,
            'recurrence_deg': 624,
            'u': 11,
            'd': 0xFFFFFFFF,
            's': 7,
            'b': 0x9D2C5680,
            't': 15,
            'c': 0xEFC60000,
            'l': 18,
            'init_cons': 1812433253
        }
        self.lower_mask = (1 << self.parameters['r']) - 1
        self.upper_mask = (~self.lower_mask) & ((2**self.parameters['word_size']) - 1)
        self.state = self.initialize_state_from_seed(seed)

    def initialize_state_from_seed(self, seed_num):
        # need n values of word size each
        self._idx = self.parameters['recurrence_deg']
        word_mask = (2**self.parameters["word_size"]) - 1
        state_arr = [0] * self.parameters["recurrence_deg"]
        state_arr[0] = seed_num
        for i in range(1, self.parameters["recurrence_deg"]):
            prev = state_arr[i - 1]
            quant = prev ^ (prev >> (self.parameters["word_size"] - 2))
            quant = (self.parameters["init_cons"] * quant) + i
            state_arr[i] = quant & word_mask
        return state_arr

    # generate the next n values
    def twist(self):
        for idx in range(0, self.parameters["recurrence_deg"]):
            curr_x_upper = self.state[idx] & self.upper_mask
            x = curr_x_upper + (self.state[(idx+1) % self.parameters["recurrence_deg"]] & self.lower_mask)
            xA = x >> 1
            if x % 2 != 0:
                xA = xA ^ self.parameters['a']
            self.state[idx] = self.state[(idx + self.parameters["m"]) % self.parameters["recurrence_deg"]] ^ xA
        self._idx = 0

    def extract_num(self):
        if self._idx >= self.parameters["recurrence_deg"]:
            self.twist()

        extracted_bits = self.state[self._idx]
        extracted_bits = extracted_bits ^ ((extracted_bits >> self.parameters["u"]) & self.parameters['d'])
        extracted_bits = extracted_bits ^ ((extracted_bits << self.parameters["s"]) & self.parameters['b'])
        extracted_bits = extracted_bits ^ ((extracted_bits << self.parameters["t"]) & self.parameters["c"])
        extracted_bits = extracted_bits ^ (extracted_bits >> self.parameters['l'])

        self._idx = self._idx + 1
        return extracted_bits & ((2**self.parameters["word_size"]) - 1)

    def overwrite_state(self, new_state):
        self.state = new_state
        self._idx = self.parameters['recurrence_deg']

def main():
    twister = MersenneTwister19937(1)
    random.seed(0b1)
    r0 = random.getstate()
    
    for poll in range(0,5):
        extracted_value = twister.extract_num()
        print("Poll Number {} with twister value {}".format(poll, extracted_value))

    for poll in range(0, 5):
        # extract from python random library as much as a word 32 bits
        extract = random.getrandbits(32)
        print("Extracted from random library twister value of {}".format(extract))
    print("*** Results are not the same because seed initialization differs")
    return

if __name__ == "__main__":
    main()
