# Contains fast exponentiation implementation and other functions for working with 
# groups

# note that this modular exponentiation is pretty broken --- it has a timing side channel
def mod_exp(base, exponent, modulus):
    curr_val = base % modulus
    return_val = 1
    for i in range(exponent.bit_length()):
        if (((exponent >> i) & 1) == 1):
            return_val *= curr_val
            if return_val > modulus:
                return_val = return_val % modulus
        curr_val = (curr_val * curr_val) % modulus         
    return return_val

def millerRabinPrimalityTest(number_to_tst):
    powers_of_two = 0
    prime_powers = number_to_tst - 1
    while prime_powers & 1 == 0:
        powers_of_two += 1
        prime_powers = prime_powers >> 1

    for iteration in range(10):
        test_base = secrets.randbelow(number_to_tst)
        current_it = prime_powers
        up_base = mod_exp(test_base, current_it, number_to_tst)
        if up_base == 1 or up_base == (number_to_tst - 1):
            continue
        # check for 1 or -1 at a^d and then check for a^(2^i*d) for i through 1 to 
        found_neg = False
        for i in range(powers_of_two):
            up_base = (up_base * 2) % number_to_tst
            if up_base == number_to_tst - 1:
                found_neg = True
                break
        if found_neg:
            continue
        return False
    return True

def generate_prime_and_generator():
    prime = 256
    prime += random.getrandbits(256)
    while prime % 2 == 0 or millerRabinPrimalityTest(prime):
        prime = 256
        prime += random.getrandbits(256)
    # this is not a safe prime 
    generator = random.randrange(prime)
    return (prime, generator)
