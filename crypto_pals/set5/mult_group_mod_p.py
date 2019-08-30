#import secrets ( don't need to use this library for now :P)
import random 
# Contains fast exponentiation implementation and other functions for working with 
# groups

# note that this modular exponentiation is pretty broken --- it has a timing side channel
def mod_exp(base, exponent, modulus):
    curr_val = base % modulus
    return_val = 1
    total_num_bits = exponent.bit_length()
    for bit in range(total_num_bits):
        if (((exponent >> bit) & 1) == 1):
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

    for iteration in range(15):
        test_base = random.randrange(number_to_tst)
        #secrets.randbelow(number_to_tst)
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

def generate_prime(bit_size_of_prime):
    prime = 2**(bit_size_of_prime)
    prime += random.getrandbits(bit_size_of_prime)
    while prime % 2 == 0 or not millerRabinPrimalityTest(prime):
        prime = 2**(bit_size_of_prime)
        prime += random.getrandbits(bit_size_of_prime)
    return prime

def generate_prime_and_generator():
    prime = 2**256
    prime += random.getrandbits(256)
    while prime % 2 == 0 or millerRabinPrimalityTest(prime):
        prime = 2**256
        prime += random.getrandbits(256)
    # this is not a safe prime, this is not necessarily a generator
    # for the whole group !!!
    generator = random.randrange(prime)
    return (prime, generator)

def find_s_and_t_euclid(left, right, state_block):
    if right == 0:
        return left

    quot = left // right 
    rem = left % right

    left = right
    right = rem

    new_x = state_block[0]['x'] - (quot * state_block[1]['x'])
    new_y = state_block[0]['y'] - (quot * state_block[1]['y'])
    state_block[0] = state_block[1]
    state_block[1] = {'x': new_x,'y': new_y}

    return find_s_and_t_euclid(left, right, state_block)


def find_inverse(number, modulus):
    state_block = [{'x': 1, 'y': 0},{'x': 0, 'y': 1}]
    gcd = find_s_and_t_euclid(modulus, number, state_block)
    if gcd != 1:
        raise ValueError("Number has no inverse in modulus")

    return state_block[0]['y'] % modulus

def find_gcd(a, b):
    if a == 0 and b == 0:
        raise ValueError("The gcd of 0 and 0 is undefined")
    if b == 0:
        return a
    return find_gcd(b, a % b)

# factorization:
# a list of tuples of the form [(p_i, r_i)]
# where modulus = p_1^r_1 * p_2^r_2 * ... p_k^r_k
# totient is calculated as 
# totient = n * (1 - 1/p_1) * (1 - 1/p_2) ...
# or totient = (p_1 - 1)*p_1^(r_1-1) * (p_2 - 1)*p_1^r_2-1 ... and so on
# and so on
def find_totient(modulus, factorization):
    if modulus == 0:
        raise ValueError("Totient of 0 is not defined")
    totient = 1
    for prime, exponent in factorization: 
        totient *= (prime - 1)*(prime**(exponent-1))
    return totient

