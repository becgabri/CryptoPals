#import secrets
import secrets
import random
from crypto_pals.set4 import SHA1
GENERATOR = 2 
PRIME = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
#PRIME = 11
# note that this modular exponentiation is pretty broken --- it has a timing side channel
def mod_exp(base, exponent, modulus):
    curr_val = base
    return_val = 1
    for i in range(exponent.bit_length()):
        if (((exponent >> i) & 1) == 1):
            return_val *= curr_val
            if return_val > modulus:
                return_val = return_val % modulus
        curr_val = (curr_val * base) % modulus         
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

def generate_public_key(generator, prime):
    secret_val = random.getrandbits(prime.bit_length())
    if secret_val > prime:
        secret_val = secret_val ^ prime
    assert secret_val < prime
    public_val = mod_exp(generator, secret_val, prime)
    assert public_val < prime
    return (secret_val, public_val)

def generate_shared_key(secret_val, public_val_from_other, prime):
    print("Secret value is {}, shared value is {}".format(secret_val, public_val_from_other))
    shared_key = mod_exp(public_val_from_other, secret_val, prime)
    print(shared_key)
    assert shared_key < prime
    hash_feed = SHA1.SHA1()
    hash_feed.Update(shared_key.to_bytes(shared_key.bit_length() + 7 // 8, byteorder='big'))
    return hash_feed.Sum()

def main():
    global PRIME
    global GENERATOR
    # prime, gen = generate_prime_and_generator()
    # PRIME = prime
    # GENERATOR = gen
    alice_secret, alice_public = generate_public_key(GENERATOR, PRIME)
    bob_secret, bob_public = generate_public_key(GENERATOR, PRIME)
    alice_shared = generate_shared_key(alice_secret, bob_public, PRIME)
    bob_shared = generate_shared_key(bob_secret, alice_public, PRIME)
    # may want to convert this to hex
    print("Alice's half: {} , Bob's half: {}".format(alice_shared, bob_shared))
    return 


if __name__ == "__main__":
    main()
