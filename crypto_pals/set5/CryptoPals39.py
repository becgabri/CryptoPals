import crypto_pals.set5.mult_group_mod_p as GroupOp 
import random # note, this if for fun which is why I'm not 
# using the secrets library

def generate_prime(bit_size_of_prime):
    prime = 2**(bit_size_of_prime)
    prime += random.getrandbits(bit_size_of_prime)
    while prime % 2 == 0 or not GroupOp.millerRabinPrimalityTest(prime):
        prime = 2**(bit_size_of_prime)
        prime += random.getrandbits(bit_size_of_prime)
    return prime

# factorization:
# a list of tuples of the form [(p_i, r_i)]
# where modulus = p_1^r_1 * p_2^r_2 * ... p_k^r_k
# totient is calculated as 
# totient = n * (1 - 1/p_1)^r_1 * (1 - 1/p_2)^r_2 ...
# and so on
def find_totient(modulus, factorization):
    totient = modulus
    for prime, exponent in factorization:
        totient *= (1 - (1 / prime))**exponent
    return int(totient)


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

# to produce a modulus of size n need to have two primes
# about size n/2 ??? but taking this exactly is a terrible idea
def generate_RSA_key(bit_size_modulus, primes=None):
    if primes:
        p = primes[0]
        q = primes[1]
    else:  
        desired_prime_size = (bit_size_modulus+1) // 2
        p = generate_prime(desired_prime_size)
        q = generate_prime(desired_prime_size)
        while p == q or find_totient(p*q, [(p, 1), (q,1)]) % 3 == 0:
            q = generate_prime(desired_prime_size)
     

    n = p * q
    assert(n.bit_length() >= bit_size_modulus)

    group_of_mult_inv = find_totient(n, [(p, 1), (q,1)])
    e = 3
    d = find_inverse(e, group_of_mult_inv)
    
    pub_key = (n, e)
    priv_key = (n, d)
    return pub_key, priv_key

def encrypt(pub_key, message):
    if type(message) is str or type(message) is bytes:
        if type(message) is str:
            message = message.encode()
        msg_as_number = int.from_bytes(message, byteorder="big")
    elif type(message) is int:
        msg_as_number = message
    mod, e = pub_key[0], pub_key[1]
    if msg_as_number > mod:
        raise ValueError("Message must be in range of the modulus")
    ct = GroupOp.mod_exp(msg_as_number, e, mod)
    ct = ct.to_bytes((mod.bit_length() + 7) // 8, byteorder="big")
    return ct
     
def decrypt(priv_key, ciphertext):
    cipherint = int.from_bytes(ciphertext, byteorder="big")
    mod, d = priv_key[0], priv_key[1]
    pt = GroupOp.mod_exp(cipherint, d, mod)
    pt = pt.to_bytes((mod.bit_length() + 7) // 8, byteorder="big")
    return pt.strip(b'\x00')

if __name__ == "__main__":
    public_key, private_key = generate_RSA_key(8)
    msg = "H" 
    import pdb; pdb.set_trace()
    ct = encrypt(public_key, msg)
    decrypted_pt = decrypt(private_key, ct)
    print("Decrypted plaintext {} and message {}".format(decrypted_pt, msg))
