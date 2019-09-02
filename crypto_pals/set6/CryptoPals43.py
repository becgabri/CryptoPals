import crypto_pals.set5.mult_group_mod_p as GroupOp
import crypto_pals.set5.sha256 as sha256
import crypto_pals.set4.SHA1 as sha1
import random

# added a smaller pair because I'm just testing
ACCEPTABLELNPAIRS = [(1024, 160), (256, 42)]

def generate_generator(prime_p, prime_q):
    g = 1
    while g == 1:
        h = random.randrange(1, prime_p)
        g = GroupOp.mod_exp(h, (prime_p - 1) // prime_q, prime_p)
    return g

# uses SHA256 to generate primes
def SecurePrimeGroupGen(seedlen, l_len, n_len):
    if seedlen < n_len:
        raise ValueError("You are compromising security by making seed length smaller than output of the hash function")
    if not (l_len, n_len) in ACCEPTABLELNPAIRS:
        raise ValueError("Improper bit lengths for primes p and q")
    num_blocks = (l_len - 1) // sha256.OUTPUT_SIZE
    rem = l_len - 1  - (num_blocks * sha256.OUTPUT_SIZE)

    
    found_q = False
    found_p = False
    while not found_q and not found_p:
        seed = random.randrange(2**seedlen, 2**(seedlen+1))
        hash_obj = sha256.SHA256()
        hash_obj.Update(seed.to_bytes(seedlen, byteorder="big"))
        u = hash_obj.Sum() % 2**(n_len-1)
        potential_q = 2**(n_len-1) + u + 1 + (u % 2) 
        if GroupOp.millerRabinPrimalityTest(potential_q):
            found_q = True

        if found_q:
            # use this to try and find a p -- must be same seed from earlier
            offset = 1
            for itr in range(4*l_len):
                # try and define V
                W = 0
                for i in range(num_blocks):
                    itr_hash = sha256.SHA256()
                    inner_num = seed + i + offset
                    itr_hash.Update(inner_num.to_bytes(inner_num + 7 // 8, byteorder="big"))
                    W += itr_hash.Sum() << (sha256.OUTPUT_SIZE *i) 
                rem_padd = seed + num_blocks + offset
                final_hash = sha256.SHA256()
                final_hash.Update(rem_padd.to_bytes(rem_padd.bit_length() + 7 // 8, byteorder="big"))
                final_add = final_hash.Sum() & (( 1 << rem) - 1) 
                W += final_add << (num_blocks * sha256.OUTPUT_SIZE)
                 
                possible_prime_p = W + 2**(l_len - 1)
                rem_in_mod = possible_prime_p % (2 * potential_q)
                possible_prime_p = possible_prime_p - (rem_in_mod - 1)
                # check if it's prime
                if GroupOp.millerRabinPrimalityTest(possible_prime_p):
                    g = generate_generator(possible_prime_p, potential_q)
                    assert(possible_prime_p.bit_length() == l_len and potential_q.bit_length() == n_len)
                    return (possible_prime_p, potential_q, g)
                offset = offset + num_blocks + 1
        found_q = False 
        offset = 1   



def DSAParamGen(bit_length_n, bit_length_l):
    p, q, g = SecurePrimeGroupGen(bit_length_n, bit_length_l, bit_length_n)
    print("Saving parameters from generation....\n p: 0x{:x}\nq: 0x{:x}\ng: 0x{:x}\n".format(p, q, g))
    return {"p": p, "q": q, "g": g}

def DSAKeyGen(params, print_x=False):
    private_key = random.randrange(1, params["q"])
    public_key = GroupOp.mod_exp(params["g"], private_key, params["p"])
    if print_x:
        print("Secret key was {:x}".format(private_key))
    return public_key, private_key

def DSASign(params, private_key, message, print_k=False, k=0):
    r = 0 
    s = 0
    while r == 0 and s == 0:
        if k == 0:
            k = random.randrange(1, params["q"])
        if print_k:
            print("K value is {:x}".format(k))
        r = GroupOp.mod_exp(params["g"], k, params["p"]) % params["q"]
        
        if r != 0:
            init_hash = sha1.SHA1()
            init_hash.Update(message)
            hashed_msg_val = int.from_bytes(init_hash.Sum(), byteorder="big") % params["q"]
            k_inv = GroupOp.find_inverse(k, params["q"])
            s = (k_inv * (hashed_msg_val + private_key * r)) % params["q"]

    return (r, s)

def DSAVerify(params, public_key, message, tag):
    r, s = tag[0], tag[1]
    if r <= 0 or r >= params["q"] or s >= params["q"] or s <= 0:
        return False
    hash_obj = sha256.SHA256()
    hash_obj.Update(message)
    msg_hash = hash_obj.Sum() % params["q"]
    s_inv = GroupOp.find_inverse(s, params["q"])
    arg1 = GroupOp.mod_exp(params["g"], (s_inv * msg_hash) % params["q"], params["p"])
    arg2 = GroupOp.mod_exp(public_key, (r * s_inv) % params["q"], params["p"])
    lhs = ((arg1*arg2) % params["p"]) % params["q"]
    return (lhs == r)

def AttackerWithKnownSubKeyK(params, public_key, k, msg, msg_sig, msg_hash=None):
    recover_x = (msg_sig[1] * k) % params["q"]
    if not msg_hash:
        hash_obj = sha1.SHA1()
        hash_obj.Update(msg)
        msg_as_int = int.from_bytes(hash_obj.Sum(), byteorder="big")
    else:
        msg_as_int = msg_hash
    recover_x = (recover_x - (msg_as_int % params["q"])) % params["q"]
    recover_x = recover_x * (GroupOp.find_inverse(msg_sig[0], params["q"]))
    return recover_x % params["q"]


def main():
    """
    parameters = DSAParamGen(42, 256)
    pub_key, priv_key = DSAKeyGen(parameters)
    test_msg = b"Lost Lenore"
    tag = DSASign(parameters, priv_key, test_msg)  
    verify = DSAVerify(parameters, pub_key, test_msg, tag)

    if verify:
        print("Passed simple test")
    else:
        print("Failed simple test")

    print("Attempting to use stolen attacker knowledge to recover the private key...")
    for i in range(3):
        temp_pub_key, temp_priv_key = DSAKeyGen(parameters, print_x=True)
        msg = input("Type in message to sign: ").encode("utf-8")
        tag = DSASign(parameters, temp_priv_key, msg, print_k=True)
        k_val = input("Give k value in hex: 0x")
        k = int("0x" + k_val, 16)
        recovered_private_key = AttackerWithKnownSubKeyK(parameters, temp_pub_key, k, msg, tag)
        print("Recovered secret key was {:x}".format(recovered_private_key))
    """
    print("Attempting to crack private key from challenge...")
    msg_str = "For those that envy a MC it can be hazardous to your health\nSo be friendly, a matter of life and death, just like a etch-a-sketch\n"
    print("Checking to make sure the message string is correct...")
    hash_obj = sha1.SHA1()
    hash_obj.Update(msg_str.encode('utf-8'))
    result_hash = int.from_bytes(hash_obj.Sum(), byteorder="big")
    if not hex(result_hash) == "0xd2d0714f014a9784047eaeccf956520045c45265":
        raise ValueError("Object hash is incorrect")

    challenge_tag = (548099063082341131477253921760299949438196259240, 857042759984254168557880549501802188789837994940)

    challenge_params = {
        "p": 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1,
        "q": 0xf4f47f05794b256174bba6e9b396a7707e563c5b,
        "g": 0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291
    }
    challenge_public_key = 0x84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17
    sha_key_fp = 0x0954edd5e0afe5542a4adf012611a91912a3ec16
    for i in range(0, 2**16):
        selector = GroupOp.mod_exp(challenge_params["g"], i, challenge_params["p"]) % challenge_params["q"]
        if selector == challenge_tag[0]:
            print("Calculated a correct r value!")
            # test k 
            potential_priv_key = AttackerWithKnownSubKeyK(challenge_params, challenge_public_key, i, msg_str, challenge_tag, result_hash)
            key_obj = sha1.SHA1()
            string_feed = hex(potential_priv_key)[2:]
            key_obj.Update(string_feed)
            key = int.from_bytes(key_obj.Sum(), byteorder="big")
            print("Key fp is {:x}".format(key))
            compute_tag = DSASign(challenge_params, potential_priv_key, msg_str.encode("utf-8"), False, i)
            if compute_tag[1] == challenge_tag[1]:
                print("Success! Key is {}".format(potential_priv_key))
                return
            else:
                print("Failure, correct r but incorrect s")
 
    return

if __name__ == "__main__":
    main()
