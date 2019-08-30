import crypto_pals.set5.mult_group_mod_p as GroupOp 
import random # note, this if for fun which is why I'm not 
# using the secrets library

# to produce a modulus of size n need to have two primes
# about size n/2 ??? but taking this exactly is a terrible idea
def generate_RSA_key(bit_size_modulus, primes=None):
    if primes:
        p = primes[0]
        q = primes[1]
    else:  
        desired_prime_size = (bit_size_modulus+1) // 2
        p = GroupOp.generate_prime(desired_prime_size)
        q = GroupOp.generate_prime(desired_prime_size)
        while p == q or GroupOp.find_totient(p*q, [(p, 1), (q,1)]) % 3 == 0:
            q = GroupOp.generate_prime(desired_prime_size)
     
    print("Primes p and q are {} and {}".format(p, q))
    n = p * q
    assert(n.bit_length() >= bit_size_modulus)

    group_of_mult_inv = GroupOp.find_totient(n, [(p, 1), (q,1)])
    import pdb; pdb.set_trace()
    assert(group_of_mult_inv == ((p -1) *(q-1)))
    e = 3
    d = GroupOp.find_inverse(e, group_of_mult_inv)
    
    pub_key = (n, e)
    priv_key = (n, d)

    return pub_key, priv_key

def encrypt(pub_key, message):
    print("BEGIN ENCRYPT")
    if type(message) is str or type(message) is bytes:
        if type(message) is str:
            message = message.encode()
        msg_as_number = int.from_bytes(message, byteorder="big")
    elif type(message) is int:
        msg_as_number = message
    mod, e = pub_key[0], pub_key[1]
    print("Message before encryption as a number is {}".format(hex(msg_as_number)))
    if msg_as_number > mod:
        raise ValueError("Message must be in range of the modulus")
    ct = GroupOp.mod_exp(msg_as_number, e, mod)
    print("Ciphertext is {}".format(hex(ct)))
    ct = ct.to_bytes((ct.bit_length() + 7) // 8, byteorder="big")
    return ct
     
def decrypt(priv_key, ciphertext):
    print("BEGIN DECRYPT")
    cipherint = int.from_bytes(ciphertext, byteorder="big")
    print("Ciphertext as an integer is {}".format(hex(cipherint)))
    mod, d = priv_key[0], priv_key[1]
    pt = GroupOp.mod_exp(cipherint, d, mod)
    print("Message decrypted as a number {}".format(hex(pt)))
    pt = pt.to_bytes((pt.bit_length() + 7) // 8, byteorder="big")
    return pt

if __name__ == "__main__":
    public_key, private_key = generate_RSA_key(512)

    msg = "H" 
    ct = encrypt(public_key, msg)
    decrypted_pt = decrypt(private_key, ct)
    print("Decrypted plaintext {} and message {}".format(decrypted_pt, msg))
