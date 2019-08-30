# CRT
import crypto_pals.set5.mult_group_mod_p as GroupOp
import crypto_pals.set5.CryptoPals39 as RSAOps

# we use CRT to get a large value
# assumption: all of these moduli are relatively prime with one another
# CRT only works if this is the case, and if it wasn't true then we can 
# break RSA by running gcd across the list of moduli and recovering the primes 
# used in key generation
def crt_reconstruct(modulus_one, modulus_two, modulus_three, rem_one, rem_two, rem_three):
    large_mod = modulus_one * modulus_two * modulus_three
    crt_factor = (modulus_one * modulus_two) + \
        (modulus_two*modulus_three) + \
        (modulus_one*modulus_three)
    crt_factor = crt_factor % large_mod
    crt_factor_inv = GroupOp.find_inverse(crt_factor, large_mod)
    mod_one_factor = (crt_factor_inv * modulus_two* modulus_three * rem_one) 
    mod_two_factor = (crt_factor_inv * modulus_three * modulus_one * rem_two)
    mod_three_factor = (crt_factor_inv * modulus_two * modulus_one * rem_three)
    reconstructed_ct_value = (mod_two_factor + mod_one_factor + mod_three_factor) % large_mod
    return reconstructed_ct_value 

def main():
    print("Testing CRT reconstruction...")
    same_msg = "H"

    pub_key1, priv_key1 = RSAOps.generate_RSA_key(8, [41,23])
    pub_key2, priv_key2 = RSAOps.generate_RSA_key(8, [53,89])
    pub_key3, priv_key3 = RSAOps.generate_RSA_key(8, [71,17])

    ct1 = RSAOps.encrypt(pub_key1, same_msg)
    ct2 = RSAOps.encrypt(pub_key2, same_msg)
    ct3 = RSAOps.encrypt(pub_key3, same_msg)

    ct_as_large = crt_reconstruct(pub_key1[0], pub_key2[0], pub_key3[0],
            int.from_bytes(ct1, byteorder="big"), int.from_bytes(ct2, byteorder="big"),
            int.from_bytes(ct3, byteorder="big"))
    plaintext_recovered = int(round(ct_as_large**(1/3.0)))
    res = plaintext_recovered.to_bytes((plaintext_recovered.bit_length() + 7) // 8,byteorder="big" )
    print("Plaintext was {}, recovered plaintext by attacker was {}".format(same_msg, res))
if __name__ == "__main__":
    main()
