import crypto_pals.set5.mult_group_mod_p as GroupOp
import crypto_pals.set6.CryptoPals43 as CP43
import crypto_pals.set5.sha256 as sha256
import crypto_pals.set4.SHA1 as sha1
import random

challenge_params = {
    "p": 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1,
    "q": 0xf4f47f05794b256174bba6e9b396a7707e563c5b,
    "g": 0x0
}
challenge_public_key = 0x2d026f4bf30195ede3a088da85e398ef869611d0f68f0713d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b85519b1c23cc3ecdc6062650462e3063bd179c2a6581519f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d32971c3de5084cce04a2e147821
recovered_priv_key = 0xf1b733db159c66bce071d21e044a48b0e4c1665a

# COPY PASTA with a bad implementation
def insecureSign(params, private_key, message):
    k = random.randrange(1, params["q"])
    r = GroupOp.mod_exp(params["g"], k, params["p"]) % params["q"]

    init_hash = sha1.SHA1()
    init_hash.Update(message)
    hashed_msg_val = int.from_bytes(init_hash.Sum(), byteorder="big") % params["q"]
    k_inv = GroupOp.find_inverse(k, params["q"])
    s = (k_inv * (hashed_msg_val + private_key * r)) % params["q"]

    return (r, s)

def insecureVerify(params, public_key, message, tag):
    r, s = tag[0], tag[1]
    
    hash_obj = sha256.SHA256()
    hash_obj.Update(message)
    msg_hash = hash_obj.Sum() % params["q"]
    s_inv = GroupOp.find_inverse(s, params["q"])
    arg1 = GroupOp.mod_exp(params["g"], (s_inv * msg_hash) % params["q"], params["p"])
    arg2 = GroupOp.mod_exp(public_key, (r * s_inv) % params["q"], params["p"])
    lhs = ((arg1*arg2) % params["p"]) % params["q"]
    return (lhs == r)

def main():
    global challenge_params
    
    # assuming we want to keep the same public key because if we didn't
    # and it was based on the bogus generator then we have big problems


    tag = insecureSign(challenge_params, recovered_priv_key, b"A message")

    # r will be 0 here, s will be k^inv * H(msg)
    # but it really doesn't matter, because the other side needs to 
    #  find the inverse of s so as long as s is invertible, you'll
    # validate. This signature would "work" for every message and moreover
    # ANYTHING will work as long as r=0 and s is invert.
    message = b"If music be the food of love, play on; Give me excess of it, that, surfeiting,The appetite may sicken, and so die. --Twelfth Night"
    res = insecureVerify(challenge_params, challenge_public_key,  message, (0, 0xdeadbeef))
    print("Generator g = 0\n")
    print("Message: {}, Sig: (0x{:x},0x{:x}), Result: {}".format(message, 0, 0xdeadbeef, res))
    # change the generator is p+1 and not 
    challenge_params["g"] = challenge_params["p"] + 1
    # I'm going to assume the key was genereated honestly, because if it wasn't
    # we would get g**x = (p+1)**x mod p which is just 1
    
    choose_random = random.randrange(1, challenge_params["q"])
    r = GroupOp.mod_exp(challenge_public_key, choose_random, challenge_params["p"]) % challenge_params["q"]
    s = (r * GroupOp.find_inverse(choose_random, challenge_params["q"])) % challenge_params["q"]
    result = insecureVerify(challenge_params, challenge_public_key, b"Hello, world", (r,s))
    res2 = insecureVerify(challenge_params, challenge_public_key, b"Goodbye, world", (r,s))
    print("Generator g = p + 1")
    print("Message: {}, Random val: 0x{:x}, Sig: (0x{:x},0x{:x}), Result: {}".format(b"Hello, world", choose_random, r, s, result))
    print("Message: {}, Random val: 0x{:x}, Sig: (0x{:x}, 0x{:x}), Result: {}".format(b"Goodbye, world", choose_random, r, s, res2))
    return

if __name__ == "__main__":
    main()
