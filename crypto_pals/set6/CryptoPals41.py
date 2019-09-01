import crypto_pals.set5.CryptoPals39 as CP39
import crypto_pals.set5.sha256 as sha256
import crypto_pals.set5.mult_group_mod_p as GroupOp
import time
import random

PRIV_KEY = None
PUBLIC_KEY = None
RSA_EXPORT_GRADE = 512
time_interval = 180

RECENT_TRIES = {}
def recovery_oracle(submitted_ciphertext):
    current_time = time.time()
    for item, val in RECENT_TRIES.items():
        if (val + time_interval) < current_time:
            del RECENT_TRIES[item]

    sha_spec = sha256.SHA256()
    sha_spec.Update(submitted_ciphertext)
    hash_check_value = sha_spec.Sum()
    if hash_check_value in RECENT_TRIES:
        return "FAILURE"
    # take current time
    msg = CP39.decrypt(PRIV_KEY, submitted_ciphertext)
    #client_message = json.loads(msg.encode("utf-8"))
    #client_message[hash_check_value] = current_time
    return msg

def attacker(pub_key, old_ct):
    #pick a number rel. prime with the modulus
    random_s = random.randrange(1,pub_key[0])
    while GroupOp.find_gcd(random_s, pub_key[0]) != 1:
        random_s = random.randrange(1, pub_key[0])
    inv_s = GroupOp.find_inverse(random_s, pub_key[0])
    old_ct_as_number = int.from_bytes(old_ct, byteorder="big")
    new_ct = (GroupOp.mod_exp(random_s, pub_key[1], pub_key[0]) * old_ct_as_number) % pub_key[0]
    oracle_res = recovery_oracle(new_ct.to_bytes((new_ct.bit_length() + 7) // 8, byteorder="big"))
    val = (inv_s*int.from_bytes(oracle_res, byteorder="big")) % pub_key[0]
    print("Original message was {}".format(val.to_bytes((val.bit_length() + 7) // 8, byteorder="big")))

def main():
    global PRIV_KEY, PUBLIC_KEY
    PUBLIC_KEY, PRIV_KEY = CP39.generate_RSA_key(RSA_EXPORT_GRADE)
    random_enc = CP39.encrypt(PUBLIC_KEY, b"It is a truth universally acknowledged")
    decrypted_with_key = CP39.decrypt(PRIV_KEY, random_enc)
    attacker(PUBLIC_KEY, random_enc)    
    return

if __name__ == "__main__":
    main()
