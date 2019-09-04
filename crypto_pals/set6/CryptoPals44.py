import crypto_pals.set6.CryptoPals43 as CP43 
import crypto_pals.set5.mult_group_mod_p as GroupOp
import crypto_pals.set4.SHA1 as sha1

challenge_params = {
    "p": 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1,
    "q": 0xf4f47f05794b256174bba6e9b396a7707e563c5b,
    "g": 0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291
}
challenge_public_key = 0x2d026f4bf30195ede3a088da85e398ef869611d0f68f0713d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b85519b1c23cc3ecdc6062650462e3063bd179c2a6581519f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d32971c3de5084cce04a2e147821

def from_file(filename):
    all_msgs = []
    with open(filename, "r") as file_obj:
        lines = file_obj.readlines()
        for idx in range(0, len(lines), 4):
            relevant_lines = lines[idx:idx+4]
            assert(len(relevant_lines) == 4)
            msg_obj = {
                "msg": relevant_lines[0][relevant_lines[0].find(":") + 1:].strip(),
                "r": int(relevant_lines[2][relevant_lines[2].find(":") +1:].strip()),
                "s": int(relevant_lines[1][relevant_lines[1].find(":") +1:].strip()),
                "m": int("0x" + relevant_lines[3][relevant_lines[3].find(":") + 1:].strip(), 16)
            }
            all_msgs.append(msg_obj)
    return all_msgs

def isolate_repeated_k(dictionary):
    match = {}
    for obj in dictionary:
        grab_g_k = obj["r"]
        if grab_g_k in match:
            return obj, match[grab_g_k]
        else:
            match[grab_g_k] = obj
    print("Was unable to find match")
    return None, None

def main():
    dictionary = from_file("44.txt")
    dict1, dict2 = isolate_repeated_k(dictionary)
    if not dict1:
        print("Could not run attack :(")
    else:
        inv_s_elt = (dict1["s"] - dict2["s"]) % challenge_params["q"]
        inv_s_elt = GroupOp.find_inverse(inv_s_elt, challenge_params["q"])
        exp_k = (dict1["m"] - dict2["m"]) % challenge_params["q"]
        exp_k = (exp_k * inv_s_elt) % challenge_params["q"]
        recovered_x = CP43.AttackerWithKnownSubKeyK(challenge_params, challenge_public_key,
         exp_k, dict1["msg"], (dict1["r"], dict1["s"]), dict1["m"])
        import pdb; pdb.set_trace()
        key_hash_obj = sha1.SHA1()
        key_hash_obj.Update(hex(recovered_x)[2:])
        key = int.from_bytes(key_hash_obj.Sum(), byteorder="big")
        print("Recovered key is {:x}  with fp {:x}".format(recovered_x, key))
    return

if __name__ == "__main__":
    main()
