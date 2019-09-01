import crypto_pals.set5.CryptoPals39 as CP39
import crypto_pals.set5.mult_group_mod_p as GroupOp
import crypto_pals.set4.SHA1 as sha1
import crypto_pals.set5.sha256 as sha256
import math

BYTE_SIZE = 8
SHA1_ASN = 0x3021300906052b0e03021a05000414
SHA1_ASNBitLen = int(math.ceil(SHA1_ASN.bit_length() / 8.0))*8
SHA1Len = 160 // BYTE_SIZE
SHA256_ASN = 0x3031300d060960864801650304020105000420



def RSASignPKCS15(priv_key, msg):
    msg_encoded = EncodeMessage(msg, priv_key[0])
    sig = GroupOp.mod_exp(msg_encoded, priv_key[1], priv_key[0])
    return sig    

def find_cube_root_range(number):
    number_digits = int(math.ceil((math.log(number**(1/3.0),10)))) + 1
    # we can account for approx 15.9 decimal digits of precision (Python
    # doubles are commonly mapped to IEEE754 "double precision" with 53 bits
    # bits of precision according to stack overflow, so we can only say 15
    # for sure
    number_digits = number_digits - 15
    low_guess = int(number**(1/3.0))
    higher_guess = low_guess + 10**(number_digits)
    assert(low_guess != higher_guess and low_guess**3 < number and higher_guess**3 > number)
    # binary search for the value
    while higher_guess - low_guess != 1:
        # this is too high, i ended up calculating low_guess + higher_guess / 2 and just getting the higher guess again... :P 
        #mid = int((low_guess + higher_guess) / 2)
        inc_low = int((higher_guess - low_guess) / 2)
        mid = low_guess + inc_low
        if mid**3 > number:
            higher_guess = mid
        else:
            low_guess = mid
    return (low_guess, higher_guess)

def RSAAttackerSign(pub_key, msg):
    hash_obj = sha1.SHA1()
    hash_obj.Update(msg)
    res = int.from_bytes(hash_obj.Sum(), byteorder="big")
    mod_byte_len = pub_key[0].bit_length() // 8
    formatted_msg = int("0x" + "0001ffff00" + hex(SHA1_ASN)[2:] + hex(res)[2:], 16) << ((mod_byte_len - 5 - (SHA1_ASNBitLen // 8) - SHA1Len)*BYTE_SIZE)
    # take the cube root and round up
    fake_sig = find_cube_root_range(formatted_msg)[1]
    return fake_sig 


def EncodeMessage(msg, modulus):
    hash_sha = sha1.SHA1()
    hash_sha.Update(msg)
    msg_hash = hash_sha.Sum()
    hash_as_int = int.from_bytes(msg_hash, byteorder="big")
    mod_size = modulus.bit_length() // 8
    # 00 01 ff ff ff ... 00 ASN.1 HASH
    numFBytes = mod_size - 3 - (SHA1_ASNBitLen // 8) - SHA1Len
    hash_and_length = SHA1_ASNBitLen + (SHA1Len*BYTE_SIZE)
    # extra byte left shift by 8 for 00
    encoded_msg = int("0x01" + (numFBytes * "ff"), 16) << (BYTE_SIZE + hash_and_length)
    encoded_msg |= (SHA1_ASN << (SHA1Len*BYTE_SIZE))
    encoded_msg |= hash_as_int
    return encoded_msg

#------ broken implementation ----
def RSAVerifyPKCS15(pub_key, msg, sig):
    verify_against = (GroupOp.mod_exp(sig, pub_key[1], pub_key[0])).to_bytes(pub_key[0].bit_length() // 8, byteorder="big")   
    begin_correct = verify_against.startswith(b"\x00\x01")
    # strip all of the ff's 
    ff_strip = verify_against[2:]
    while ff_strip[0] == 0xff:
        ff_strip = ff_strip[1:]
    correct0 = ff_strip.startswith(b"\x00")
    hash_id_length = SHA1_ASNBitLen // 8
    hash_identifier = int.from_bytes(ff_strip[1:hash_id_length+1], byteorder="big")

    if hash_identifier == SHA1_ASN:
        hash_obj = sha1.SHA1()
    elif hash_identifier == SHA256_ASN:
        hash_obj = sha256.SHA256()
    else:
        raise ValueError("Was unable to identify hash alg")

    hash_obj.Update(msg)
    hashed_msg = hash_obj.Sum()

    hash_from_sig = ff_strip[hash_id_length+1:hash_id_length+1+SHA1Len]
    check_val = (hash_from_sig == hashed_msg) 
    return check_val and correct0 and begin_correct

def main():
    pub_key, priv_key = CP39.generate_RSA_key(1024)
    msg = b"A rose with any other name"
    sig = RSASignPKCS15(priv_key, msg)
    print("Valid Signer: Signature {} on message {} was successful {}".format(sig, msg, RSAVerifyPKCS15(pub_key, msg, sig)))
    print("Attempting Attacker strategy...")
    alternate_msg = b"hi mom"
    fake_sign = RSAAttackerSign(pub_key, alternate_msg)
    print("Attacker: Signature {} on message {} was successful {}".format(fake_sign, alternate_msg, RSAVerifyPKCS15(pub_key, alternate_msg, fake_sign)))
    return

if __name__ == "__main__":
    main()
