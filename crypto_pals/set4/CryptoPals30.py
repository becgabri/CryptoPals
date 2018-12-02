import sys
from crypto_pals.set4.CryptoPals29 import pick_a_key
import MD4

SECRET_KEY = b""
original_msg = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
new_msg = ";admin=true"
POSSIBLE_BLOCKS = 2
# COPY PASTA SECTION
# ----------------------------------------
# secret_key and message must be of same type
def verify_message(secret_key, tag, message):
    hash_func2 = MD4.MD4()
    hash_func2.Update(secret_key + message)
    check_val = hash_func2.Sum()
    return check_val == tag

# secret_key and message must be of same type
def tag_message(secret_key, message):
    hash_func = MD4.MD4()
    hash_func.Update(secret_key + message)
    tag = hash_func.Sum()
    return tag

def validate_msg_for_key(msg, tag):
    if SECRET_KEY == b"":
        raise ValueError("Secret key was never set")

    return verify_message(SECRET_KEY, tag, msg)
# ------------------------------------------

def create_md4_tagged_msg():
    global SECRET_KEY
    SECRET_KEY = str.encode(pick_a_key())

    return (tag_message(SECRET_KEY, original_msg), original_msg)


def main():
    tag, message = create_md4_tagged_msg()
    print("Old tag is ", tag)
    # keep increasing your test length by a byte and see if it succeeds
    # [key] [original msg] | [padd]
    for i in range(1, POSSIBLE_BLOCKS):
        new_digest = MD4.MD4()

        new_digest.update_hash(int.from_bytes(tag,byteorder='big'), POSSIBLE_BLOCKS)
        new_digest.Update(new_msg)
        new_tag = new_digest.Sum()
        print("New tag is ", new_tag)

        for j in range(1, MD4.PROCESS_LIMIT):
            if j == len(SECRET_KEY):
                print("Hit key length")
                import pdb; pdb.set_trace()
            try_msg_blocks = MD4.padd_message(message, j + len(original_msg))
            try_msg = 0
            for idx,try_block in enumerate(try_msg_blocks):
                try_msg += (try_block) << (512 * (len(try_msg_blocks) - 1 - idx))
            try_msg = try_msg.to_bytes((try_msg.bit_length() + 7) // 8, byteorder='big')
            try_msg += str.encode(new_msg)
            if validate_msg_for_key(try_msg, new_tag):
                print("Message validated successfully")
                print(try_msg)
                return
            else:
                print("Message try failed")
            print("FAILED")
    return

if __name__ == "__main__":
    main()