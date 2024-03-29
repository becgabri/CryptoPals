import sys
import random
from crypto_pals.set4 import CryptoPals28
import SHA1

original_msg = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
new_msg = ";admin=true"
SECRET_KEY = b""
POSSIBLE_BLOCKS = 2
def pick_a_key():
    with open("words", "r") as read_f:
        choose_key = read_f.readlines()
        idx = random.randint(0, len(choose_key) - 1)
    return choose_key[idx].strip()

def create_msg():
    global SECRET_KEY
    got_a_key = pick_a_key()
    SECRET_KEY = str.encode(got_a_key)
    return (CryptoPals28.tag_message(SECRET_KEY, original_msg), original_msg)

def validate_msg_for_key(msg, tag):
    if SECRET_KEY == b"":
        raise ValueError("Secret key was never set")

    return CryptoPals28.verify_message(SECRET_KEY, tag, msg)

def main():
    tag, message = create_msg()
    print("Old tag is ", tag)
    # keep increasing your test length by a byte and see if it succeeds
    # [key] [original msg] | [padd]
    for i in range(1, POSSIBLE_BLOCKS):
        new_digest = SHA1.SHA1()

        new_digest.update_hashes(tag, POSSIBLE_BLOCKS)
        new_digest.Update(new_msg)
        new_tag = new_digest.Sum()
        print("New tag is ", new_tag)

        for j in range(1, SHA1.PROCESS_LIMIT):
            try_msg_blocks = SHA1.padd_message(message, j + len(original_msg))
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
