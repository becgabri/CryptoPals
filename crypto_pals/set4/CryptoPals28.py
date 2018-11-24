import sys
sys.path.append('/mnt/c/Users/becga/Documents/crypto_pals')
import SHA1

# secret_key and message must be strs
def verify_message(secret_key, tag, message):
    hash_func2 = SHA1.SHA1()
    hash_func2.Update(secret_key + message)
    check_val = hash_func2.Sum()
    return check_val == tag

# secret_key and message must be strs
def tag_message(secret_key, message):
    hash_func = SHA1.SHA1()
    hash_func.Update(secret_key + message)
    tag = hash_func.Sum()
    
    return tag
    #return str(int.from_bytes(tag, byteorder='big'),encoding='utf-8')

def main():
    msg_str = 'Persuasion, Emma, and other novels by Austen'
    a_0 = tag_message('password123', msg_str)
    if verify_message('password123', a_0, msg_str):
        print("Message verified correctly!")
    else:
        print("Correct tag did not verify :(")
        return 
    mall_msg = 'Persuasion, Tame, and other novels by Austen'
    mall_msg2 = 'Persuasion, Emma, and other novels by'

    if verify_message('password123', a_0, mall_msg) or \
        verify_message('password123', a_0, mall_msg2):
        print("Changed messages should not have a correct tag!!!")
        return
    if verify_message('password111', a_0, msg_str):
        print("Different password should not give a message that still verifies!!")
        return

    print("Passed all tests.") 
    return 


if __name__ == "__main__":
    main()
