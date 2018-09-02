import random
import sys
import random
import copy
sys.path.append('/mnt/c/Users/becga/Documents/crypto_pals')
from crypto_pals.set1 import CryptoPals7
from crypto_pals.set2.CryptoPals11 import generate_rand_AES_key, generate_rand_IV
from crypto_pals.set2.CryptoPals12 import find_block_size

key = generate_rand_AES_key()
iv = generate_rand_IV()
list_of_strs = ['MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93']

def encrypt_random_string():
    chosen_text = list_of_strs[random.randint(0,len(list_of_strs) - 1)]

    res = CryptoPals7.ENCRYPTION_CBC_MODE(iv, key, chosen_text, CryptoPals7.encrypt_aes)
    return (res, iv)

def decryption_oracle(ciphertext):
    try:
        result = CryptoPals7.DECRYPTION_CBC_MODE(iv, key, ciphertext, CryptoPals7.decrypt_aes)
        # if it got this far, padding must be correct
        return 1
    except ValueError:
        return 0

def modify_iv_into_string(iv):
    iv_ret = ""
    iv_ret = [chr(int(num)) for num in iv.split('-')]
    return ''.join(iv_ret)

def break_CBC_confidentiality():
    block_size = 16
    #find_block_size(CryptoPals7.ENCRYPTION_CBC_MODE, CryptoPals7.encrypt_aes, key)
    target, current_IV = encrypt_random_string()

    recovered_pt = ""
    print("target length of string: {}".format(len(target)))
    for idx in range(0,len(target), block_size):
        current_text = ''
        if idx == 0:
            current_text = modify_iv_into_string(current_IV) + target[:block_size]
        # doing this way differently than I normally would...
        # take the current block and ALWAYS send the modified text
        # [ IV ] | [ target block ]
        # that's it and then add this block
        else:
            current_text = target[: idx + block_size]
        # always modify the second to last block
        modified_txt = [i for i in current_text]
        quot_start = int((len(current_text) / block_size) - 2)
        decrypted_block = [" "] * block_size
        for i in range(block_size):
            # modify the end of the current msg so that it has the correct
            # padding
            padd_val = i + 1
            # make sure this is a shallow copy... if not you'll need to copy it again
            current_tst = copy.copy(modified_txt)
            for j in range(i):
                # assumption is that modified_txt has been changed so that the end is
                # zero'ed out once decryption
                current_tst[(quot_start * block_size) + block_size - 1 - j] = chr(ord(modified_txt[(quot_start * block_size) + block_size - 1 - j]) ^ padd_val)

            tst = 0
            ct_chr = current_tst[(block_size * quot_start) + block_size - 1 - i]
            current_tst[(block_size * quot_start) + block_size - 1 - i] = chr(ord(ct_chr) ^ tst ^ padd_val)
            while (decryption_oracle("".join(current_tst)) != 1):
                tst += 1
                # this is needed right at the end b/c if tst ^ padd_val cancel out and the message
                # is padded validly then it will still be valid
                if idx == len(target) - block_size and i == 0 and tst == padd_val:
                    import pdb; pdb.set_trace()
                    continue
                current_tst[(block_size * quot_start) + block_size - 1 - i] = chr(ord(ct_chr) ^ tst ^ padd_val)

            # should be the correct value now
            # modified_txt now contains the value 0'ed out
            modified_txt[(block_size * quot_start) + block_size - 1 - i] = chr(ord(ct_chr) ^ tst)
            # you know that C_[i - 1] \xor Dec_k(C_[i]) where
            # C_[i-1] = C_[i - 1] \xor tst so
            # **P_i = C_[i-1] \xor tst \xor C_[i-1] \xor P_i
            # **P_i = tst \xor P_i so.... P_i = **P_i \xor tst
            decrypted_block[block_size - 1 - i] = chr(tst)
        recovered_pt += ''.join(decrypted_block)
    import pdb; pdb.set_trace()
    print(recovered_pt)





def main():
    break_CBC_confidentiality()
    return

if __name__ == "__main__":
    main()