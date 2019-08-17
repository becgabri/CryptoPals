from crypto_pals.set1.CryptoPals7 import PKCS_padding, GF28_to_string, modify_list_into_GF28

def main():
    plaintext = "YELLOW SUBMARINE"
    bytearray_plain = modify_list_into_GF28(plaintext)
    padded = GF28_to_string(PKCS_padding(bytearray_plain))
    print(padded)
    

if __name__ == "__main__":
    main()
