# Requires: bytes_str be a bytearray
# Modifies: bytes_str
def padd_out(bytes_str, block_len):
    coverage = block_len - (len(bytes_str) % block_len)
    bytes_str.extend([coverage] * coverage)

def main():
    plaintext = "YELLOW SUBMARINE"
    bytearray_plain = bytearray(len(plaintext))

    for idx, let in enumerate(plaintext):
        bytearray_plain[idx] = ord(let)

    padd_out(bytearray_plain, 20)

    import pdb; pdb.set_trace()

if __name__ == "__main__":
    main()
