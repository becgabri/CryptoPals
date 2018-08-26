BLOCK_SIZE = 16

# expects PT to be bytearray
def strip_padding(plaintext):
    if (len(plaintext) % BLOCK_SIZE) != 0:
        raise ValueError("plaintext is not a multiple of 16")
    expected_val = plaintext[-1]
    if expected_val >= BLOCK_SIZE:
        raise ValueError('this is longer than the block size')
    # validate padding
    last_valid_idx = len(plaintext) - 1
    for i in range(1, expected_val):
        if plaintext[last_valid_idx - i] != expected_val:
            raise ValueError("Padding Error")
    # strip padding
    return plaintext[:-1 * expected_val]

def main():
    # quick tests
    str_array = bytearray("ICE ICE BABY", encoding='utf-8')

    test1 = str_array + bytearray([4] * 4)
    print(strip_padding(test1))

    print("Passed test 1")
    test2 = str_array + bytearray([5] * 4)
    try:
        strip_padding(test2)
    except ValueError as err:
        print(err)
        print("Caught test2 error")
    test3 = str_array + bytearray([1,2,3,4])
    try:
        strip_padding(test3)
    except ValueError as err:
        print(err)
        print("Caught test3 error")
    return

if __name__ == "__main__":
    main()