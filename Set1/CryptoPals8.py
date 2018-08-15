import sys
import os.path
import binascii

def AES_test(input_file):
    input = ""
    best_line_and_total = (-1, 0)
    if not os.path.exists(input_file):
        raise OSError("File does not exist")
    with open(input_file, 'r') as a_file:
        input = a_file.readlines()
    for index,encrypted_line in enumerate(input):
        # unhexlify
        encrypted_line = encrypted_line.strip()
        results = binascii.unhexlify(encrypted_line)
        block_groups = []
        current_list = {}
        # break into 16 byte chunks
        for idx in range(0, len(results), 16):
            block_groups.append(results[idx:idx+16])
            if not str(results[idx:idx+16]) in current_list:
                current_list[str(results[idx:idx+16])] = 0
            current_list[str(results[idx:idx+16])] = current_list[str(results[idx:idx+16])] + 1
        max_val = -1
        for val in current_list.values():
            if val > max_val:
                max_val = val
        if max_val > best_line_and_total[1]:
            best_line_and_total = (index, max_val)
    print("Most likely line is {} with the same block appearing {} times".format(best_line_and_total[0], best_line_and_total[1]))

    # data is hex encoded

def main():
    if len(sys.argv) != 2:
        print("Usage is python3 {} [file_name]".format(sys.argv[0]))
        return
    AES_test(sys.argv[1])
    return


if __name__ == "__main__":
    main()