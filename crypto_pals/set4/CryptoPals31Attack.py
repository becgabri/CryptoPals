import multiprocessing, time, os
import requests, json, math, statistics
from CryptoPals31 import run_server


def convert_to_hex(byte_repr):
    integer = int.from_bytes(byte_repr, byteorder='big')
    return hex(integer)[2:]

def uncoverCorrectFileMac(filename):
    if not os.path.exists(filename):
        raise ValueError("File does not exist")
    # 2 hex characters is a byte, SHA1 output is 160 bits so 20 bytes and thus 40 hex chars 
    hex_mac_guess = bytearray(20)
    request_body = {
        "file_t": filename,
        "signature": convert_to_hex(hex_mac_guess)
    }
    
    for digest_idx in range(len(hex_mac_guess)):
        print("Trying to find index {}".format(digest_idx))
        time_results = []
        byte_val = 0
        while byte_val <= 255:
            hex_mac_guess[digest_idx] = byte_val
            request_body['signature'] = convert_to_hex(hex_mac_guess)
            timer_value = time.perf_counter()
            resp = requests.post("http://localhost:9000/test", data=request_body)
            if resp.status_code != 500:
                print(resp.status_code)
            #time_kill = time.time() - timer_value
            time_results.append(time.perf_counter() - timer_value)
            #if (float(time_kill) - baseline) >= .025:
            #   print("Exceeded time difference!")
            #    found_byte_value = True
            #else:
            byte_val += 1
        #print(time_results)
        std_dev = statistics.stdev(time_results)
        mean = statistics.mean(time_results)
        print("Population varies with from mean {} with a standard deviation of {}".format(std_dev, mean))
        max_diff = max(time_results)
        byte_idx = time_results.index(max_diff)
        print("Biggest difference is {} for byte value {} with {} std dev above mean".format(max_diff,byte_idx, (max_diff - mean) / std_dev))
        hex_mac_guess[digest_idx] = byte_idx
    final_guess = convert_to_hex(hex_mac_guess)
    print("Valid signature for file is {}".format(final_guess))
    request_body['signature'] = final_guess
    resp = requests.post("http://localhost:9000/test", data=request_body)
    if resp.status_code == 200:
        print("Success!")
    else:
        print("Fail :(")



    

def main():
    web_proc = multiprocessing.Process(target=run_server, args=())
    # need to do some timing to make sure the server is up before sending the first request
    web_proc.start()
    time.sleep(20)
    print("Done sleeping, starting attack")
    uncoverCorrectFileMac("good_stuff.txt")
    web_proc.terminate()
    return

if __name__ == "__main__":
    main()
