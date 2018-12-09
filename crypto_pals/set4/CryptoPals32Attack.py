import multiprocessing, time, os
import requests, json, math, statistics
from CryptoPals31 import run_server


def convert_to_hex(byte_repr):
    integer = int.from_bytes(byte_repr, byteorder='big')
    return hex(integer)[2:]

def run_subtest(mac_guess, curr_idx, test_val, request_body):
    if not curr_idx + 1 < len(mac_guess):
        raise ValueError("Can only run a subtest for smaller indices")
    avg_time = 0.0
    mac_guess[curr_idx] = test_val
    for i in range(5):
        mac_guess[curr_idx + 1] = i
        request_body['signature'] = convert_to_hex(mac_guess)
        start = time.time()
        resp = requests.post("http://localhost:9000/test", data=request_body)
        end = time.time()
        avg_time += (end - start)
    # restore state
    mac_guess[curr_idx] = 0
    mac_guess[curr_idx + 1] = 0
    return avg_time / 10.0

def uncoverCorrectFileMac(filename):
    if not os.path.exists(filename):
        raise ValueError("File does not exist")
    # 2 hex characters is a byte, SHA1 output is 160 bits so 20 bytes and thus 40 hex chars 
    hex_mac_guess = bytearray(20)
    request_body = {
        "file_t": filename,
        "signature": convert_to_hex(hex_mac_guess)
    }
    
    for digest_idx in range(len(hex_mac_guess) - 1):
        print("Trying to find index {}".format(digest_idx))
        time_results = [(i, 0) for i in range(256)]
        for it in range(3):
            byte_val = 0
            while byte_val <= 255:
                hex_mac_guess[digest_idx] = byte_val
                request_body['signature'] = convert_to_hex(hex_mac_guess)
                
                timer_value = time.time()
                resp = requests.post("http://localhost:9000/test", data=request_body)
                time_difference = time.time() - timer_value
                time_results[byte_val] = (time_results[byte_val][0], time_results[byte_val][1] + time_difference)
                #time_results[byte_val][1] += time_difference
                #.append((byte_val, avg_two_trials / 2.0))
                byte_val += 1
        for idx in range(len(time_results)):
            avg_res = time_results[idx][1] / 3.0
            time_results[idx] = (time_results[idx][0], avg_res)
        solely_times = list(map(lambda pair : pair[1], time_results))
        std_dev = statistics.stdev(solely_times)
        mean = statistics.mean(solely_times)
        print("Population varies with from mean {} with a standard deviation of {}".format(std_dev, mean))
        time_results.sort(reverse=True, key=lambda pair : pair[1])

        best_avg_time_byte_pair = (-1, None)
        for test in time_results[:5]:
            res = run_subtest(hex_mac_guess, digest_idx, test[0], request_body)
            best_avg_time_byte_pair = (res, test[0]) if res > best_avg_time_byte_pair[0] else best_avg_time_byte_pair

        max_diff = max(time_results)
        byte_idx = time_results.index(max_diff)
        print("Biggest average time for next byte test is {} for byte value {}".format(best_avg_time_byte_pair[0], best_avg_time_byte_pair[1]))
        hex_mac_guess[digest_idx] = best_avg_time_byte_pair[1]
    # try last byte by hand, only 256 options now
    for last_byte in range(256):
        hex_mac_guess[-1] = last_byte
        signature_hex = convert_to_hex(hex_mac_guess)
        request_body['signature'] = signature_hex
        resp = requests.post("http://localhost:9000/test", data=request_body)
        if resp.status_code == 200:
            print("Success! Valid signature for file is {}".format(signature_hex))
            return
    print("Fail :(")   

def main():
    web_proc = multiprocessing.Process(target=run_server, args=())
    # need to do some timing to make sure the server is up before sending the first request
    web_proc.start()
    time.sleep(10)
    print("Done sleeping, starting attack")
    uncoverCorrectFileMac("good_stuff.txt")
    web_proc.terminate()
    return

if __name__ == "__main__":
    main()
