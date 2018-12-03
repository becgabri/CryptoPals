import os
import SHA1
import CryptoPals29
import time
from flask import Flask, request, status

app = Flask(__name__)

opad_byte = (int('0x' + ('5c' * SHA1.PROCESS_LIMIT), 16)).to_bytes(SHA1.PROCESS_LIMIT, byteorder='big')
ipad_byte = (int('0x' + ('36' * SHA1.PROCESS_LIMIT), 16)).to_bytes(SHA1.PROCESS_LIMIT, byteorder='big')
HMAC_KEY = "" 
CryptoPals29.pick_a_key()

#HMAC ripped straight from https://en.wikipedia.org/wiki/HMAC
# key is assumed to be a string as is message or at least a byte array
def HMAC_SHA(key, message):
    key_to_use = b""
    if len(key) * 8 > SHA1.BLOCK_SIZE:
        key_for_sha = SHA1.SHA1()
        key_for_sha.Update(key)
        key_to_use = key_for_sha.Sum()
    else:
        key_to_use = str.encode(key)
        for i in range(SHA1.PROCESS_LIMIT - len(key_to_use)):
            key_to_use.append(0)
    inner_hmac = SHA1.SHA1()
    inner_msg = bytearray()
    for i in range(16):
        inner_msg.append(key_to_use[i] ^ ipad_byte[i])
    inner_hmac.Update(inner_msg + str.encode(message))
    outer_hmac = SHA1.SHA1()
    outer_msg = bytearray()
    for i in range(16):
        outer_msg.append(key_to_use[i] ^ opad_byte[i])
    outer_hmac.Update(outer_msg + inner_hmac.Sum())
    return outer_hmac.Sum()

def insecure_compare(arg1, arg2):
    for i in len(arg1):
        if i >= len(arg2):
            return False
        if arg1[i] != arg2[i]:
            return False 
        time.sleep(.050)
    return True
        
@app.route('/test')
def test_file():
    global HMAC_KEY
    if not 'file' in request.args or not 'signature' in request.args:
        # return a bad request
        return "Missing Parameters", status.HTTP_400_BAD_REQUEST

    filename = request.args.get('file')
    signature = request.args.get('signature')

    if HMAC_KEY == "":
        HMAC_KEY = CryptoPals29.pick_a_key()

    if os.path.exists(filename):
        with open(filename, "r") as read_file:
            read_values = read_file.read()
        MAC_of_file = HMAC_SHA(HMAC_KEY, read_values)
        if insecure_compare(MAC_of_file, signature):
            return "Success", status.HTTP_200_OK
        else:
            return "Invalid MAC", status.HTTP_500_INTERNAL_SERVER_ERROR
    else:
        return "File does not exist", status.HTTP_400_BAD_REQUEST



if __name__ == "__main__":
    app.run()