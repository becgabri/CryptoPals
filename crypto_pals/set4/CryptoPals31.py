import os
import SHA1
import CryptoPals29
import time
from flask import Flask, request
from logging.config import dictConfig

dictConfig({
    'version': 1,
    'formatters': {'default': {
        'format': '[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
    }},
    'handlers': {'wsgi': {
        'class': 'logging.FileHandler',
        'filename': '/dev/null',
        'formatter': 'default',
    }},
    'root': {
        'level': 'INFO',
        'handlers': ['wsgi']
    }
})

app = Flask(__name__)
 
opad_byte = (int('0x' + ('5c' * SHA1.PROCESS_LIMIT), 16)).to_bytes(SHA1.PROCESS_LIMIT, byteorder='big')
ipad_byte = (int('0x' + ('36' * SHA1.PROCESS_LIMIT), 16)).to_bytes(SHA1.PROCESS_LIMIT, byteorder='big')
HMAC_KEY = ""

#HMAC ripped straight from https://en.wikipedia.org/wiki/HMAC
# key is assumed to be a string as is message or at least a byte array
def HMAC_SHA(key, message):
    key_to_use = bytearray()
    if len(key) * 8 > SHA1.BLOCK_SIZE:
        key_for_sha = SHA1.SHA1()
        key_for_sha.Update(key)
        key_to_use = key_for_sha.Sum()
    else:
        if type(key) is bytes:
            key_to_use = bytearray(key)
        else:
            key_to_use = key_to_use + str.encode(key, encoding='utf-8')
        key_to_use = key_to_use + bytearray(SHA1.PROCESS_LIMIT - len(key_to_use))

    inner_hmac = SHA1.SHA1()
    inner_msg = bytearray()
    for i in range(SHA1.PROCESS_LIMIT):
        inner_msg.append(key_to_use[i] ^ ipad_byte[i])
    inner_hmac.Update(inner_msg + str.encode(message))
    outer_hmac = SHA1.SHA1()
    outer_msg = bytearray()
    for i in range(SHA1.PROCESS_LIMIT):
        outer_msg.append(key_to_use[i] ^ opad_byte[i])
    outer_hmac.Update(outer_msg + inner_hmac.Sum())
    return outer_hmac.Sum()

def insecure_compare(arg1, arg2):
    if len(arg1) != len(arg2):
        return False
    for i in range(len(arg1)):
        if arg1[i] != arg2[i]:
            return False 
        #time.sleep(.050)
        time.sleep(.005)
    return True
        
@app.route('/test',methods=['POST','GET'])
def test_file():
    if request.method == 'GET':
        html = '<form action="" method="post" >' + \
        '<label for="signature"> Enter the signature over the hash of the file (in hex): </label> ' + \
        '<input type="text" name="signature" id="signature">' + \
        '<br/> <label for="file_t"> File to Upload: </label>' + \
        '<input type="file" name="file_t" id="file_t">' + \
        '<input type="submit" value="Upload and Verify"> </form>'
        return (html, 200)
        
    if not 'file_t' in request.form or not 'signature' in request.form:
        return ("Invalid Request", 400)

    filename = request.form['file_t']
    signature = request.form['signature']

    if os.path.exists(filename):
        with open(filename, "r") as read_file:
            read_values = read_file.read()
        MAC_of_file = HMAC_SHA(HMAC_KEY, read_values)
        try:
            signature_as_bytes = int(signature,16).to_bytes(20, byteorder='big')
        except:
            return ("Signature not in correct format", 400)

        if insecure_compare(MAC_of_file, signature_as_bytes):
            return ("Success", 200)
        else:
            return ("Invalid MAC", 500)
    else:
        return ("File does not exist", 400)


def run_server():
    global HMAC_KEY
    if HMAC_KEY == "":
        HMAC_KEY = CryptoPals29.pick_a_key()
    app.run(port=9000)
    

if __name__ == "__main__":
    if HMAC_KEY == "":
        HMAC_KEY = CryptoPals29.pick_a_key()
    app.run(port=9000)
