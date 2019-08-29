# Implemented in PYTHON3 
# SRP (Secure Remote Password implementation in python)
import math
from multiprocessing import Process
import secrets
import random
import network_utils as net_utils
import server
import time
import socket
import sha256
import hmac_myimpl
import mult_group_mod_p as GroupOp
from ast import literal_eval

MODPGROUP = {
    "1536": 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF,
    "2048": 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF,
    "3072": 2**3072 - 2**3008 - 1+ 2**64 * ((2**2942 * int(math.pi)) + 1690314)
}

SALT = ""
GENERATOR = 2
K = 3
EMAIL = "something"
PASSWORD = b"password123"
v = 0 
PROTOCOL = 49153
HOST = "127.0.0.1"

def server_setup():
    global SALT
    global v
    # generate salt 
    SALT = (random.getrandbits(64)).to_bytes(8, byteorder='big')
    v = generate_v(SALT, PASSWORD)
    return

def generate_v(salt, password):
    sha256_string = sha256.SHA256()
    salt_hash_concat = "{}||{}".format(salt,password)
    sha256_string.Update(bytes(salt_hash_concat, encoding='utf-8'))
    x = sha256_string.Sum()
    # this is a random numerical value -- not a string although it should be one
    v = GroupOp.mod_exp(GENERATOR, x, MODPGROUP["1536"])
    return v

def server_srp(client_sock, email_held, salt, v_held):
    # try and receive msg from pipe
    b = secrets.randbelow(MODPGROUP["1536"])
    client_msg = (net_utils.receive_msg(client_sock)).decode('utf-8')
    args = client_msg.split(",")
    email = args[1][:-1]
    client_key_share = int(args[0][1:])

    if email == email_held:
        g_with_b = GroupOp.mod_exp(GENERATOR, b, MODPGROUP["1536"])
        maskedv = (K * v_held + g_with_b) % MODPGROUP["1536"]
        server_msg = "({},{})".format(salt, maskedv)
    else:
        print("Server received wrong email identifier")
        server_msg = "ERROR"

    
    if not net_utils.send_msg(server_msg, client_sock):
        raise ValueError("Failed writing to pipe")
    client_hmac_val = net_utils.receive_msg(client_sock)
    #compute local 
    u_hash = sha256.SHA256()
    u_hash.Update(bytes("{}||{}".format(client_key_share, maskedv), encoding='utf-8'))
    u = u_hash.Sum()

    total = GroupOp.mod_exp(v_held,u,MODPGROUP["1536"])
    total = (total *  client_key_share) % MODPGROUP["1536"]
    total = GroupOp.mod_exp(total, b, MODPGROUP["1536"])
    key_digest = sha256.SHA256()
    key_digest.Update(bytes("{}".format(total), encoding='utf-8'))
    actual_key = (key_digest.Sum()).to_bytes(256 // 8,byteorder='big')

    check_against = hmac_myimpl.SHA256_HMAC(actual_key, salt)

    # this comparison is very insecure
    if client_hmac_val == check_against:
        print("{} client succesfully authenticated".format(email_held))
        return True
    else:
        return False
        
def client():
    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_sock.connect((HOST,PROTOCOL))
    # generate a needed for diffie hellman
    a = secrets.randbelow(MODPGROUP["1536"])
    g_with_a = GroupOp.mod_exp(GENERATOR, a, MODPGROUP["1536"])
    if not net_utils.send_msg("({},{})".format(g_with_a, EMAIL),client_sock):
        raise ValueError("Failed to send message")
    message_received = net_utils.receive_msg(client_sock)
     
    msg_ints = literal_eval(message_received.decode('utf-8'))
    salt = msg_ints[0]
    b_value = msg_ints[1]
    sha_pw_digest = sha256.SHA256()
    sha_pw_digest.Update(bytes("{}||{}".format(salt, PASSWORD), encoding='utf-8'))
    x_exp = sha_pw_digest.Sum()
    u_digest = sha256.SHA256()
    u_digest.Update(bytes("{}||{}".format(g_with_a, b_value), encoding='utf-8'))
    u = u_digest.Sum()
    
    v_value = GroupOp.mod_exp(GENERATOR, x_exp, MODPGROUP["1536"])
    total = (b_value - (K * v_value)) % MODPGROUP["1536"]
    total = GroupOp.mod_exp(total, a + (x_exp * u), MODPGROUP["1536"])

    key_digest = sha256.SHA256()
    key_digest.Update(bytes("{}".format(total), encoding='utf-8'))
    actual_key = (key_digest.Sum()).to_bytes(256 // 8,byteorder='big')
    verification_check = hmac_myimpl.SHA256_HMAC(actual_key, salt)
    if not net_utils.send_msg(verification_check, client_sock):
        raise ValueError("Could not send over pipe")

def main():
    server_setup()
    server_thread = Process(target=server.server, args=(server_srp, HOST, PROTOCOL, EMAIL, SALT, v))
    client_thread = Process(target=client, args=())
    server_thread.start()
    client_thread.start()
    client_thread.join()
    server_thread.join()

if __name__ == "__main__":
    main()
