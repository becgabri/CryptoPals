import network_utils as net_utils
import random
import socket
import sys
import server
import sha256
import secrets
import hmac_myimpl
import mult_group_mod_p as GroupOp
import crypto_pals.set5.CryptoPals36 as CP36
import crypto_pals.set5.CryptoPals37 as CP37
import json
from ast import literal_eval
 
"""
How to test simple srp implementation:
    1. Run with argument server 
        python3 CryptoPals38.py server
    2. In a separate window, run with argument client
        python3 CryptoPals38.py client
    3. When prompted if you want to create a new user,
    create a new user (give appropriate email and password)
    4. Run again this file with argument client 
    5. When prompted, elect not to create a new user, enter the correct password

How to test mitm offline dictionary attack:
    1. Run with argument mitm
    2. In a separate window, run with argument client
    3. When prompted elect not to create a new user, enter a username and password (one of a, b, or c)
"""


HOST = "127.0.0.1"
PROTOCOL = 63030

server_user_list = {}
PASSWORD_DICT = ['a', 'b', 'c', 'd']
#### COPY PASTA ##########


def client(email, password, new_user=False):
    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_sock.connect((HOST,PROTOCOL))

    if new_user:
        msg = "CREATE_PASSWORD:({},{})".format(email, password)
        if not net_utils.send_msg(msg, client_sock):
            raise ValueError("Failed to send message")

        # wait to receive a SUCCESSFUL from the server
        server_reply = (net_utils.receive_msg(client_sock)).decode('utf-8')
        if server_reply != "SUCCESS":
            raise ValueError("Could not create account")
        else:
            print("Successfully created account")
    else:
        # generate a needed for diffie hellman
        a = secrets.randbelow(CP36.MODPGROUP["1536"])
        g_with_a = GroupOp.mod_exp(CP36.GENERATOR, a, CP36.MODPGROUP["1536"])
        if not net_utils.send_msg("AUTH_ATTEMPT:({},{})".format(g_with_a, email),client_sock):
            raise ValueError("Failed to send message")
        message_received = net_utils.receive_msg(client_sock)
         
        msg_ints = literal_eval(message_received.decode('utf-8'))
        salt = msg_ints[0]
        b_value = msg_ints[1]
        u = msg_ints[2]
        sha_pw_digest = sha256.SHA256()
        sha_pw_digest.Update(bytes("{}||{}".format(salt, password), encoding='utf-8'))
        x_exp = sha_pw_digest.Sum()
       
        total = GroupOp.mod_exp(b_value, a + (x_exp * u), CP36.MODPGROUP["1536"])

        key_digest = sha256.SHA256()
        key_digest.Update(bytes("{}".format(total), encoding='utf-8'))
        actual_key = (key_digest.Sum()).to_bytes(256 // 8,byteorder='big')
        verification_check = hmac_myimpl.SHA256_HMAC(actual_key, salt)
        if not net_utils.send_msg(verification_check, client_sock):
            raise ValueError("Could not send over pipe")
        msg = (net_utils.receive_msg(client_sock)).decode('utf-8')
        print("Server says {}".format(msg))
        print("Finishing client thread")

    return


def simple_srp(email, client_share, client_sock):
    # try and receive msg from pipe
    b = secrets.randbelow(CP36.MODPGROUP["1536"])
    salt, v = server_user_list[email]
    
    g_with_b = GroupOp.mod_exp(CP36.GENERATOR, b, CP36.MODPGROUP["1536"])
    u = secrets.randbelow(2**128)
    server_msg = "({},{},{})".format(salt, g_with_b, u)
    
    if not net_utils.send_msg(server_msg, client_sock):
        raise ValueError("Failed writing to pipe")

    client_hmac_val = net_utils.receive_msg(client_sock)

    total = GroupOp.mod_exp(v,u, CP36.MODPGROUP["1536"])
    total = (total *  client_share) % CP36.MODPGROUP["1536"]
    total = GroupOp.mod_exp(total, b, CP36.MODPGROUP["1536"])
    key_digest = sha256.SHA256()
    key_digest.Update(bytes("{}".format(total), encoding='utf-8'))
    actual_key = (key_digest.Sum()).to_bytes(256 // 8,byteorder='big')

    check_against = hmac_myimpl.SHA256_HMAC(actual_key, salt)

    # this comparison is very insecure
    if client_hmac_val == check_against:
        return True
    else:
        return False
    return

""" 
Note! The only possible thing to precompute here is the G**x value if G is a 
known generator and the attacker always sends the same salt. You will not be able
to compute the HMAC(Key, salt) value beforehand because S depends upon the client
share value

"""
def offline_attack(client_key_share, salt, client_output, pw_dictionary):
    for psw in pw_dictionary:
        sha_pw_digest = sha256.SHA256()
        sha_pw_digest.Update(bytes("{}||{}".format(salt,psw), encoding='utf-8'))
        x_exp = sha_pw_digest.Sum()

        g_to_the_x = GroupOp.mod_exp(CP36.GENERATOR, x_exp, CP36.MODPGROUP["1536"])
        potential_s = (g_to_the_x * client_key_share) % CP36.MODPGROUP["1536"]
        key_digest = sha256.SHA256()
        key_digest.Update(bytes("{}".format(potential_s), encoding='utf-8'))
        actual_key = (key_digest.Sum()).to_bytes(256 // 8,byteorder='big')

        check_against = hmac_myimpl.SHA256_HMAC(actual_key, salt)
        if client_output == check_against:
            return psw
    return None

#simulated, just impersonating rather than active mitm'ing
def mitm(client_sock):
    # client will send the value B**(a + ux)
    # I can't think of any possible way to get the a value completely out
    # of the calculation while only knowing G**a and not a 
    # so setting u = 1 and B = generator, this will give G**a * G**x as the value the client
    # will be use as S for generating the key K in the HMAC computation.
    # Full attack: 
    # for likely passwords pw, do the following,
    # calculate x = H(salt || pw) for known salt, calculate G**x and use client value G**a to 
    # create potential S. take k = H(S) and compute HMAC(key, salt) and check this against client
    # output
    u = 1
    B = CP36.GENERATOR
    salt = ("000").encode()
    # run interaction with client
    client_msg = (net_utils.receive_msg(client_sock)).decode("utf-8")
    
    if ":" in client_msg:
        switch_val, actual_msg = client_msg.split(":")
    else:
        switch_val = client_msg

    if switch_val == "AUTH_ATTEMPT":
        client_share, email = actual_msg.split(',')
        client_share = int(client_share.lstrip('('))
        email = email.rstrip(')')        

        server_msg = "({},{},{})".format(salt, B, u)
        
        if not net_utils.send_msg(server_msg, client_sock):
            raise ValueError("Failed writing to pipe")

        client_hmac_val = net_utils.receive_msg(client_sock)

        net_utils.send_msg("FAILED", client_sock)

        print("Beginning dictionary attack... ")
        res = offline_attack(client_share, salt, client_hmac_val, PASSWORD_DICT)
        if res:
            print("Found password used by victim: {}".format(res))
        else:
            print("Was unable to find password")
    else:
        send_msg("FAILED", client_sock)
    return


    return

def server_wrapper(client_sock):
    client_msg = (net_utils.receive_msg(client_sock)).decode("utf-8")
    
    if ":" in client_msg:
        switch_val, actual_msg = client_msg.split(":")
    else:
        switch_val = client_msg
    if switch_val == "CREATE_PASSWORD":
        email, passw = actual_msg.split(',')
        email = email.lstrip('(')
        passw = passw.rstrip(')')

        if email in server_user_list:
            net_utils.send_msg("FAILED", client_sock)
        else:
            salt, v = CP37.create_password(passw)
            server_user_list[email] = (salt, v)
            net_utils.send_msg("SUCCESS", client_sock)

    elif switch_val == "AUTH_ATTEMPT":
        client_share, email = actual_msg.split(',')
        client_share = int(client_share.lstrip('('))
        email = email.rstrip(')')
        if email in server_user_list:
            auth_outcome = simple_srp(email, client_share, client_sock)       
            if auth_outcome:
                net_utils.send_msg("SUCCESS", client_sock)
            else:
                net_utils.send_msg("FAILED", client_sock)
        else: 
            net_utils.send_msg("FAILED", client_sock)
    else:
        net_utils.send_msg("FAILED", client_sock)
    return

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage is python3 {} [client/server/mitm]".format(sys.argv[0]))
        sys.exit(1)
    else:
        if sys.argv[1] == "server":
            server.server(server_wrapper, HOST, PROTOCOL)
        elif sys.argv[1] == "client":
            new_account = input("Would you like to create a new account? ")

            if new_account.startswith("Y") or new_account.startswith("y"):
                user_email = input("User's Email: ")
                user_pass = input("User's password: ")
                client(user_email, user_pass, True)
            else:
                print("Please log in.")
                user_email = input("User's Email: ")
                user_pass = input("User's password: ")
                client(user_email, user_pass)
        elif sys.argv[1] == "mitm":
            server.server(mitm, HOST, PROTOCOL)
        else:
            print("Usage is python3 {} [client/server/mitm]".format(sys.argv[0]))

