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
from ast import literal_eval
"""
How to test attacker authenticating:
    1. Run with argument server
        python3 CryptoPals37.py server
    2. In a separate window, run with argument client
    3. When prompted, create a username and password
    4. Run with argument attacker 
    5. When prompted, enter 0 for the G value and 0
 for S (b/c g**a * y will be 0 if g**a = 0) 
"""

EMAIL = ""
v = None
SALT = ""
HOST = "127.0.0.1"
PROTOCOL = 63030


def create_password(password):
    password = password.rstrip(")")
    salt = (random.getrandbits(64)).to_bytes(8, byteorder='big')
    v = CP36.generate_v(salt, password)

    return salt, v

def server_switch(client_sock):
    global SALT, v, EMAIL
    client_msg = (net_utils.receive_msg(client_sock)).decode("utf-8")

    if ":" in client_msg:
        switch_val, actual_msg = client_msg.split(":")
    else:
        switch_val = client_msg

    if switch_val == "CREATE_PASSWORD" and len(EMAIL) == 0:
        EMAIL, password = actual_msg.split(',')
        EMAIL = EMAIL.lstrip('(')
        password = password.rstrip(')')
        SALT, v = create_password(password)
        print("Successfully created user password {}".format(EMAIL))
        net_utils.send_msg("SUCCESS", client_sock) 
    elif switch_val == "AUTH_ATTEMPT" and len(EMAIL) != 0:
        net_utils.send_msg("CONTINUE", client_sock)
        auth_outcome = CP36.server_srp(client_sock, EMAIL, SALT, v)
        if auth_outcome:
            net_utils.send_msg("SUCCESS", client_sock)
        else:
            net_utils.send_msg("FAILED", client_sock)
    else:
        net_utils.send_msg("FAILED", client_sock)
    

def client(email, password):
    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_sock.connect((HOST,PROTOCOL))
    msg = "CREATE_PASSWORD:({},{})".format(email, password)
    if not net_utils.send_msg(msg, client_sock):
        raise ValueError("Failed to send message")

    # wait to receive a SUCCESSFUL from the server
    server_reply = (net_utils.receive_msg(client_sock)).decode('utf-8')
    if server_reply != "SUCCESS":
        raise ValueError("Could not create account")
    return

def attacker():
    print("Attacker trying to authenticate")
    email = input("Please enter the user you would like to authenticate as...")
    # generate a needed for diffie hellman
    share = input("Input client share (i.e. g**a) as numerical value or [number]G\n")
    changed_val = False
    if "G" in share:
        g_with_a = CP36.MODPGROUP["1536"] * int(share[:share.index("G")])
        changed_val = True
    else:
        g_with_a = int(share)

    second_client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    second_client_sock.connect((HOST, PROTOCOL))
    if not net_utils.send_msg("AUTH_ATTEMPT", second_client_sock):
        raise ValueError("Failed to send message")
    saw_okay = (net_utils.receive_msg(second_client_sock)).decode('utf-8')
    if saw_okay != "CONTINUE":
        raise ValueError("Server Error")
    if not net_utils.send_msg("({},{})".format(g_with_a, email),second_client_sock):
        raise ValueError("Failed to send message")
    message_received = net_utils.receive_msg(second_client_sock)
    msg_ints = literal_eval(message_received.decode('utf-8'))
    salt = msg_ints[0]
    total = int(input("Please give integer input (i.e. S): ")) 
    key_digest = sha256.SHA256()
    key_digest.Update(bytes("{}".format(total), encoding='utf-8'))
    actual_key = (key_digest.Sum()).to_bytes(256 // 8,byteorder='big')
    
    verification_check = hmac_myimpl.SHA256_HMAC(actual_key, salt)
    if not net_utils.send_msg(verification_check, second_client_sock):
        raise ValueError("Could not send over pipe")
    response = (net_utils.receive_msg(second_client_sock)).decode('utf-8')
    print("Finishing client thread, received from server {}".format(response))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage is python3 {} [client/server/attacker]".format(sys.argv[0]))
        sys.exit(1)
    else:
        if sys.argv[1] == "server":
            server.server(server_switch, HOST, PROTOCOL)
        elif sys.argv[1] == "client":
            user_email = input("User's Email: ")
            user_pass = input("User's password: ")
            client(user_email, user_pass)
        elif sys.argv[1] == "attacker":
            attacker()
        else:
            print("Usage is python3 {} [client/server/attacker]".format(sys.argv[0]))
