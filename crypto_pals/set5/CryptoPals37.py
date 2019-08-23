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
""" INTERFACE
    Server:
        SUCCESS
        FAILURE
    Client:
        CREATE_PASSWORD
        AUTH_ATTEMPT

"""
EMAIL = ""
v = None
SALT = ""
HOST = "127.0.0.1"
PROTOCOL = 63030

def server_switch(client_sock):
    global SALT, v, EMAIL
    client_msg = (net_utils.receive_msg(client_sock)).decode("utf-8")
    if ":" in client_msg:
        switch_val, actual_msg = client_msg.split(":")
    else:
        switch_val = client_msg
    if switch_val == "CREATE_PASSWORD" and len(EMAIL) == 0:
        email, passw = actual_msg.split(",")
        EMAIL = email.lstrip("(")
        passw = passw.rstrip(")")
        SALT = (random.getrandbits(64)).to_bytes(8, byteorder='big')
        v = CP36.generate_v(SALT, passw)
        net_utils.send_msg("SUCCESS", client_sock)
    elif switch_val == "AUTH_ATTEMPT" and len(EMAIL) != 0:
        net_utils.send_msg("CONTINUE", client_sock)
        auth_outcome = CP36.server_srp(client_sock, EMAIL, SALT, v)
        if auth_outcome:
            net_utils.send_msg("SUCCESS", client_sock)
        else:
            net_utils.send_msg("FAILED", client_sock)
    else:
        send_msg("FAILED", client_sock)
    

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

    # generate a needed for diffie hellman
    share = input("Input client share as numerical value or [number]G\n Note! If -1 is given share is assumed to be random\n")
    changed_val = False
    if "G" in share:
        g_with_a = CP36.MODPGROUP["1536"] * int(share[:share.index("G")])
        changed_val = True
    elif int(share) == -1:
        a = secrets.randbelow(CP36.MODPGROUP["1536"])
        g_with_a = GroupOp.mod_exp(CP36.GENERATOR, a, CP36.MODPGROUP["1536"])
    else:
        g_with_a = int(share)
        changed_val = True

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
    b_value = msg_ints[1]
    sha_pw_digest = sha256.SHA256()
    sha_pw_digest.Update(bytes("{}||{}".format(salt, password), encoding='utf-8'))
    x_exp = sha_pw_digest.Sum()
    u_digest = sha256.SHA256()
    u_digest.Update(bytes("{}||{}".format(g_with_a, b_value), encoding='utf-8'))
    u = u_digest.Sum()
    v_value = GroupOp.mod_exp(CP36.GENERATOR, x_exp, CP36.MODPGROUP["1536"])
    if changed_val:
        total = int(input("Please give integer input (i.e. S): "))
    else:
        total = (b_value - (CP36.K * v_value)) % CP36.MODPGROUP["1536"]
        total = GroupOp.mod_exp(total, a + (x_exp * u), CP36.MODPGROUP["1536"])
    
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
        print("Usage is python3 {} [client/server]".format(sys.argv[0]))
        sys.exit(1)
    else:
        if sys.argv[1] == "server":
            server.server(server_switch, HOST, PROTOCOL)
        elif sys.argv[1] == "client":
            user_email = input("User's Email: ")
            user_pass = input("User's password: ")
            client(user_email, user_pass)
        else:
            print("Usage is python3 {} [client/server]".format(sys.argv[0]))
