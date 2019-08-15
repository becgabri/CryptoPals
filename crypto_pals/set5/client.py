from network_utils import *
import CrytpoPals33
SERVER_HOST = "192.168.0.8"

# acts as Alice -- this will be the client
# produces the group and generator for Z_p and sends to Bob
# p (group) as in Z_p, g as the generator, and A = g**a mod Z_p
def client(msg, mitm_pipe=None):
    print("Client proc running")
    time.sleep(5)
    print("Client proc woke from sleeping")
    if type(msg) is str:
        msg = bytearray(msg, encoding='utf-8')
    p, g = CryptoPals33.generate_prime_and_generator()
    secret, publicval = CryptoPals33.generate_public_key(g,p)
    # :P
    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_sock.connect((HOST, NEW_PROTOCOL))
    # ESTABLISH: (p, g, A)
    print("Client is coming from {} and is connected to {}".format(client_sock.getsockname(), client_sock.getpeername()))
    string_params = "ESTABLISH: ({},{},{})".format(p, g, publicval)
    send_msg(string_params, client_sock, mitm_pipe, client_sock.getsockname()[1])
    #receive message 
    receive_message = receive_msg(client_sock)
    if receive_message.startswith(b"ESTABLISH"):
        grab_public_param = receive_message[receive_message.find(b":")+1:]
        public_param = int(grab_public_param)
        shared_key = CryptoPals33.generate_shared_key(secret, public_param, p)
        # now try to send message
        new_msg = encrypt(shared_key, msg)
        second_client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        second_client_sock.connect((SERVER_HOST, NEW_PROTOCOL))
        print("Second Client side information is {}".format(second_client_sock.getsockname()))
        send_msg(b"MESSAGE:" + new_msg, second_client_sock, mitm_pipe, second_client_sock.getsockname()[1])
        recv_msg = receive_msg(second_client_sock)
        recv_msg = recv_msg.decode()
        decrypted_text = decrypt(shared_key, recv_msg)
        print(decrypted_text)
    return

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage is incorrect. Correct usage is: python3 {} [f|s] [filename | string]".format())
        sys.exit(1)

    fileOrString = sys.argv[1]
    filenameOrString = sys.argv[2]

    if fileOrString =="f":
        with open(filenameOrString, "r") as read_f:
            arg_to_send = read_f.read()
            client(arg_to_send)
    elif fileOrString == "s":
        client(filenameOrString)
    else:
        print("Usage is incorrect. Correct usage is: python3 {} [f|s] [filename | string]")
