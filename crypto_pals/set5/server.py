from network_utils import *
import CryptoPals33
import sys
import argparse

CLIENT_HOST = "192.168.0.4"

def server_client_thread(socket_to_use, response_msg, mitm_pipe):
    global SHARED_KEY
    global SECRET_KEY
    if type(response_msg) is str:
        response_msg = bytearray(response_msg, encoding='utf-8')
    print("Server is coming from {} and is connected to client at {}".format(socket_to_use.getsockname(), socket_to_use.getpeername()))
    message = receive_msg(socket_to_use)
    print("Server received a message from client")
    if message.startswith(b"ESTABLISH"):
        print("Message to server was to establish key")
        if SHARED_KEY != b"":
            raise ValueError("Key was already established")
        grab_public_param = message[message.find(b"(") + 1:message.find(b")")]
        inner_vals = grab_public_param.split(b",")
        
        # WARNING: you should probably change this arg
        public_param = int(inner_vals[2])
        prime = int(inner_vals[0])
        generator = int(inner_vals[1])

        # Generate your half of the secret and update secret key
        secret, server_public = CryptoPals33.generate_public_key(generator, prime)
        print("Server received from client {}".format(public_param))
        SHARED_KEY = CryptoPals33.generate_shared_key(secret, public_param, prime)
        SECRET_KEY = secret
        # Send notification back to client
        string_param = "ESTABLISH:{}".format(server_public) 
        if send_msg(bytes(string_param, encoding='utf-8'), socket_to_use, mitm_pipe, socket_to_use.getpeername()[1]):
            print("Successfully sent message to client")
        else:
            print("Message unsuccessful, quitting :(")

    elif message.startswith(b"MESSAGE"):
        print("Recieved encrypted message from client")
        encrypted_text_w_IV = message.decode()
        recovered_text = decrypt(SHARED_KEY, encrypted_text_w_IV)
        print("Received " + recovered_text + " from client")
        return_msg = encrypt(SHARED_KEY, response_msg)
        ret_msg = b"MESSAGE:" + return_msg
        send_msg(ret_msg, socket_to_use, mitm_pipe, socket_to_use.getpeername()[1])
    else:
        print("Received disallowed message: {}".foramt(message))
        send_msg(b"METHOD DISALLOWED", socket_to_use, mitm_pipe, socket_to_use.getpeername()[1])
    return


# acts as Bob -- this will be the server
def server(msg_to_party_one, mitm_pipe=None):
    print("Server proc running")
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((HOST, NEW_PROTOCOL))
    server_sock.listen(5) 

    while True:
        (client_sock, addr) = server_sock.accept()
        print("Server says socket should be {}".format(client_sock.getsockname()))
        process_req = threading.Thread(target=server_client_thread, args=(client_sock,msg_to_party_one, mitm_pipe))
        process_req.run()

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
            server(arg_to_send)
    elif fileOrString == "s":
        server(filenameOrString)
    else:
        print("Usage is incorrect. Correct usage is: python3 {} [f|s] [filename | string]")
