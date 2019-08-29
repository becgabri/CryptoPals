import sys
import socket
import threading

HOST = "127.0.0.1"
PROTOCOL = 4509

def server(server_func, host, protocol, *args):
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((host,protocol))
    server_sock.listen(5) 

    while True:
        (client_sock, addr) = server_sock.accept()
        process_req = threading.Thread(target=server_func, args=(client_sock,*args))
        process_req.run()

    return


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage is incorrect. Correct usage is: python3 {} [f|s] [filename | string]".format(sys.argv[0]))
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
        print("Usage is incorrect. Correct usage is: python3 {} [f|s] [filename | string]".format(sys.argv[0]))
