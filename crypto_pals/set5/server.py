import sys
import socket
import threading

CLIENT_HOST = "192.168.0.4"

def server(server_func, HOST, PROTOCOL):
    print("Server proc running")
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((HOST, PROTOCOL))
    server_sock.listen(5) 

    while True:
        (client_sock, addr) = server_sock.accept()
        print("Server says socket should be {}".format(client_sock.getsockname()))
        process_req = threading.Thread(target=server_func, args=(client_sock,))
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
