# yay! Fun networking time -- I get to build an echo bot 
import multiprocessing, threading
import time
from scapy.all import *
import socket, struct
import sys
sys.path.append("/home/becgabri/Documents/Personal/CryptoPals/")
from network_utils import *
IFACE = "lo"
######################################################################################

# NOTES 1/21/2019
# TODO: figure out why the tcp retransmission is still occuring, and fake a ack from the client to the server

######################################################################################

# note that this value will only be shared with multiple threads in the same process
# NOT different processes
SHARED_KEY = b""
SECRET_KEY = b""
NEW_PROTOCOL = 50021

def main():
    msg1 = "Free Falling"
    msg2 = "Elisabeth Gaskell"
    # spin up two child processes and have them communicate with each other
    if ENABLE_MITM:
        server_pipe, mitm_server_pipe = multiprocessing.Pipe()
        client_pipe, mitm_client_pipe = multiprocessing.Pipe()
        server_proc = multiprocessing.Process(target=server, args=(msg1, server_pipe))
        client_proc = multiprocessing.Process(target=client, args=(msg2, client_pipe))
        mitm = multiprocessing.Process(target=man_in_the_middle, args=(mitm_server_pipe, mitm_client_pipe))
        server_proc.start()
        client_proc.start()
        mitm.start()
        print("Server pid: {}, Client pid: {}, MitM pid: {}".format(server_proc.pid, client_proc.pid, mitm.pid))
    else:
        server_proc = multiprocessing.Process(target=server, args=(msg1,))
        client_proc = multiprocessing.Process(target=client, args=(msg2,))
        server_proc.start()
        client_proc.start()
    return

if __name__ == "__main__":
    """
    test_one = 150 << 16 |
    test_two = 63
    
    addAndNegate()
    """
    main()
