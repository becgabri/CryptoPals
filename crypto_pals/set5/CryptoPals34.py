# yay! Fun networking time -- I get to build an echo bot 
import multiprocessing, threading
import time
from scapy.all import *
import socket, struct
import sys
#sys.path.append('/mnt/c/Users/becga/Documents/crypto_pals/')
sys.path.append('C:\\Users\\becga\\Documents\\crypto_pals')
from crypto_pals.set4 import SHA1
from crypto_pals.set1 import CryptoPals7
from crypto_pals.set2 import CryptoPals11
import CryptoPals33

######################################################################################

# NOTES 1/21/2019
# TODO: figure out why the tcp retransmission is still occuring, and fake a ack from the client to the server

######################################################################################

# note that this value will only be shared with multiple threads in the same process
# NOT different processes
SHARED_KEY = b""
SECRET_KEY = b""
NEW_PROTOCOL = 50021
HOST = "127.0.0.1"
ENABLE_MITM = True
SIZE_MESSAGE = struct.calcsize("i")
# decision: do I also add the Miller-Rabin test and create 
# p where p is a safe prime ??? No, that would defeat the purpose
# of this attack... pretty sure.
def IPStringtoNumber(ip_addr_string):
    parse_list = ip_addr_string.split(".")
    if len(parse_list) != 4:
        raise ValueError("Address is not IPv4")
    sum_addr = 0
    for idx, elt in enumerate(parse_list):
        sum_addr = sum_addr + (int(elt) << ((len(parse_list) - 1 - idx) * 8))
    return sum_addr

# this number should already be correctly padded to the right with 0's
def addAndNegate(number_to_sum):
    mask = (2**16) - 1
    # round up to a multiple of 16
    # this should only happen if [empty][rest of number]\
    num_bits = number_to_sum.bit_length()
    total_number_chunks = (num_bits + 15) // 16
    """
    if number_to_sum.bit_length != (total_number_chunks * 16):
        print("Not the correct size, padding on the right")
        number_to_sum = number_to_sum << ((16 - num_bits) % 16)

        assert (number_to_sum.bit_length() % 16) == 0
    """
    sum_vals = 0
    for chunk in range(total_number_chunks - 1, -1, -1):
        sixteenbit_chunk = (number_to_sum >> (16 * chunk)) & mask
        sum_vals = sum_vals + sixteenbit_chunk
        while sum_vals > mask:
            leftover = sum_vals >> 16
            sum_vals = (sum_vals & mask) + leftover
        assert sum_vals <= 2**16
    neg_compl = sum_vals ^ mask
    return neg_compl

def calculateTCPChecksum(tcp_packet):
    # calculate the new tcp checksum
    # zero out the old checksum
    tcp_packet[TCP].chksum = 0
    pseudo_header = 0
    pseudo_header = (IPStringtoNumber(tcp_packet[IP].src)) << 32 | IPStringtoNumber(tcp_packet[IP].dst)
    # the 8 here is for the reserved field of the pseudo header
    pseudo_header = pseudo_header << 8
    pseudo_header = pseudo_header << 8 | tcp_packet[IP].proto
    tcp_size = len(tcp_packet[TCP])
    pseudo_header = pseudo_header << (2 * 8) | tcp_size
    
   
    tcp_segment = bytes(tcp_packet[TCP])
    #tcp_segment = int.from_bytes(bytes(tcp_packet[TCP]), byteorder='big')
    tcp_segment = int.from_bytes(tcp_segment, byteorder='big')
    for_final_sum = pseudo_header << (len(bytes(tcp_packet[TCP])) * 8) | tcp_segment
    if len(bytes(tcp_packet[TCP])) & 1:
        print("Length of tcp segment is odd, padding with octet of 0s")
        for_final_sum  = for_final_sum << 8
    
    new_chk_sum = addAndNegate(for_final_sum)
    return new_chk_sum

def PackForSending(msg_to_pack):
    if type(msg_to_pack) is str:
        raise TypeError("Message must be a byte array, not str")
    msg_to_send = struct.pack("i" + str(len(msg_to_pack)) + "s", len(msg_to_pack), msg_to_pack)
    return msg_to_send

# takes message either as a byte array or as a string 
def send_msg(message, socket_t, man_pipe=None, client_port_num=0):
    if type(message) is str:
        message = bytearray(message, encoding='utf-8')
    if man_pipe != None:
       print("Sending over mitm pipe")
       print("Port number is {}".format(client_port_num))
       man_pipe.send([client_port_num,message])
       time.sleep(15)
       print("Sending proc has woken up")
       # this is simulating that the packet was dropped
       return 1
    print("Attempting to send message")
    send_msg = PackForSending(message)
    msg_size = len(send_msg)
    sent = 0
    try:
        while sent < msg_size:
            managed_to_send = socket_t.send(send_msg[sent:])
            sent += managed_to_send
        print("Succeeded in sending {} bytes: {}".format(sent, send_msg[:50]))
        return 1
    except:
        print("Failed in attempt")
        return 0

def receive_msg(socket_t):
    # keep receiving up until :
    msg_received = b""
    no_data = True
    data_to_consume = 0
    partial_scan_str = b""

    while no_data or data_to_consume > 0:
        first_half = socket_t.recv(1024)
        if no_data:
            partial_scan_str += first_half
            if len(partial_scan_str) < SIZE_MESSAGE:
                continue
        
            size, leftover = struct.unpack("i" + str(len(partial_scan_str) - SIZE_MESSAGE) + "s", partial_scan_str)
            msg_recovered = struct.unpack(str(len(partial_scan_str)) + "s", partial_scan_str)
            data_to_consume = size - len(leftover)
            print("Data to consume is {}".format(size))
            no_data = False
            msg_received += leftover
            print(msg_received)
        else:
            msg_received += first_half
            data_to_consume -= len(first_half)
            print(msg_received)
    return msg_received 

# wrapper to do encryption for AES 128 bit 
def decrypt(key, message):
    iv_start_idx = message.find(":")
    iv_end_idx = message.find("|")
    iv = message[iv_start_idx+1: iv_end_idx]
    decrypted = CryptoPals7.DECRYPTION_CBC_MODE(iv, key, message[iv_end_idx+1:], CryptoPals7.decrypt_aes)
    return decrypted

# wrapper for CBC AES 128 bit key encryption with IV prepended
def encrypt(key, message):
    new_IV = CryptoPals11.generate_rand_IV()
    new_msg = CryptoPals7.ENCRYPTION_CBC_MODE(new_IV, key, message, CryptoPals7.encrypt_aes)
    new_msg = bytearray(new_IV, encoding='utf-8') + b"|" + new_msg.encode()
    return new_msg

def man_in_the_middle(server_pipe, client_pipe):
    # .... so do I wait for them to try and send things across the wire??
    # maybe???? .... have them send a signal? 
    # wait until a signal is sent, check the client pipe and server pipe 
    # for data, figure out the stage of the program and send the appropriate msgi
    prime = 0

    # this base will be 0 no matter what because it is p*k for some 
    #integer k mod p  
    sha1_dgst = SHA1.SHA1()
    zero_key = 0
    sha1_dgst.Update(zero_key.to_bytes(zero_key.bit_length() + 7 // 8, byteorder='big'))
    key = sha1_dgst.Sum()
    pkt_to_process = None
    client_seq_num = 0
    server_seq_num = 0
    while True:
        print("Man in the middle is waiting to receive from pipe")
        # this timeout is just designed to be long enough
        if pkt_to_process is None:
            print("MitM is attempting to capture network traffic")
            mitm_packets_captured = sniff(iface="Npcap Loopback Adapter", timeout=10)
            print("MitM woke up --- I need a better way to do this")
            relevant_pkts = []
            for pkt in mitm_packets_captured:
                if TCP in pkt:
                    if pkt[TCP].sport == NEW_PROTOCOL or pkt[TCP].dport == NEW_PROTOCOL:
                        relevant_pkts.append(pkt)

            if len(relevant_pkts) != 1:
                if len(relevant_pkts) > 1:
                    print("There was more than one message captured")
                else:
                    print("No packets captured, continue loop")
                    continue
            # TCP segment 
            for pkt in relevant_pkts:
                pkt.show()
            pkt_to_process = relevant_pkts[-1]
        print("Waiting to receive from client/server pipes")
        ready_list = multiprocessing.connection.wait([server_pipe, client_pipe])
        for pipe in ready_list:
            port, message = pipe.recv()
            port = int(port)
            #mal_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # the sending server gives this to mitm
            if pipe.fileno() == server_pipe.fileno():
                print("Received response from server in MitM")
                # forward on to client p
                if prime == 0:
                    raise ValueError("This should have been changed")
                #mal_socket.connect((HOST, protocol)) 
                if message.startswith(b"ESTABLISH"):
                    print("Pretending to be server to client from port {} to port {}".format(NEW_PROTOCOL, port))
                    to_send_on = "ESTABLISH:{}".format(prime)
                    to_send_on = PackForSending(bytes(to_send_on, encoding='utf-8'))
                    # check different sequence numbers and try to send packet to server 
                    # I'm going to try and NOT fake the ack, although I arguably should... 
                    # this will just be a PA then 
                    if not pkt_to_process:
                        raise ValueError("Something broke :( sad.")
                    print("Last packet captured")
                    pkt_to_process.show()
                    
                    # drop the padding
                    pkt_to_process.getlayer(2).remove_payload()
                    pkt_to_process[TCP].flags = "PA"
                    #pkt_to_process[TCP].options = ''
                    pkt_to_process[IP].id = pkt_to_process[IP].id + 1
                    pkt_to_process[TCP].seq = server_seq_num
                    pkt_to_process[TCP].ack = client_seq_num
                    pkt_to_process[TCP].dataofs = 5
                    pkt_to_process[TCP].options = ''
                    #pkt_to_process[TCP].payload = to_send_on
                    pkt_to_process = pkt_to_process / Raw(load=to_send_on)
                    
                    new_chksum = calculateTCPChecksum(pkt_to_process)
                    pkt_to_process[TCP].chksum = new_chksum

                    #ack_data = ack_data / TCP(dport=port, sport=NEW_PROTOCOL, flags="A", seq=mitm_packets_captured[0][TCP].ack, ack=mitm_packets_captured[0][TCP].seq + )
                    pkt_to_process = srp1(pkt_to_process, iface="Npcap Loopback Adapter")
                    #pkt_to_process = None
                    print("Packet received was the following: ")
                    pkt_to_process.show()
                    print("Sent packets pretending to be server, mitm")
                else:
                    # now try to decrypt message
                    recover_msg = decrypt(key, message.decode())
                    print("Man in the middle recovered message from server: {}".format(recover_msg))
                          
            else:
                # forward to server p, g, p
                #print("Received response in MITM, forward to server")
                
                if message.startswith(b"ESTABLISH"):
                    print("Pretending to be client to server from port {} to port {}".format(port, NEW_PROTOCOL))

                    inner_params = message[message.find(b"(") + 1: message.find(b")")]
                    inner_params = inner_params.split(b",")
                    print("Established prime")
                    prime = int(inner_params[0])
                    generator = int(inner_params[1])
                    print("attempting to connect to server")
                
                    to_send_on = "ESTABLISH: ({},{},{})".format(prime, generator, prime)
                    to_send_on = bytes(to_send_on, encoding='utf-8')
                    to_send_on = struct.pack("i" + str(len(to_send_on)) + "s", len(to_send_on), to_send_on)
                    new_pkt = None

                    if pkt_to_process[TCP].sport != NEW_PROTOCOL and pkt_to_process[TCP].flags == 'A':
                        part_of_pkt = pkt_to_process[TCP]
                        print("From the packet sniffed {}".format(hex(int.from_bytes(part_of_pkt, byteorder='big'))))
                        new_pkt = pkt_to_process
                        if server_seq_num == 0 and client_seq_num == 0:
                            server_seq_num = new_pkt[TCP].ack
                            client_seq_num = new_pkt[TCP].seq
                            print("Updated server number to {} and client to {}".format(server_seq_num,client_seq_num))
                        print(new_pkt[TCP])
                        old_chk_sum = new_pkt[TCP].chksum 
                        new_pkt.getlayer(2).remove_payload()
                        
                        new_pkt[TCP].flags = "PA"
                        # increment the ip identification number so the server doesn't think this is a duplicate
                        new_pkt[IP].id = new_pkt[IP].id + 1
                        
                        #new_pkt[TCP].payload = bytes(to_send_on)
                        new_pkt = new_pkt / Raw(load=to_send_on)

                        # calculate the new tcp checksum
                        newchecksum = calculateTCPChecksum(new_pkt)
                        
                        new_pkt[TCP].chksum = newchecksum 
                    else:
                        print("This shouldn't happen! Quitting ")
                        sys.exit(1)
                    new_pkt.show()
                    print ("Sending packet")
                    # what should I do here? sendp
                    pkt_to_process = srp1(new_pkt, iface="Npcap Loopback Adapter")
                    
                    print("Packet received was the following: ")
                    pkt_to_process.show()
                    print("Mitm: Finished sending packets to server as client")
                    
                else:
                    recover_msg = decrypt(key, message.decode())
                    print("Man in the middle recovered message from client: {}".format(recover_msg)) 
 
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
        second_client_sock.connect((HOST, NEW_PROTOCOL))
        print("Second Client side information is {}".format(second_client_sock.getsockname()))
        send_msg(b"MESSAGE:" + new_msg, second_client_sock, mitm_pipe, second_client_sock.getsockname()[1])
        recv_msg = receive_msg(second_client_sock)
        recv_msg = recv_msg.decode()
        decrypted_text = decrypt(shared_key, recv_msg)
        print(decrypted_text)
    return

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
