from network_utils import *
from crypto_pals.set4 import SHA1
IFACE="eth2"

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
            mitm_packets_captured = sniff(iface=IFACE, timeout=10)
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
                    pkt_to_process = srp1(pkt_to_process, iface=IFACE)
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
                    pkt_to_process = srp1(new_pkt, iface=IFACE)
                    
                    print("Packet received was the following: ")
                    pkt_to_process.show()
                    print("Mitm: Finished sending packets to server as client")
                    
                else:
                    recover_msg = decrypt(key, message.decode())
                    print("Man in the middle recovered message from client: {}".format(recover_msg)) 
 
