SIZE_MESSAGE = struct.calcsize("i")
NEW_PROTOCOL = 50021
from crypto_pals.set1 import CryptoPals7
from crypto_pals.set2 import CryptoPals11

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