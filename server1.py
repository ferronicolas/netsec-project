import socket, argparse, PoW, math, incoming_control, threading, Diffie_hellman
from file_handler import create_file
import sched, time
import netifaces as ni

# Flags
PORT_FLAG = "-sp"

# Messages
SIGN_IN_MESSAGE = "sign_in"
LIST_MESSAGE = "list"
LIST_RESPONSE_MESSAGE = "list_response"
GET_ADDRESS_OF_USER = "get_address_of_user"
GET_ADDRESS_OF_USER_RESPONSE = "get_address_of_user_response"
ILLEGAL_MESSAGE_RESPONSE = "illegal"

# Error messages
ERROR_MUST_ENTER_POSITIVE = "You must enter a positive number"

# Global constants
BUFFER_SIZE = 1024

# Global variables
current_users = {}
server_socket = None
pow_length = 3

# Hardcoded values
#server_private_key = "path/to/private/key"
#server_public_key = "path/to/public/key"

#threads
threads = []


def start_server():
    port = check_arguments()
    if port:
        listen_on_port(port)


# Checks that the program was called with the following 3 arguments: server.py, -sp, port number
def check_arguments():
    parser = argparse.ArgumentParser(description="Server for secure chat application")
    parser.add_argument(PORT_FLAG, type=check_if_positive, required=True)
    args = parser.parse_args()
    return args.sp


# Checks if number is positive
def check_if_positive(input_number):
    try:
        number = int(input_number)
        if number <= 0:
            raise argparse.ArgumentTypeError(ERROR_MUST_ENTER_POSITIVE)
        return number
    except ValueError:
        raise argparse.ArgumentTypeError(ERROR_MUST_ENTER_POSITIVE)


# Gets IP address of current host
def get_ip_address():
    interface = 'eth0'  # Windows
    try:
        ni.ifaddresses(interface)
        return ni.ifaddresses(interface)[ni.AF_INET][0]["addr"]
    except ValueError:
        interface = 'en0'  # Unix-like systems
        ni.ifaddresses(interface)
        return ni.ifaddresses(interface)[ni.AF_INET][0]["addr"]


# Establishes UDP socket
def listen_on_port(port):
    try:
        global server_socket
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_socket.bind(('', port))
        create_file(get_ip_address(), port)
        print "Server initialized..."
        control_incoming_request()
        while True:
            data, address = server_socket.recvfrom(BUFFER_SIZE)
            message = data.split()
            print message
            if len(message) > 0:
                if message[0] == SIGN_IN_MESSAGE:
                    current_users[message[1]] = (address[0], address[1])  # USERNAME: (IP address, port)
                    global pow_length
                    pow_length = incoming_control.get_pow_length(pow_length)
                    r1,r2,hash_value = PoW.proof_o_work(pow_length)
                    print r2
                    server_socket.sendto(str(r1) + ',' + str(hash_value), address)
                    print 'finished'
                    #send r2 to client
                    #data, address = server_socket.recvfrom(BUFFER_SIZE)

                    # get Answer, if correct then process rest of message (username,password,R1,g^a)
                    # send back R1,g^b encrypted with private key (integrity)
                elif message[0] == LIST_MESSAGE:
                    server_socket.sendto(make_current_users_message(), address)
                elif message[0] == GET_ADDRESS_OF_USER:
                    server_socket.sendto(make_get_address_of_user_response(message[1]), address)
                elif message[0] == 'puzzle':
                    print PoW.check_proof_o_work(r1, message[1],hash_value)
                    if PoW.check_proof_o_work(r1, message[1],hash_value):
                        username, password, r1, df_contribution = message[2].split(',')
                        print df_contribution
                        #check password
                        #
                        shared_key, server_pubkey = Diffie_hellman.server_contribution(int(df_contribution))
                        server_socket.sendto(str(r1) + ',' + str(server_pubkey), address)
                        print 'shared_key:', shared_key

                    else:
                        print 'pow failed'
            else:
                server_socket.sendto(ILLEGAL_MESSAGE_RESPONSE + " You just typed in an invalid command", address)
    except socket.error, exc:  # If address is already in use it will throw this exception
        print exc.strerror

def receive():
    data, address = server_socket.recvfrom(BUFFER_SIZE)
    return data, address



def control_incoming_request ():
    """
    Function that resets the counter in the 'incoming_control.py' module.
    :return:
    """
    threading.Timer(30, control_incoming_request).start ()
    incoming_control.reset()



def make_current_users_message():
    usernames = current_users.keys()
    if len(usernames) == 1:
        return LIST_RESPONSE_MESSAGE + " Signed in user: " + usernames[0]
    elif len(usernames) > 1:
        return LIST_RESPONSE_MESSAGE + " Signed in users: " + ', '.join(current_users.keys())


def make_get_address_of_user_response(username):
    if username in current_users:
        ip, port = current_users[username]
        return GET_ADDRESS_OF_USER_RESPONSE + ' {"ip":"' + ip + '", "port":' + str(port) + '}'
    else:
        return ILLEGAL_MESSAGE_RESPONSE + " The username " + username + " doesn't exist"


if __name__ == "__main__":
    start_server()
