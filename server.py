import socket
import argparse
import PoW
import math
import do_proof_o_work
import incoming_control

# Flags
PORT_FLAG = "-sp"

# Messages
SIGN_IN_MESSAGE = "sign_in"
LIST_MESSAGE = "list"
LIST_RESPONSE_MESSAGE = "list_response"
GET_ADDRESS_OF_USER = "get_address_of_user"
GET_ADDRESS_OF_USER_RESPONSE = "get_address_of_user_response"
ILLEGAL_MESSAGE_RESPONSE = "illegal"

# Global variables
current_users = {}
server_socket = None

# Hardcoded values
server_private_key = "path/to/private/key"
server_public_key = "path/to/public/key"


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
            raise argparse.ArgumentTypeError("You must enter a positive number")
        return number
    except ValueError:
        raise argparse.ArgumentTypeError("You must enter a positive number")


# Establishes UDP socket
def listen_on_port(port):
    global server_socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(('', port))
    print "Server initialized..."
    #make file with server configuration stuff.
    while True:
        data, address = server_socket.recvfrom(1024)  # Buffer size = 1024 bytes
        message = data.split()
        incoming_control.main(1)
        if len(message) > 0:
            if message[0] == SIGN_IN_MESSAGE:
                current_users[message[1]] = (address[0], address[1])  # USERNAME: (IP address, port)
                #The following code is a work around the PoW. Since us.random generates random bytes this creates large
                #jumps in computational time. (2 bytes = 1 second, 3 bytes = 30 seconds). By dividing 1000 over m, the
                # larger m gets, the smaller 1000/m gets, so the computational jump will be less big.
                m = 5
                r1,r2,hash_value = PoW.proof_o_work(int(math.floor(1000/m)),m)
                r2_computed = do_proof_o_work.compute_r2(r1,hash_value)
                print PoW.check_proof_o_work(r1,r2_computed,hash_value)
                # get Answer, if correct then process rest of message (username,password,R1,g^a)
                # send back R1,g^b encrypted with private key (integrity)
            elif message[0] == LIST_MESSAGE:
                server_socket.sendto(make_current_users_message(), address)
            elif message[0] == GET_ADDRESS_OF_USER:
                server_socket.sendto(make_get_address_of_user_response(message[1]), address)
            else:
                server_socket.sendto(ILLEGAL_MESSAGE_RESPONSE + " You just typed in an invalid command", address)
        else:
            server_socket.sendto(ILLEGAL_MESSAGE_RESPONSE + " You just typed in an invalid command", address)


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
