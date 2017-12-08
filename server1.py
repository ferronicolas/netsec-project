import socket, argparse, math, threading
import PoW, incoming_control, Diffie_hellman,saltpassword, userdatabase,check_data_format
from file_handler import create_server_file
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
PUZZLE_MESSAGE = 'puzzle'

# Error messages
ERROR_MUST_ENTER_POSITIVE = "You must enter a positive number"

# Global constants
BUFFER_SIZE = 1024
PUBLIC_KEY_FULL_PATH = "public_key_4096.der"
PRIVATE_KEY_FULL_PATH = "private_key_4096.der"

# Global variables
current_users = {}
server_socket = None
pow_length = 3

# Hardcoded values
server_private_key = "path/to/private/key"
server_public_key = "path/to/public/key"

# Threads
threads = []

# Charsets
hex_set = set('abcdef123456789')


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
        init_socket(port)
        while True:
            data, address = server_socket.recvfrom(BUFFER_SIZE)
            message = data.split()
            if len(message) > 0:
                if message[0] == SIGN_IN_MESSAGE:
                    handle_sign_in(address)
                elif message[0] == LIST_MESSAGE:
                    server_socket.sendto(make_current_users_message(), address)
                elif message[0] == GET_ADDRESS_OF_USER:
                    server_socket.sendto(make_get_address_of_user_response(message[1]), address)
                elif message[0] == PUZZLE_MESSAGE:
                    handle_puzzle_response(message, address)
                else:
                    server_socket.sendto(ILLEGAL_MESSAGE_RESPONSE + " You just typed in an invalid command", address)
    except socket.error, exc:  # If address is already in use it will throw this exception
        print exc.strerror


def init_socket(port):
    global server_socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(('', port))
    create_server_file(get_ip_address(), port)
    print "Server initialized..."
    control_incoming_request()


def handle_sign_in(address):
    global pow_length
    pow_length = incoming_control.get_pow_length(pow_length)
    r1, r2, hash_value = PoW.proof_o_work(pow_length)
    server_socket.sendto(str(r1) + ',' + str(hash_value), address)
    current_users[address[0], address[1]] = r2  # addres: (IP address, port)


def handle_puzzle_response(message, address):
    if check_data_format.check_charset(message[1], hex_set):
        if current_users[address[0], address[1]] == message[1]:  # check PoW
            username, password, r1, df_contribution = message[2].split(',')
            if saltpassword.check(userdatabase.get_salt_user(username), password, userdatabase.get_hash_user(username)):
                shared_key, server_contribution = Diffie_hellman.server_contribution(int(df_contribution))
                server_socket.sendto(str(r1) + ',' + str(server_contribution), address)


def control_incoming_request():
    """
    Function that resets the counter in the 'incoming_control.py' module.
    :return:
    """
    threading.Timer(30, control_incoming_request).start()
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
