import socket, argparse, math, threading, os, base64
import PoW, incoming_control, Diffie_hellman, saltpassword, userdatabase, check_data_format, symmetric_encryption
from file_handler import create_server_file
import netifaces as ni
from time_handler import get_expiration_of_puzzle, is_timestamp_valid
from asymmetric_encryption import decrypt_message

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
INCORRECT_USER_PASS_MESSAGE = "incorrect_user_pass"
LOGOUT_MESSAGE = 'logout'

# Error messages
ERROR_MUST_ENTER_POSITIVE = "You must enter a positive number"

# Global constants
BUFFER_SIZE = 1024
PRIVATE_KEY_FULL_PATH = "private_key_8192.der"

# Global variables
current_users = {}
ip_port_association = {}
server_socket = None
pow_length = 3

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
                elif message[0] == PUZZLE_MESSAGE:
                    handle_puzzle_response(data, message, address)
                elif (address in ip_port_association) and ip_port_association[address][0] and len(message) == 4:
                    # Thus message is encrypted with symmetric key (-> decrypting is a cheap operation )
                    handle_symmetric_encrypted_data(address, message)
                else:
                    server_socket.sendto(ILLEGAL_MESSAGE_RESPONSE + " You just typed in an invalid command", address)
            else:
                server_socket.sendto(ILLEGAL_MESSAGE_RESPONSE + " You just typed in an invalid command", address)
    except socket.error, exc:  # If address is already in use it will throw this exception
        print exc.strerror
        exit(1)
    except Exception, exc:
        print exc
        exit(1)


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
    # Add puzzle result to dictionary
    ip_port_association[address] = [False, r2, get_expiration_of_puzzle()]  # [Logged_in, result_puzzle, expiration_puzzle]
    server_socket.sendto(str(r1) + ',' + str(hash_value), address)


def handle_puzzle_response(data, message, address):
    if len(message) > 2 and (address in ip_port_association) and ip_port_association[address][0] == False \
            and ip_port_association[address][1] == message[1]:  # Puzzle valid
        message_to_decrypt = data.split(message[0] + " " + message[1] + " ", 1)[1]
        print message_to_decrypt
        print "ENCRYTPED MESSAGE: " + message_to_decrypt
        message_decrypted = decrypt_message(PRIVATE_KEY_FULL_PATH, message_to_decrypt)
        print "DECRYPTED MESSAGE: " + message_decrypted
        payload = message_decrypted.split(',')
        if len(payload) == 4:
            username, password, random_number, df_contribution = payload

            # Check if username in db
            if userdatabase.is_user_registered(username) and saltpassword.check(userdatabase.get_salt_user(username), password,
                        userdatabase.get_hash_user(username)):
                shared_key, server_contribution = Diffie_hellman.server_contribution(int(df_contribution))

                shared_key = shared_key.decode("hex")
                # Put shared key in dictionary
                ip_port_association[address] = [True, shared_key, username]
                current_users[username] = address
                server_socket.sendto(str(random_number) + ',' + str(server_contribution), address)
            else:
                server_socket.sendto(make_invalid_user_password_response(), address)


def handle_symmetric_encrypted_data(address,message):
    # Message is encrypted and client already set shared key
    decrypted_message = symmetric_encryption.decrypt(ip_port_association[address][1], message)
    split_decrypted_message = decrypted_message.split()

    if len(split_decrypted_message) == 3 and split_decrypted_message[0] == LIST_MESSAGE:  # Check if message is a list
        handle_list_message(split_decrypted_message, address)
    elif split_decrypted_message[0] == LOGOUT_MESSAGE and len(split_decrypted_message) == 2:
        handle_logout(split_decrypted_message, address)
    elif 0:  # send
        pass
    else:
        pass  # we will see


def handle_list_message(split_decrypted_message, address):
    list_random_number = split_decrypted_message[1]
    try:
        timestamp = float(split_decrypted_message[2])
        if is_timestamp_valid(timestamp):
            server_socket.sendto(make_current_users_message(ip_port_association[address][1], list_random_number), address)
        else:
            print "Timestamp invalid DEBUG"
    except Exception, exc:
        print 'exception: ', exc


def handle_logout(split_decrypted_message,address):
    try:
        timestamp = float(split_decrypted_message[1])
        if is_timestamp_valid(timestamp):
            server_socket.sendto(make_user_logout_message(ip_port_association[address][1]), address)
            status, shared_key, username = ip_port_association[address]
            del current_users[username]
            del ip_port_association[address]
        else:
            print "Timestamp invalid DEBUG"
    except Exception, exc:
        print exc


def make_user_logout_message(shared_key):
    payload = LOGOUT_MESSAGE
    associated_data = os.urandom(16)
    return symmetric_encryption.encrypt(shared_key, payload, associated_data)

def control_incoming_request():
    """
    Function that resets the counter in the 'incoming_control.py' module.
    :return:
    """
    threading.Timer(30, control_incoming_request).start()
    incoming_control.reset()


def make_current_users_message(shared_key, list_random_number):
    usernames = current_users.keys()
    if len(usernames) == 1:
        message = LIST_RESPONSE_MESSAGE + " " + list_random_number + " Signed in user: " + usernames[0]
    elif len(usernames) > 1:
        message = LIST_RESPONSE_MESSAGE + " " + list_random_number + " Signed in users: " + ', '.join(current_users.keys())
    else:  # No users connected
        message = LIST_RESPONSE_MESSAGE + " " + list_random_number + " There are no signed in users"
    associated_data = os.urandom(16)
    return symmetric_encryption.encrypt(shared_key, message, associated_data)


def make_get_address_of_user_response(username):
    if username in current_users:
        ip, port = current_users[username]
        return GET_ADDRESS_OF_USER_RESPONSE + ' {"ip":"' + ip + '", "port":' + str(port) + '}'
    else:
        return ILLEGAL_MESSAGE_RESPONSE + " The username " + username + " doesn't exist"


def make_invalid_user_password_response():
    return INCORRECT_USER_PASS_MESSAGE + " User/Password combination incorrect"


if __name__ == "__main__":
    start_server()
