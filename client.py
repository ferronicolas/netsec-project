import socket, threading, json, os, binascii, getpass
import PoW, Diffie_hellman, symmetric_encryption
from errno import ENOENT
from file_handler import read_server_file
from excep import InvalidIPAddressError, InvalidPortError
from time_handler import get_current_timestamp
from asymmetric_encryption import encrypt_message

# Flags
USER_FLAG = "-u"
SERVER_IP_FLAG = "-sip"
SERVER_PORT_FLAG = "-sp"

# Messages
SIGN_IN_MESSAGE = "sign_in"
LIST_MESSAGE = "list"
LIST_RESPONSE_MESSAGE = "list_response"
GET_ADDRESS_OF_USER = "get_address_of_user"
PUZZLE_RESPONSE = 'puzzle'
GET_ADDRESS_OF_USER_RESPONSE = "get_address_of_user_response"
ILLEGAL_MESSAGE_RESPONSE = "illegal"
SEND = "send"
INCORRECT_USER_PASS_MESSAGE = "incorrect_user_pass"
LOGOUT_MESSAGE = 'logout'


# Exception messages
INVALID_IP_EXCEPTION = "The IP address of the server is invalid"
INVALID_PORT_EXCEPTION = "The port number of the server is invalid"
SERVER_DOWN = "The server is down"
FILE_DOESNT_EXIST = "The server hasn't created the configuration file yet"

# Global constants
WAIT_FOR_SERVER = "Connecting to server..."
ENTER_USERNAME = "Enter your username: "
USERNAME_CANT_BE_BLANK = "Username can't be blank. Enter it again: "
ENTER_PASSWORD = "Enter your password: "
PASSWORD_CANT_BE_BLANK = "Password can't be blank. Enter it again: "
DO_YOU_WANNA_TRY_AGAIN = "Do you wanna try again? (Y/N) "
SHARED_KEY_COULDNT_BE_ESTABLISHED = "Shared key couldn't be established"
BUFFER_SIZE = 1024
SERVER_PUBLIC_KEY_FULL_PATH = "public_key_4096.der"

# Global variables
client_socket = None
threads = []
my_username = ""
server_ip = 0
server_port = 0
current_message = ""  # Message that I want to send
shared_key = 0
shared_key_set = False
list_random_number = 0



def start_client():
    global server_ip, server_port
    try:
        server_ip, server_port = read_server_file()
        server_ip = check_if_ipv4(server_ip)
        server_port = check_if_valid_port(server_port)
        if check_if_server_up():
            # my_username = raw_input(ENTER_USERNAME)
            # my_password = raw_input(ENTER_PASSWORD)
            # if my_username:  # Checks if it got arguments
            # start_input_thread()
            print WAIT_FOR_SERVER
            start_socket_thread()
        else:
            print SERVER_DOWN
    except InvalidIPAddressError as error:
        print error.message
        exit(1)
    except InvalidPortError as error:
        print error.message
        exit(1)
    except IOError, e:
        if e.errno == ENOENT:  # File doesn't exist - print custom message
            print FILE_DOESNT_EXIST
            exit(1)
        else:
            print e.strerror
            exit(1)


def check_if_server_up():
    return True


# Checks if IP supplied is a valid IPv4
def check_if_ipv4(ip):
    if ip == 'localhost':
        return ip
    else:
        ip_split = ip.split('.')
        if len(ip_split) == 4:
            for number in ip_split:
                check_if_valid_ip_number(number)
            return ip
        else:
            raise InvalidIPAddressError(INVALID_IP_EXCEPTION)


# Checks if number is between 0 and 255
def check_if_valid_ip_number(number):
    try:
        number = int(number)
        if number < 0 or number > 255:
            raise InvalidIPAddressError(INVALID_IP_EXCEPTION)
        else:
            return number
    except ValueError:
        raise InvalidIPAddressError(INVALID_IP_EXCEPTION)


# Checks if number is positive
def check_if_valid_port(input_number):
    try:
        number = int(input_number)
        if number <= 0:
            raise InvalidPortError(INVALID_PORT_EXCEPTION)
        return number
    except ValueError:
        raise InvalidPortError(INVALID_PORT_EXCEPTION)


def start_socket_thread():
    global client_socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    t = threading.Thread(target=listen_on_port())
    threads.append(t)
    t.start()


# Listens for messages from other clients
def listen_on_port():
    # Sends sign_in message to server
    client_socket.sendto(make_sign_in_message(), (server_ip, server_port))

    data, address = client_socket.recvfrom(BUFFER_SIZE)
    r1_hash = data.split(',')
    if len(r1_hash) == 2:
        r1 = r1_hash[0]
        hash = r1_hash[1]
        r2 = PoW.compute_r2(r1, hash)
        client, client_pubkey = Diffie_hellman.client_contribution()

        global my_username
        my_username, my_password = enter_username_password()

        random_number = str(binascii.hexlify(os.urandom(16)))  # Generate random number for
        c_key = str(client_pubkey)

        client_socket.sendto(make_puzzle_message(r2, my_username, my_password, random_number, c_key), (server_ip, server_port))
        data, address = client_socket.recvfrom(BUFFER_SIZE)

        response_split = data.split()
        if len(response_split) > 1 and response_split[0] == INCORRECT_USER_PASS_MESSAGE:
            print ' '.join(response_split[1:])
            while True:
                try_again = raw_input(DO_YOU_WANNA_TRY_AGAIN)
                if try_again == "Y" or try_again == "y" or try_again == "yes" or try_again == "YES":
                    listen_on_port()
                elif try_again == "N" or try_again == "n" or try_again == "no" or try_again == "NO":
                    exit(0)

        response = data.split(',')
        if len(response) == 2:
            random_answer, server_contribution = response
            if random_number == random_answer:
                global shared_key
                shared_key = Diffie_hellman.process_server_contribution(client, int(server_contribution))
                print 'shared_key:', shared_key
                shared_key = shared_key.decode("hex")

                global shared_key_set
                shared_key_set = True
                start_input_thread()

            if shared_key_set:

                while True:
                    data, address = client_socket.recvfrom(BUFFER_SIZE)  # Buffer size = 1024 bytes
                    data_split = data.split()
                    if shared_key_set and len(data_split) == 4:
                        # if data_split[0] == LIST_RESPONSE_MESSAGE:
                        #     print ' '.join(data_split[1:])
                        decrypted_message = symmetric_encryption.decrypt(shared_key, data_split)
                        split_decrypted_message = decrypted_message.split()
                        if len(split_decrypted_message) > 2 and split_decrypted_message[0] == LIST_RESPONSE_MESSAGE:
                            if list_random_number == split_decrypted_message[1]:  # Valid response!
                                print ' '.join(split_decrypted_message[2:])
                        elif split_decrypted_message[0] == LOGOUT_MESSAGE:
                            exit(0)
                        elif data_split[0] == GET_ADDRESS_OF_USER_RESPONSE:
                            json_response = json.loads(''.join(data_split[1:]))
                            client_socket.sendto(my_username + " " + current_message, (json_response["ip"], json_response["port"]))
                        elif data_split[0] == ILLEGAL_MESSAGE_RESPONSE:
                            print ' '.join(data_split[1:])
                        else:
                            print "<From " + str(address[0]) + ":" + str(address[1]) + ":" + str(data_split[0]) + ">: " \
                                  + ' '.join(data_split[1:])
                    elif len(data_split) > 1 and data_split[0] == ILLEGAL_MESSAGE_RESPONSE:
                        print " ".join(data_split[1:])

            else:
                print SHARED_KEY_COULDNT_BE_ESTABLISHED
                exit(0)


def start_input_thread():
    t = threading.Thread(target=input_handling)
    threads.append(t)
    t.start()


# Handles the input from the user
def input_handling():
    print "You can chat now:"
    while True:
        message = raw_input()
        split_message = message.split()
        if len(split_message) > 0:
            if split_message[0] == SEND:
                if len(split_message) > 2:
                    global current_message
                    current_message = ' '.join(split_message[2:])
                    client_socket.sendto(GET_ADDRESS_OF_USER + " " + split_message[1], (server_ip, server_port))
                else:
                    print "You are not using the command 'send' the proper way"
            elif split_message[0] == LIST_MESSAGE:
                client_socket.sendto(make_list_message(), (server_ip, server_port))
            elif split_message[0] == LOGOUT_MESSAGE:
                client_socket.sendto(make_logout_message(), (server_ip, server_port))
            else:
                client_socket.sendto(message, (server_ip, server_port))
        else:
            print "Incorrect command\n"


def enter_username_password():
    global my_username
    my_username = raw_input(ENTER_USERNAME)
    while len(my_username) == 0:
        my_username = raw_input(USERNAME_CANT_BE_BLANK)
    my_password = getpass.getpass()
    return my_username, my_password


def make_sign_in_message():
    return SIGN_IN_MESSAGE


def make_puzzle_message(r2, username, password, random_number, c_key):
    message = username + "," + password + "," + random_number + "," + str(c_key)
    # print message
    # print len(message)
    return PUZZLE_RESPONSE + " " + r2 + " " + encrypt_message(SERVER_PUBLIC_KEY_FULL_PATH, message)


def merge_numbers(number):
    final_number = ""
    for i in range(0, len(number), 2):
        if i == len(number) - 1:
            final_number += format(int(number[i]), 'x')
        else:
            final_number += format(int(number[i]) + int(number[i+1]), 'x')
    return final_number


# def to_bytes(number):
#     final_number = ""
#     for i in range(0, len(number), 2):
#         if i == len(number) - 1:
#             result = format(int(number[i]), '04b')
#             final_number += str(int(result, 2))
#         else:
#             result = str(format(int(number[i]), '04b')) + str(format(int(number[i+1]), '04b'))
#             print result
#             final_number += str(int(result, 2))
#             print str(int(result, 2))
#     return final_number


def make_list_message():
    global list_random_number
    list_random_number = binascii.hexlify(os.urandom(16))
    associated_data = os.urandom(16)
    message = LIST_MESSAGE + " " + list_random_number + " " + str(get_current_timestamp())
    message_to_send = symmetric_encryption.encrypt(shared_key, message, associated_data)
    return message_to_send


def make_logout_message():
    payload = LOGOUT_MESSAGE + " " + str(get_current_timestamp())
    associated_data = os.urandom(16)
    payload = symmetric_encryption.encrypt(shared_key, payload, associated_data)
    return payload


if __name__ == "__main__":
    start_client()
