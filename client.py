import socket
import threading
import json
from errno import ENOENT
from file_handler import read_file
from excep import InvalidIPAddressError, InvalidPortError

# Flags
USER_FLAG = "-u"
SERVER_IP_FLAG = "-sip"
SERVER_PORT_FLAG = "-sp"

# Messages
SIGN_IN_MESSAGE = "sign_in"
LIST_MESSAGE = "list"
LIST_RESPONSE_MESSAGE = "list_response"
GET_ADDRESS_OF_USER = "get_address_of_user"
GET_ADDRESS_OF_USER_RESPONSE = "get_address_of_user_response"
ILLEGAL_MESSAGE_RESPONSE = "illegal"

# Exception messages
INVALID_IP_EXCEPTION = "The IP address of the server is invalid"
INVALID_PORT_EXCEPTION = "The port number of the server is invalid"
SERVER_DOWN = "The server is down"
FILE_DOESNT_EXIST = "The server hasn't created the configuration file yet"

# Global constants
ENTER_USERNAME = "Enter your username: "
ENTER_PASSWORD = "Enter your password: "
BUFFER_SIZE = 1024

# Global variables
client_socket = None
threads = []
my_username = ""
server_ip = 0
server_port = 0
current_message = ""  # Message that I want to send


def start_client():
    global my_username, server_ip, server_port
    try:
        server_ip, server_port = read_file()
        server_ip = check_if_ipv4(server_ip)
        server_port = check_if_valid_port(server_port)
        if check_if_server_up():
            my_username = raw_input(ENTER_USERNAME)
            my_password = raw_input(ENTER_PASSWORD)
            if my_username:  # Checks if it got arguments
                start_input_thread()
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
    t = threading.Thread(target=listen_on_port())
    threads.append(t)
    t.start()


# Listens for messages from other clients
def listen_on_port():
    global client_socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Sends sign_in message to server
    client_socket.sendto(make_sign_in_message(), (server_ip, server_port))
    while True:
        data, address = client_socket.recvfrom(BUFFER_SIZE)  # Buffer size = 1024 bytes
        data_split = data.split()
        if data_split[0] == LIST_RESPONSE_MESSAGE:
            print ' '.join(data_split[1:])
        elif data_split[0] == GET_ADDRESS_OF_USER_RESPONSE:
            json_response = json.loads(''.join(data_split[1:]))
            client_socket.sendto(my_username + " " + current_message, (json_response["ip"], json_response["port"]))
        elif data_split[0] == ILLEGAL_MESSAGE_RESPONSE:
            print ' '.join(data_split[1:])
        else:
            print "<From " + str(address[0]) + ":" + str(address[1]) + ":" + str(data_split[0]) + ">: " \
                  + ' '.join(data_split[1:])


def make_sign_in_message():
    return SIGN_IN_MESSAGE + " " + my_username


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
        if len(split_message) > 0 and split_message[0] == "send":
            if len(split_message) > 2:
                global current_message
                current_message = ' '.join(split_message[2:])
                client_socket.sendto(GET_ADDRESS_OF_USER + " " + split_message[1], (server_ip, server_port))
            else:
                print "You are not using the command 'send' the proper way"
        else:
            client_socket.sendto(message, (server_ip, server_port))


if __name__ == "__main__":
    start_client()
