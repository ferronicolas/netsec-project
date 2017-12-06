import socket
import argparse

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


def start_server():
    port = check_arguments()
    if port:
        listen_on_port(port)


# Checks that the program was called with the following 3 arguments: server.py, -sp, port number
def check_arguments():
    parser = argparse.ArgumentParser(description="Server for chat application")
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
    while True:
        data, address = server_socket.recvfrom(1024)  # Buffer size = 1024 bytes
        message = data.split()
        if len(message) > 0:
            if message[0] == SIGN_IN_MESSAGE:
                current_users[message[1]] = (address[0], address[1])  # USERNAME: (IP address, port)
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
