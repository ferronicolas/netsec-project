# Global constant
DELIMITER = "="

# Server info
FILENAME_SERVER = "server_information.txt"
IP = "IP"
PORT = "PORT"


# Creates file with information passed as a parameter
def create_server_file(ip_address, port):
    file = open(FILENAME_SERVER, "w")
    file.write(IP + DELIMITER + ip_address + "\n")
    file.write(PORT + DELIMITER + str(port) + "\n")
    file.close()


# Returns a tuple: (IP address, port)
def read_server_file():
    file = open(FILENAME_SERVER, "r")
    result_ip = None
    result_port = None
    for line in file:
        array = line.split(DELIMITER)
        if array[0] == IP:
            result_ip = array[1].strip(" \t\n\r")  # Trim
        elif array[0] == PORT:
            result_port = array[1].strip(" \t\n\r")  # Trim
    return result_ip, result_port

