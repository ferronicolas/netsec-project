# Global constant

FILENAME = "configuration_file.txt"
IP = "IP"
PORT = "PORT"
DELIMITER = ":"


# Creates file with information passed as a parameter
def create_file(ip_address, port):
    file = open(FILENAME, "w")
    file.write(IP + DELIMITER + ip_address + "\n")
    file.write(PORT + DELIMITER + str(port) + "\n")
    file.close()


# Returns a tuple: (IP address, port)
def read_file():
    file = open(FILENAME, "r")
    result_ip = None
    result_port = None
    for line in file:
        array = line.split(DELIMITER)
        if array[0] == IP:
            result_ip = array[1].strip(" \t\n\r")
        elif array[0] == PORT:
            result_port = array[1].strip(" \t\n\r")
    return result_ip, result_port
