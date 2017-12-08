import pyDH

"""
All contributions are 2048 bit.
"""


def process_server_contribution(client, servers_contribution):
    """
    Makes shared key for client
    :param client: DH-object
    :param servers_contribution
    :return: shared_key
    """
    shared_key = client.gen_shared_key(servers_contribution)
    print shared_key
    print 'keylength: ', len(shared_key)
    print len(bytearray.fromhex(str(shared_key)))
    return shared_key


def server_contribution(clients_contribution):
    """
    Makes DH-object for server to generate shared key (given client_contribution)
    :param clients_contribution
    :return: shared key (for server)
    :return: server_contribution (for client)
    """
    server = pyDH.DiffieHellman()
    server_contribution = server.gen_public_key()
    shared_key = server.gen_shared_key(clients_contribution)
    return shared_key, server_contribution


def client_contribution():
    """
    Makes DH-object for client to generate shared key
    :return: client: DF object (for client)
    :return: client_pubkey (for server)
    """
    client = pyDH.DiffieHellman()
    print client.get_private_key()
    client_contribution = client.gen_public_key()
    return client, client_contribution
