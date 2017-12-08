import pyDH

"""
All public keys are 2048 bit.
"""


def process_server_contribution(client, server_pubkey):
    """
    Makes shared key for client
    :param client: DH-object
    :param server_pubkey
    :return: shared_key
    """
    shared_key = client.gen_shared_key(server_pubkey)
    return shared_key


def server_contribution(client_pubkey):
    """
    Makes DH-object for server to generate shared key (given client_pubkey)
    :param client_pubkey
    :return: shared key (for server)
    :return: server_pubkey (for client)
    """
    server = pyDH.DiffieHellman()
    server_pubkey = server.gen_public_key()
    shared_key = server.gen_shared_key(client_pubkey)
    return shared_key, server_pubkey


def client_contribution():
    """
    Makes DH-object for client to generate shared key
    :return: client: DF object (for client)
    :return: client_pubkey (for server)
    """
    client = pyDH.DiffieHellman()
    client_pubkey = client.gen_public_key()
    return client, client_pubkey

