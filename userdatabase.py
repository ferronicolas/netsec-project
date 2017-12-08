user1info = 'eb0b34e9','246fc797de3106f4ec9ef4da4dcae2e36bc6be4ab8ff89395be96030f64b6bf91cdfa03fda59aa2aa8c8efaa80b1fa869965897cbb0ba9f29c6829b4be624ae9'
user2info = '1dba6fed','a367bb9ffb1eb4a828664ecec5d494b34150630a0c0ca8a9f7de35a21c5a499884c59618b6faa485b55a5966c696ce4c0e083cb627fb40e5c23caebbb14ba537'
user3info = 'fe2ab762','647bf18acb14b3cb6c31cfda361f27f1ef195adbecec16c947ee9b726b380a8f0a1ce6c64a6bea47729defc4d30ccb69aa4e3ac42a9789336eb5c75ea29d9a4a'
a = 'a3494c96','6d300cf531949047c21b326cdebcdac4c1c803d1381b895b4fddb75cfc46162f09c2379f04444ea26566f7581ae0300a8fd91347ed62d500dde2cc2700cf5075'

userinfo = {"user1": user1info, "user2": user2info, "user3": user3info, 'a': a}


def get_pwd_info(username):
    return userinfo[username]


def get_salt_user(username):
    a,b = userinfo[username]
    return a


def get_hash_user(username):
    a,b = userinfo[username]
    return b

