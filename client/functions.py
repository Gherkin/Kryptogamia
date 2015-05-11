'''
Created on May 11, 2015

@author: niyohn
'''

from pbkdf2 import PBKDF2
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA

import ast

from encryption import diffie_hellman



def pad_message(message_):
    """Pads a string to a multiple of 16 as required by AES-CBC"""
 
    message = message_
    mod = len(message) % 16
 
    if mod == 0:
        return message
 
    addition = 16 - mod
    message = message.encode(encoding='utf_8', errors='strict')
    print("padding with {} characters".format(addition))
    
    message += bytes([15])*addition
    print("padded: {}".format(message))
    message = message.decode(encoding='utf_8', errors='strict')
 
    return message
 
 
def unpad_message(message_):
    """
   Unpads a string by removing chr(0)
 
   AES-CBC requires input to be a length that is a multiple of 16,
   therefore we pad it with chr(0)
   """
    print("before unpad: {}".format(message_))
    message = message_.decode(encoding='utf_8', errors='strict')
    message = message.rstrip(chr(15))
 
    return message


def verify_from_server(message, signature, server_key):
    """
    Verifies a message signed with the servers private key
    
    Used to verify that the public Diffie-Hellman key
    from the other client has been safely transmitted from the server
    """
    
    hash = SHA.new(message)
    verifier = PKCS1_v1_5.new(server_key)
    
    if verifier.verify(hash, signature):
        return True
    else:
        print("recieved a non-authentic public key")
        return False



def encrypt_to_server(message, server_key):
    """
    Encrypts a message using PKCS1_OAEP with the servers public RSA key
    
    Used to send the public Diffie-Hellman safely to the server,
    the server in turn passes it along,
    signing it with its private RSA key
    """
    
    cipher = PKCS1_OAEP.new(server_key, None, None, '')
    ciphertext = cipher.encrypt(message)
    
    return ciphertext

def process_public_key(tuple_, server_key):
    """process the public Diffie-Hellman key recieved from the server"""

    public_key, signature = ast.literal_eval(tuple_)

    authenticity = verify_from_server(public_key, signature, server_key)
    if authenticity:
        return int(public_key)
    else:
        return
 
def initiate_encryption(private_key, recieved_public_key):
    """creates the encryption key used in AES-CBC using PBKDF2"""

    secret = diffie_hellman.calculate_secret(private_key,
                                                  recieved_public_key)
    # As the Diffie-Hellman key is secure enough theres no need for a salt
    salt = b''

    encryption_key = PBKDF2(str(secret), salt).read(32)
    
    return encryption_key

def get_server_key():
    server_key = \
    b'-----BEGIN PUBLIC KEY-----\n\
    MIIEIjANBgkqhkiG9w0BAQEFAAOCBA8AMIIECgKCBAEA3yA+JsfvcmhthnaVHp8z\nEsjJM4S\
    hWLYRQd96Lx8BqpB9gICvo8upZisxHy4Wov3nIV/6mO7PnnSsM8jhtzEW\n/5cjSQ6XrC3Pfj\
    RHIYwUkBHFv8aJ2t5XeBgUgNqnXUiNd1/fKCcTGQnMvL3fkmMA\n+jgWc6arasWcAMScMjUNp\
    +rF5jpgNutWEV9vcObYmBnl2MamG/FOEbeBZ5NIj4lq\nvWuefoRDypAsGrYfHhSF5CT5YjFu\
    zXvc/ZxxZOHZ2ng+wlXNsGyff92eIq4vQNCL\nmjFihdCXi0LNNyD4tXykXwzd2tI05vebYOU\
    LoVFSdQVgTxDtSVbEAIkQUk1JFYgn\n74GZakt64E8yOmXdI+wNb+qYJKAA7jyGvLbzEmheJO\
    xUz9GqkhKVCTNB8yoMFYRl\nVVnfi54volb/l+YWUCcZS/Ktxx/zFSVNrfh8UYlHiszIDOa5H\
    xv+5Egq20VRtOOe\nUJw2Ba2RB8UBTwtTtWbEc0Dmz0FdbSSXbFkKZyYiY86p7ZO0kC4t4c+3\
    IxNdB/+3\ncLgvw4fupoVih8fxCd13nofpfanjiw2di6hvE4teTwgQqr+520WDOo0+EvHcLEs\
    L\ngL59VBUdtEPfbWam0WLZJ2PirG3qEayBMGi+PguAxFsb5RNyXL+nycJ27VpJtHvy\nSEEV\
    pSUMQpdYGKJLfAxA0BneqGLNDu/P7b5x0E8vpIBZ98UFChhyrFs9f5d18qc6\nf03YjwK6q7+\
    BQJ6/8Ayu0A4QQmylFOLoJHfOEedgCYuHpqr8Z2U3N1hdrJqCh3Ky\n1//6HLTKtLzhMsDaUN\
    DbZs/sFWqMqoy+oh0lNNKGCimavKJ/DR4I8JspNCm/XZEf\nPRJ+aJYLvuY0VizS+X29raviL\
    omdmlHN4s4L7cR0kt2m7O/iJLNpp3SBEqUS6EL8\nAALa0BJ1hahVO8cvO4i6iCWxCYloMXMf\
    Rba8r2O5GF5/N/NXesJxnR0rpz2M8rxi\nLnl/BUMfiFPqacQt5TLOW0XdPtllQ7lQqGG5r28\
    6YoT/WQ7v60R3e3vIZ7+9QEs0\nV+FyKVQ2RUL/nGYErSh4ce3poIhkr39Ps3eZTC9zs1+vgz\
    NdTRwOkF9TKxJWe5vN\nPRBIytN9ISFBN+tPh0GH/LqpYqpqpdx3Pj3GHBdRdpmChL742beEp\
    LDnS6ujuDDY\nseJznLJCqcEB6McqKrkF371GUgb8vGdgMzUVDl3TdU6eAKgU0sRY+pCO4+Aj\
    GTS+\nTQ/PacOzyGEIB4K3gaQcRGcJws9xdohvfITxYi/S3Uxhy2CYqZ9Murj68qhQGxYs\nq\
    cBsAsgsOUWQFsOtZY5+e/bsTUl37Wqj3neCa5q6kP29kcIsa3TKGTPk4+XNMEBw\nwQIDAQAB\
    \n-----END PUBLIC KEY-----'

        
    return server_key


