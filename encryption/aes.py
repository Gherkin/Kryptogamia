'''
Created on May 10, 2015

@author: niyohn
'''

import base64
import os
from Crypto.Cipher import AES


def encrypt(message, passphrase):
    """encrypts a message using AES-CBC and a 16-byte long IV"""
    IV = os.urandom(16)
    aes = AES.new(passphrase, AES.MODE_CBC, IV)
    
    return base64.b64encode(IV + aes.encrypt(message))


def decrypt(ciphertext, passphrase):
    """decrypts a message using AES-CBC and a 16-byte long IV"""
    ciphertext = base64.b64decode(ciphertext)
    IV = ciphertext[:16]
    aes = AES.new(passphrase, AES.MODE_CBC, IV)
    
    plaintext = aes.decrypt(ciphertext[16:])

    return plaintext

