'''
Created on May 8, 2015
 
@author: niyohn
 
TO-DO:
check if whats recieved is correct in protocol_setup
check if diffie-hellman keys are correct (MTProto?)
command line arguments for different adress/port
commands
   reconnect
   create new public-key
   display keys
protocol requests/commands
   request new server key
   request new public key  
'''
 
import socket
import sys
import select

from Crypto.PublicKey import RSA

from encryption import diffie_hellman
from encryption import aes

from client import functions
 
class Client:
    def __init__(self):
        self.connection = self.start_connection()
 
        self.private_key, self.public_key = diffie_hellman.generate_keys()
 
        self.encryption_key = None
        self.setup_done = False
        
        # Import the servers public key from string
        key_string = functions.get_server_key()
        self.server_key = RSA.importKey(key_string)
        
        self.send_public_key()
        
        self._run()
 
    def _run(self):
        """The main running loop of the client"""
 
        while True:
            self.send_messages()
            try:
                self.recieve_messages()
            except ConnectionResetError:
                self.stop()
            except BlockingIOError:
                pass
 
    def stop(self):
        """Cleanly exits the client"""
        self.connection.close()
        sys.exit()

    def send_public_key(self):
        """encrypts the clients public key and sends it to the server"""
 
        if self.server_key is None:
            print("Haven't recieved the servers public key, try restarting")
            self.stop()
 
        message = str(self.public_key)
        message = message.encode(encoding='utf_8', errors='strict')
 
        encrypted_key = functions.encrypt_to_server(message, self.server_key)
        
        print("sending encrypted public key")
        
        self.connection.sendall(encrypted_key)
 
    def send_messages(self):
        """reads from stdin, catches commands and sends to server"""
 
        stdin_readable = select.select([sys.stdin], [], [], 0.0)[0]
        if stdin_readable:
            input_string = input()
 
            if input_string == "quit":
                self.stop()
 
            if self.encryption_key is not None:
                input_string = functions.pad_message(input_string)
                input_bytes = aes.encrypt(input_string,
                                          self.encryption_key)
            
            elif self.setup_done is False:
                print("Setup is not done, please wait")
                return
                
            else:
                print("No encryption key, something went wrong!")
                self.stop()

            print("encrypted: {}".format(input_bytes))
            self.connection.sendall(input_bytes)
 
    def protocol_setup(self, input_data):
        """the initial setup of the protocol"""
 
        # The servers public RSA key should be recieved first.
 
        # TO-DO check if whats recieved is correct
        print("doing setup")

        # The other clients public Diffie-Hellman key is recieved first
        if self.encryption_key is None:
            input_string = input_data.decode(encoding='utf_8',
                                             errors='strict')
            public_key = functions.process_public_key(input_string,
                                                        self.server_key)
            if public_key:
                self.encryption_key = functions.initiate_encryption(self.private_key, public_key)
            else:
                return
 
        print("Setup is done")
        self.setup_done = True
 
    def recieve_messages(self):
        """recieve messages from the server and handle them properly"""
        try:
            input_data = self.connection.recv(8192)
        except ConnectionResetError:
            raise
        # If the stream is null, the other side has closed the connection
        if input_data == b'':
            self.stop()
 
        if self.setup_done is False:
            self.protocol_setup(input_data)
 
        else:
            print("Recieved: {}".format(input_data))
            
            input_string = aes.decrypt(input_data, self.encryption_key)
            input_string = functions.unpad_message(input_string)
            
            print("Decrypted: {}".format(input_string))
 
    def start_connection(self, adress=None, port=None):
        if adress is None:
            adress = socket.gethostname()
 
        if port is None:
            port = 11145
 
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((adress, port))
        # Sets the socket to not block on actions
        client_socket.settimeout(0.0)
 
        return client_socket
 
 
client = Client()