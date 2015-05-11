'''
Created on May 8, 2015
 
@author: niyohn
'''
 
import os
import socket
import threading

from Crypto.PublicKey import RSA

from server import functions
 
from queue import Queue, Empty
 
import select
 
 
def generate_keys_rsa():
    """
   Generates the public and private RSA keys
 
   To protect against MITM-attacks the private key is not generated,
   so this function imports a static 8192-bit key and derives the public key
   the reason behind such a large key is that the accepted length of
   encrypted messages are correlated to the length of the key and it
   was a quick fix to allow the Diffie-Hellman keys to be encrypted
   """
 
    rsa_string = functions.get_RSA_key()
    private_key = RSA.importKey(rsa_string)
 
    public_key = private_key.publickey()
    return private_key, public_key
 
 
class ClientHandler(threading.Thread):
    """The ClientHandler handles all communicating with one client"""
 
    def __init__(self, socket_, adress, connection_id):
        threading.Thread.__init__(self)
 
        self.socket_ = socket_
        self.adress = adress
        self.connection_id = connection_id
       
        self.stopped = False
        self.pubkey = False
 
        print("accepted new connection")
 
 
    def stop(self):
        """cleanly stops the connection"""
 
        print("closing connection no. {}".format(self.connection_id))
        self.socket_.close()
 
        connections[self.connection_id] = None
        self.stopped = True
 
 
    def send_to_other(self, input_data):
        """passes data to the other client by putting it in the queue"""
       
        if input_data is not None:
            queues[self.connection_id ^ 1].put(input_data)
 
 
    def send_messages(self):
        """gets messages from the other client and sends them to the client"""
 
        output_data = queues[self.connection_id].get_nowait()
 
        if output_data == b'':
            return
 
        print("sending data to client no. {}".format(self.connection_id))
        print(output_data)
   
        self.socket_.sendall(output_data)
 
 
    def recieve_messages(self):
        """recieves messages from the client and handles them accordingly"""
        try:
            input_data = self.socket_.recv(4096)
        except ConnectionResetError:
            self.stop()
            return
 
        # If the stream is null, the other side has closed the connection
        if input_data == b'':
            self.stop()
 
        # The first message is supposed to be a public Diffie-Hellman key
        elif self.pubkey is False:
            print("got pubkey")
            self.handle_public_keys(input_data)
            self.pubkey = True
            return
       
        self.send_to_other(input_data)
 
 
    def run(self):
        """The Main loop that handles everything"""
       
        print("running new thread")
 
        while True:
            # Check if the connection has been stopped from the outside
            if self.stopped:
                return
 
            try:
                self.send_messages()
            except Empty:
                pass
 
            try:
                self.recieve_messages()
            except BlockingIOError:
                # The exception is thrown if there is no data to be read
                pass
 
 
    def handle_public_keys(self, public_key_):
        """Processes a public key, as recieved by a client"""
       
        public_key = public_key_
 
        public_key = functions.decrypt(public_key, private_rsa_key)
        signature = functions.sign(public_key, private_rsa_key)
       
        tuple_ = public_key, signature
        
        message = str(tuple_)
        message = message.encode(encoding='utf_8', errors='strict')
 
        self.send_to_other(message)
 
hostname = socket.gethostname()
port = 11145
 
#the sockets for the clients
connections = [None, None]
#the queues are used to send the messages between the clients
queues = Queue(), Queue()
 
private_rsa_key,  public_rsa_key = generate_keys_rsa()
exported_public_key = public_rsa_key.exportKey()
 
listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listen_socket.bind((hostname, port))
 
#This makes every new socket non-blocking
socket.setdefaulttimeout(0.0)
 
while True:
    listen_socket.listen(2)
 
    new_connection, adress = listen_socket.accept()
 
    #There are only room for two connections, so don't accept more
    if connections.count(None) == 0:
        new_connection.close()
        continue
 
    open_id = connections.index(None)
 
    new_handler = ClientHandler(new_connection, adress, open_id)
    new_handler.daemon = True
    new_handler.start()
 
    connections[open_id] = new_handler