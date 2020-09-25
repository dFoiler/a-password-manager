from zkp import *

import socket

host = 'localhost'
port = 373

print('[ Setting up connections ]')

client_connection = socket.socket()
client_connection.connect((host, port))

print('[ Checking connection ]')
client_connection.sendall(b'The client connection is working')
print(client_connection.recv(4096).decode())

print('[ Setting up ZKP]')
# Server will prove to client
# Set up with no secret
token = int(client_connection.recv(4096).strip(), 16)
verifier = Verifier(client_connection, token)
#verifier = Verifier(client_connection, token+1)

print('[ Begin ZKP ]')
check = verifier.run(256)
print(check)

print('[ Finished ZKP ]')
