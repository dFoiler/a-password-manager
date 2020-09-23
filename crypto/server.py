from zkp import *

import socket
import os
import binascii

host = 'localhost'
port = 373

print('[ Setting up connections ]')
server = socket.socket()
server.bind((host, port))
server.listen(1)

server_connection, _ = server.accept()

print('[ Checking connection ]')
print(server_connection.recv(4096).decode())
server_connection.sendall(b'The server connection is working')

print('[ Setting up ZKP]')
# Server will prover to client
# Set up with no secret
prover = Prover(server_connection)
server_connection.sendall(hex(prover.token)[2:].encode())

print('[ Check ZKP ]')
print('token == pow(g, secret, p) :', prover.token == pow(g, prover.secret, p))

print('[ Begin ZKP ]')
prover.run(256)

print('[ Finished ZKP ]')
