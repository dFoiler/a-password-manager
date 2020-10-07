''' server code '''

import os			# urandom
from zkp import *		# Prover

# local imports
import sys
sys.path.append('..')
from JASocket.jasocket import *	# JASocket

host = 'localhost'
port = 373

print('[ Setting up connections ]')
server = JASocket(host, port, is_server=True)

server_connection, _ = server.accept()

print('[ Checking connection ]')
print(server_connection.recv())
server_connection.send('The server connection is working')

print('[ Setting up ZKP]')
# Server will prover to client
# Set up with no secret
prover = Prover(server_connection)
server_connection.send(hex(prover.token)[2:])

print('[ Check ZKP ]')
print('token == pow(g, secret, p) :', prover.token == pow(g, prover.secret, p))

print('[ Begin ZKP ]')
prover.run(256)

print('[ Finished ZKP ]')
