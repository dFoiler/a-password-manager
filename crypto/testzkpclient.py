''' client code '''

from zkp import *		# Verifier

# local imports
import sys
sys.path.append('..')
from JASocket.jasocket import *	# JASocket

host = 'localhost'
port = 373

print('[ Setting up connections ]')

client_connection = JASocket(host, port)

print('[ Checking connection ]')
client_connection.send('The client connection is working')
print(client_connection.recv())

print('[ Setting up ZKP]')
# Server will prove to client
# Set up with no secret
token = int(client_connection.recv(), 16)
verifier = Verifier(client_connection, token)
#verifier = Verifier(client_connection, token+1)

print('[ Begin ZKP ]')
check = verifier.run(256)
print('Result:',check)

print('[ Finished ZKP ]')
