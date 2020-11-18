import binascii 		# hexlify
import json			# load, dumps
import os			# urandom
import socket			# socket
import string			# printable

# local imports
PATH = os.path.abspath(__file__)
PATH = PATH[:-PATH[::-1].find('/')]
# Go back up a directory from here
import sys
sys.path.append(PATH+'..')
from helpers import *
from crypto.zkp import *	# authentication
from JASocket.jasocket import *	# JASocket

class Server:
	''' This class is for creating server objects '''
	def __init__(self, host, port, queuelength=5):
		'''
		Parameters
		----------
		host : str
			String naming the host to bind to
		port : int
			Integer value of the port to bind to
		queuelength : int
			Length of the waiting queue for the connection
		'''
		# Set up connection
		self.server = JASocket(host, port, is_server=True, queuelength=queuelength)
		# Gather user tokens
		self.user_tokens = loadfile(PATH+'client_tokens.txt', default={})
		# Gather own secret
		secret = binascii.hexlify(os.urandom(256)).decode()
		self.secret = loadfile(PATH+'secret.txt', default={'secret':secret})
		self.secret = int(self.secret['secret'], 16)
		self.token = pow(g, self.secret, p)
		# Get user passwords
		self.user_pwds = loadfile(PATH+'client_pwds.txt', default={})
	
	def get_username(self, client):
		'''
		Runs the username extraction protocol with the client
		
		Parameters
		----------
		client: socket
			Socket connection of the client
		
		Returns
		-------
		str, the username of the user
		'''
		# Receive username
		data = client.recv()
		new_user, username = data[:3], data[4:]
		if new_user == 'New':
			new_user = True
		elif new_user == 'Old':
			new_user = False
		else:
			raise Exception('Corrupted username: ' + str(data))
		# Is this a new user?
		if username in self.user_tokens:
			# If user was new, recurse
			if new_user:
				client.send('Username taken.')
				return self.get_username(client)
			# Else proceed normally
			print('[ Found user ]')
			client.send('Found user.')
		else:
			print('[ New user ]')
			# Get user token
			client.send('New user. Send token.')
			token = client.recv()
			print('[ Token:', token, ']')
			self.user_tokens[username] = token
			writefile(PATH+'client_tokens.txt', self.user_tokens)
			# Send our token
			client.send(hex(self.token)[2:])
		# Check if the username has passwords
		if username not in self.user_pwds:
			self.user_pwds[username] = {}
			with open(PATH+'client_pwds.txt','w') as f:
				f.write(json.dumps(self.user_pwds))
				f.close()
		return username
	
	def authenticate(self, client, token):
		'''
		Runs the authentication protocol with the client; see crypto
		Parameters
		----------
		client : socket
			Socket connection of the client
		token : str
			Hex string givig the token of the client
		
		Returns
		-------
		bool, if the authentication was successful
		'''
		# Client proves first
		print('[ Verifying client ]')
		verifier = Verifier(client,token)
		check = verifier.run(256)
		# Server proves second
		print('[ Verifying server ]')
		prover = Prover(client, self.secret)
		prover.run(256)
		# Run checks
		if check:
			client.send('Authenticated.')
		else:
			client.send('Failed.')
		self_check = client.recv().strip()
		self_check = (self_check == 'Authenticated.')
		# Failure
		if not check or not self_check:
			client.close()
			if not check:
				raise Exception('client failed authentication')
			if not self_check:
				raise Exception('server failed authentication')
		return check and self_check
	
	def run_pwds(self, client, username):
		'''
		Runs the password exchange protocol
		
		Parameters
		----------
		client : socket
			Socket connection of the client
		username : str
			Username of the client
		'''
		client.send('Ready.')
		choice = client.recv()
		client.send('Which?')
		which = client.recv()
		# Retrieve
		if choice == 'r':
			print('[ Retrieving',which,']')
			if which in self.user_pwds[username]:
				client.send(self.user_pwds[username][which])
				print('[ Found ]')
			else:
				client.send('[ Password not found ]')
				print('[ Not found ]')
		# Store
		elif choice == 's':
			print('[ Storing to',which,']')
			client.send('To?')
			replacement = client.recv()
			self.user_pwds[username][which] = replacement
			writefile(PATH+'client_pwds.txt', self.user_pwds)
		else:
			client.send('Invalid.')
		assert client.recv() == 'Done.'
	
	def run_client(self, client, addr):
		'''
		Runs the program with the specified client
		
		Parameters
		----------
		client : socket
			Socket connection of the client
		addr : str
			Address of the current client
		'''
		# Check the username
		username = self.get_username(client)
		print('[', addr[0], 'is', username, ']')
		# Run the authentication protocol
		user_token = int(self.user_tokens[username], 16)
		print('[ Authenticating', addr[0], ']')
		authenticated = self.authenticate(client, user_token)
		print('[ Running ]')
		# Run password protocol
		while True:
			self.run_pwds(client, username)
	
	def run(self):
		'''
		Runs the entire program, in sequence
		'''
		print('[ Running ]')
		while True:
			try:
				# Accept client
				client, addr = self.server.accept()
				print('[ Connected to', addr[0], ']')
				# This server should never crash
				self.run_client(client, addr)
			except KeyboardInterrupt:
				# Ok, if you said to die, we'll die
				print('[ Exiting ]')
				exit()
			except Exception as e:
				print('[ Error with',addr[0],':',e,']')
			print('[ Closing ]')
			client.close()

if __name__ == "__main__":
	HOST = 'localhost'
	PORT = 373
	server = Server(HOST, PORT)
	server.run()
