''' server code '''

host = 'localhost'
port = 373

import socket
import string
import json

class Server:
	def __init__(self, host, port, queuelength=5):
		self.server = socket.socket()
		self.server.bind((host, port))
		self.server.listen(queuelength)
		with open('user_tokens.txt','r') as f:
			self.user_tokens = json.load(f)
			f.close()
	
	def get_username(self, client):
		# Receive username
		username = client.recv(4096)
		username = ''.join(chr(c) for c in username)
		username = username.strip()
		# Test if username is printable
		if any(c not in string.printable for c in username):
			return False
		# Is this a new user?
		if username in self.user_tokens:
			print('[ Found user ]')
			client.send(b'Found user.\n')
		else:
			print('[ New user ]')
			client.send(b'New user. Send token.\n')
			token = client.recv(4096)
			token = ''.join(chr(c) for c in token)
			print('Token:', token)
			token = int(token, 16)
			self.user_tokens[username] = token
			with open('user_tokens.txt','w') as f:
				f.write(json.dumps(self.user_tokens))
				f.close()
		return username
	
	def run(self):
		print('[ Running ]')
		while True:
			client, addr = self.server.accept()
			print('Received connection form', addr[0])
			username = self.get_username(client)
			if not username:
				print(addr[0], 'gave invalid username. Closing.')
				client.send(b'Invalid username. Closing.\n')
				client.close()
			print(addr[0], 'is', username)
			# Run cat to show that we're done
			while True:
				data = client.recv(4096)
				if not data:
					break
				client.sendall(data)
			print('[ Closing ]')
			client.close()

server = Server(host, port)
server.run()
