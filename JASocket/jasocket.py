''' Just another socket '''

import json		# loads, dumps
import socket		# socket
import string		# printable

class JASocket:
	''' This is a simple socket wrapper class '''
	def is_printable(s):
		'''
		Determines if s contains printable characters
		
		Parameters
		----------
		s : str
			String to test
		
		Returns
		-------
		bool, true iff s is printable
		'''
		for c in s:
			if c not in string.printable:
				return False
		return True
	
	def __init__(self, host, port, is_server=False, queuelength=5, sd=None):
		'''
		Parameters
		----------
		host : str
			Name of host to connect to
		port : str
			Name of port of host to connect to
		is_server : bool, optional
			Whether or nor this is a server
		queuelength : int, optional
			Length of the queue
		sd : socket
			Socket to wrap around if provided
		'''
		self.is_server = is_server
		# Pass in a socket through client
		if sd:
			self.socket = sd
			return
		# Keep going
		self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		if not is_server:
			self.socket.connect((host, port))
		else:
			self.socket.bind((host, port))
			self.socket.listen(queuelength)
	
	def accept(self):
		'''
		Function to accept connections
		'''
		if not self.is_server:
			raise Exception('client cannot accept')
		client,addr = self.socket.accept()
		return JASocket(None, None, sd=client), addr
	
	def send(self, message):
		'''
		Function sending along the socket
		
		Parameters
		----------
		message : str
			Message to send
		'''
		if not isinstance(message, str):
			raise TypeError('can only send strings')
		if not JASocket.is_printable(message):
			raise Exception('message not printable')
		if len(message) >= 4096:
			raise Exception('message too long')
		self.socket.sendall(message.encode())
	
	def recv(self):
		'''
		Function to receive from the socket
		
		Returns
		-------
		str, the first 4096 characters of the received message
		'''
		message = self.socket.recv(4096).decode()
		if not JASocket.is_printable(message):
			raise Exception('message corrupted')
		return message
	
	def close(self):
		'''
		Function to close the connection
		'''
		self.socket.close()
