# Test by running and connecting "nc localhost 373"

from jasocket import *

host = 'localhost'
port = 373

# Open a socket
# It automatically listens, etc.
server = JASocket(host, port, is_server=True)

print('[ Running at',host,port,']')

while True:
	try:
		# Accept connection
		client,addr = server.accept()
		print('[', addr, ']')
		client.send('Ready.\n')
		while True:
			client.send('>>> ')
			data = client.recv()
			if not data:
				break
			client.send(data)
		print('[ Closing ]')
		client.close()
	except KeyboardInterrupt:
		print('[ Exiting ]')
		exit()
	except Exception as e:
		raise(e)
		print('[', e, ']')
		client.close()
