from client import Client
import random			# randint

host = 'localhost'
port = 373

# List of inputs
random_name = ''.join(chr(random.randint(32,127)) for _ in range(8))
inputs = [
	'\x00',		# Invalid character
	'',		# Too short
	'a'*8000,	# Too long
	'jack',		# Username
	'1234',		# Password
	'2345',		# Bad confirm
	'1234',		# Password
	'\x00',		# Invalid character
	'1234',		# Confirm
	'',		# Too short
	'rr',		# Too long
	'r',		# Retrieve
	'',		# Too short
	'0'*4001,	# Too long
	random_name,	# A valid name, not there
	'S',		# Store
	random_name,	# That valid name
	'R',		# Random
	'R',		# Retrieve
	random_name,	# Hopefully that random value
	's',		# Store
	random_name,	# Reenter
	'e',		# Enter
	10*random_name,	# Store
	'r',		# Retrieve
	random_name	# Hopefully that random value
]

counter = 0
def runner(prompt):
	global counter
	global inputs
	if counter >= len(inputs):
		print('[ Finished testing ]')
		exit()
	r = inputs[counter]
	print('> ', end='')
	if len(r) < 10:
		print(r)
	else:
		print(r[:10], '...')
	counter += 1
	return r

client = Client(host, port, runner, runner)

client.run()
