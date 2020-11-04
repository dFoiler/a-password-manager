import getpass		# getpass
import json		# loads, dumps
import os		# urandom

''' Some helper functions '''

# Tests if a string is printable with string.printable
def is_printable(s: str):
	if not isinstance(s, str):
		raise TypeError('is_printable takes str')
	for c in s:
		if c not in string.printable:
			return False
	return True

# Generic input function
def get_input(prompt='> ', password=False,
		maxlength=None, minlength=None, options=None):
	inputfunction = getpass.getpass if password else input
	while True:
		r = inputfunction(prompt)
		if maxlength and len(r) > maxlength:
			print('Length cannot exceed', maxlength)
			continue
		if minlength and len(r) < minlength:
			print('Length cannot go below', minlength)
			continue
		if options and any(c not in options for c in r):
			print('Must be in', options)
			continue
		return r

# Loads a dictionary from a file
def loadfile(name: str, default={}):
	if not isinstance(name, str):
		raise TypeError('loadfile takes str')
	ret = default
	try:
		f = open(name, 'r')
		ret = json.load(f)
		f.close()
	except FileNotFoundError:
		f = open(name, 'w')
		f.write(json.dumps(default))
		f.close()
	return ret

# Writes a dictionary to a file
def writefile(name: str, data: dict):
	if not isinstance(name, str):
		raise TypeError('writefile takes str')
	if not isinstance(data, dict):
		raise TypeError('writefile takes dict')
	f = open(name, 'w')
	f.write(json.dumps(data))
	f.close()

''' Random passwords '''

# Gets a cryptographically secure random number from urandom
def get_rand_int(upper):
	# We add in 30 extra bytes so that the mod is "uniform"
	num_bytes = upper.bit_length()//8 + 30
	rand_bytes = os.urandom(num_bytes)
	# Convert to a number with upper bound
	rand = 0
	for (k,b) in enumerate(rand_bytes):
		# Base conversion
		rand = (rand * 256) % upper
		rand += b
	return rand % upper

def get_rand_word(num_chars, char_list=[chr(c) for c in range(33,128)]):
	r = [char_list[get_rand_int(len(char_list))]
		for _ in range(num_chars)]
	return ''.join(r)
