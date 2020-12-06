import getpass		# getpass
import json		# loads, dumps
import os		# urandom

''' Some helper functions '''

# Tests if a string is printable with string.printable
def is_printable(s):
	'''
	Determines if a string is printable
	
	Parameters
	----------
	s : str
		String to determine printability of
	
	Returns
	-------
	Boolean, true iff s is printable
	'''
	# I don't want to have to deal with bytes-related problems
	if not isinstance(s, str):
		raise TypeError('is_printable takes str')
	# This more readable than an any loop
	for c in s:
		if c not in string.printable:
			return False
	return True

''' Random passwords '''

def get_rand_int(upper):
	'''
	Gets a cryptographically secure random integer from urandom
	
	Parameters
	----------
	upper : int
		Upper bound for the random integer
	
	Returns
	-------
	A random integer in [0, upper)
	'''
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

def get_rand_word(num_chars: int, char_list: list):
	'''
	Gets a cryptographically secure random word
	
	Parameters
	----------
	num_chars : int
		Number of characters in the word
	char_list : list
		List of characters to make the word from
	
	Returns
	-------
	A randomly generated string length num_chars from the char_list
	'''
	# Get random integers to forom our word from the char_list
	r = [char_list[get_rand_int(len(char_list))]
		for _ in range(num_chars)]
	return ''.join(r)
