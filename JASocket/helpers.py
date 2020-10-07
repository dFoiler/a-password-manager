''' Some helper functions '''

import json		# loads, dumps
import string		# printable

# Tests if a string is printable with string.printable
def is_printable(s: str):
	if not isinstance(s, str):
		raise TypeError('is_printable takes str')
	for c in s:
		if c not in string.printable:
			return False
	return True

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
