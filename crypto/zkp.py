# NIST safe prime; 2048-bit MODP group

p = '''      FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
      29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
      EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
      E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
      EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
      C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
      83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
      670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
      E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
      DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
      15728E5A 8AACAA68 FFFFFFFF FFFFFFFF'''
p = int(''.join(p.split()),16)

g = 2

import os		# urandom
import binascii		# binascii

def random(byte):
	'''
	Parameters
	----------
	byte : int
		Number of bytes to randomly generate
	
	Returns
	-------
	Bytes randomly generated from urandom
	'''
	return int(binascii.hexlify(os.urandom(byte)), 16)

ROUNDS = 256

# This is the DH zero-knowledge proof
class Prover:
	''' Class to do the proving '''
	def __init__(self, verifier, secret=None):
		'''
		Parameters
		----------
		verifier : socket
			Socket of the verifier to communicate with
		secret : int
			Integer value of the secret
		'''
		if secret == None:
			print('[ Generating secret ]')
			secret = random(256)
		self.secret = secret
		self.token = pow(g, self.secret, p)
		self.verifier = verifier
		# This is kind of an annoying thing
		assert isinstance(self.secret, int)
	
	def round(self):
		'''
		Runs a round of the Diffie-Hellman zero-knowledge proof
		'''
		# Generate random number
		r = random(256)
		# Send g^r
		C = pow(g, r, p)
		self.verifier.send(hex(C)[2:])
		# Get verifier's choice
		choice = self.verifier.recv()
		evidence = 0
		# Send accordingly
		if choice == 'r':
			evidence = r
		elif choice == 'x':
			evidence = (r+self.secret) % (p-1)
		else:
			raise Exception('Invalid choice: '+choice)
		self.verifier.send(hex(evidence)[2:])
	
	def run(self, rounds):
		'''
		Parameters
		----------
		rounds : int
			Number of rounds of the ZKP to run
		'''
		for r in range(rounds):
			print('[ Round', r, ']\033[F')
			self.round()
		print('[ Finished rounds ]')

class Verifier:
	''' Class to do the verifying '''
	def __init__(self, prover, token):
		'''
		Parameters
		----------
		prover : soket
			Socket to communicate with
		token : int
			Integer value of the token for the ZKP
		'''
		self.prover = prover
		self.token = token
		# This is kind of an annoying thing
		assert isinstance(self.token, int)
	
	# choice = 'r' means send r, choice = 'x' means send (x+r) % (p-1)
	def round(self, choice):
		'''
		Parameters
		----------
		choice : str
			String determining to get r or r+x
		
		Returns
		-------
		Boolean, true iff the evidence matches the requested
		'''
		C = int(self.prover.recv(), 16)
		# Send our choice
		self.prover.send(choice)
		evidence = int(self.prover.recv(), 16)
		if choice == 'r':
			# Check g^r is actually C
			return  pow(g, evidence, p) == C
		elif choice == 'x':
			# Check g^(r+secret) is C * g^token
			return (C * self.token) % p == pow(g, evidence, p)
		else:
			raise Exception('Invalid choice: '+choice.decode())
	
	def run(self, rounds):
		'''
		Parameters
		----------
		rounds : int
			Number of rounds of the ZKP to run
		
		Returns
		-------
		Boolean, true iff the prover passed all rounds
		'''
		# Run all rounds
		ret = True
		for r in range(rounds):
			print('[ Round', r, ']\033[F')
			choice = 'r' if random(1)%2 else 'x'
			# Update current
			ret = self.round(choice) and ret
			# Even if the other side has failed, we don't want them to know
			# The check should be indistuishible, so we do all checks
		print('[ Finished rounds ]')
		return ret
