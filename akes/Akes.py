#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys, base64

__all_supported = ('AES', 'RSA')

__all__ = ('new', 'AKES', 'main')

__constructor_cache = {}

def new(name):
	return __get_constructor(name)()

def __get_constructor(name):
	cache = __constructor_cache
	constructor = cache.get(name)
	if constructor is not None:
		return constructor
	try:
		if name in ('AES', 'aes'):
			from akm.akes import AES as _aes
			cache['AES'] = cache['aes'] = _aes.AES
		elif name in ('RSA', 'rsa'):
			from akm.akes import RSA as _rsa
			cache['RSA'] = cache['rsa'] = _rsa.RSA
	except ImportError:
		pass  # no extension module, this Encryption is unsupported.

	constructor = cache.get(name)
	if constructor is not None:
		return constructor

	raise ValueError('unsupported Encryption type ' + name)


class AKES:
	'''A generic class for AKM Encryption Standard

	:undocumented: ...
	'''

	#: All supported key bits.
	all_key_bits = ()

	def generate_key(self, key_bits=0, **kwargs):
		'''kwargs: key_file, password
			return key
		'''
		raise NotImplementedError

	def load_key(self, key_file):
		'''load key from key_file
			return key, key_attr
		'''
		raise NotImplementedError

	def fernet(self, key):
		'''set key'''
		raise NotImplementedError

	def encrypt(self, b):
		'''encrypt bytes, return bytes'''
		raise NotImplementedError

	def decrypt(self, b):
		'''decrypt bytes, return bytes'''
		raise NotImplementedError

#####################   main():   #######################


_ENCRYPT = 0
_DECRYPT = 1

_e = _ENCRYPT
_d = _DECRYPT
_in = 0x2411
_out = 0x2412
_stdio = 0x2421
_key = 0x2431
_password = 0x2432
_keygen = 0x2441
_key_bits = 0x2442
_help = 0x2451
_check = 0x2461

options = {
	'-e': _e,
	'-d': _d,
	'-in': _in,
	'-out': _out,
	'-stdio': _stdio,
	'-k': _key,
	'-key': _key,
	'-p': _password,
	'-password': _password,
	'-keygen': _keygen,
	'-kb': _key_bits,
	'-key-bits': _key_bits,
	'-c': _check,
	'-check': _check,
	'-h': _help,
	'-help': _help
}


def main(argv):
	argc = len(argv); optind = 0
	if argc < 2:
		print('Usage:  ', argv[0], '[command] [OPTIONS]')
		sys.exit(1)
	if argv[1] == 'help':
		print('All supported:', __all_supported)
		sys.exit()
	command = argv[1]
	try:
		akes = new(command)
	except ValueError:
		print(f'Invalid command \'{command}\'; type "help" for a list.')
		sys.exit(1)
	
	optind += 1

	mode = _ENCRYPT
	keygen = None
	is_stdio = False
	in_file = None; out_file = None; key_file = None
	password = None
	key_bits = akes.all_key_bits[0]
	is_tty = sys.stdout.isatty()

	while optind+1 < argc:
		optind += 1
		argstr = argv[optind]
		arg = options.get(argstr)

		if arg == None:
			print('unrecognized command line option \''+argstr+'\'')
			sys.exit(1)

		if arg in (_e, _d):
			mode = arg
		elif arg == _in:
			optind += 1
			if optind < argc:
				in_file = argv[optind]
			else:
				arg = -1
		elif arg == _out:
			optind += 1
			if optind < argc:
				out_file = argv[optind]
			else:
				arg = -1
		elif arg == _key:
			optind += 1
			if optind < argc:
				key_file = argv[optind]
			else:
				arg = -1
		elif arg == _password:
			optind += 1
			if optind < argc:
				password = argv[optind]
			else:
				arg = -1
		elif arg == _keygen:
			optind += 1
			if optind < argc:
				keygen = argv[optind]
			else:
				arg = -1
		elif arg == _key_bits:
			optind += 1
			if optind < argc:
				key_bits_error = None
				try:
					key_bits = int(argv[optind])
					if key_bits not in akes.all_key_bits:
						key_bits_error = True
				except ValueError:
					key_bits_error = True
				if key_bits_error:
					print('key-bits must in', akes.all_key_bits)
					sys.exit(1)
			else:
				arg = -1
		elif arg == _stdio:
			is_stdio = True
		elif arg == _check:
			optind += 1
			if optind < argc:
				key_file = argv[optind]
				try:
					key,key_attr = akes.load_key(key_file)
					print(key_attr)
				except ValueError:
					print('key format error')
					sys.exit(1)
				sys.exit()
			else:
				arg = -1
		elif arg == _help:
			help(argv, akes)
			sys.exit()
		else:
			print('getopt error')
			sys.exit(1)

		if arg < 0:
			print('missing argument after \''+argstr+'\'')
			sys.exit(1)

	if not key_file:
		try:
			if keygen and not password:
				pass
			else:
				akes.generate_key(password='\n')
		except ValueError as e:
			print(e)
			sys.exit(1)

	if keygen:
		akes.generate_key(key_bits, key_file=keygen, password=password)
		sys.exit()

	if not in_file and not out_file:
		is_stdio = True

	if is_stdio:
		s = input('Please enter the text: ' if is_tty else '')
		ibs = s.encode()
		if mode == _DECRYPT:
			ibs = base64.b64decode(ibs)
	else:
		if not in_file:
			print('Missing input file')
			sys.exit(1)
		if not out_file:
			print('Missing output file')
			sys.exit(1)
		with open(in_file, 'rb') as in_file:
			ibs = in_file.read()
	if not len(ibs):
		print('No input data')
		sys.exit(1)

	if key_file:
		kbs,key_attr = akes.load_key(key_file)
	else:
		if not password:
			password = input('Please enter the password: ' if is_tty else '')
		if not len(password):
			password = '\n'
		kbs = akes.generate_key(key_bits, password=password)

	akes.fernet(kbs)

	if mode == _ENCRYPT:
		obs = akes.encrypt(ibs)
	else:
		obs = akes.decrypt(ibs)

	if is_stdio:
		if is_tty:
			print('Output:')
		if mode == _ENCRYPT:
			obs = base64.b64encode(obs)
		print(obs.decode(), end='')
		if is_tty:
			print()
	else:
		with open(out_file, 'wb') as out_file:
			out_file.write(obs)

	if is_tty:
		if is_stdio:
			print()
		print(("Encrypt" if mode == _ENCRYPT else "Decrypt"), "OK")


def help(argv, akes):
	print('Usage:    python3', argv[0], argv[1], '[options] [-in IN_FILE -out OUT_FILE]')
	print('Valid options are:')
	print(' -e                Encrypt')
	print(' -d                Decrypt')
	print(' -in in_file       Input file')
	print(' -out out_file     Output file')
	print(' -stdio            Standard input and output')
	print(' -k/-key key       Specifying the key file')
	print(' -p/-password ***  Specifying the password')
	print(' -keygen           Generate key')
	print(' -kb/-key-bits %d  Specify key length while Generate key, default =', akes.all_key_bits[0])
	print(' -c/-check key     check key format')
	print(' -h/-help          Display this message')


# Cleanup locals()
# del __all_supported
# del _ENCRYPT, _DECRYPT
