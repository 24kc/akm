#!/usr/bin/env python3

__all__ = ('OPT', 'help', 'main')

import socket, os, sys, signal
from threading import Thread
from enum import IntEnum,unique
from akm.aktalk.mmsock import *
from akm.akes import Akes

def exit():
	os._exit(1)

signal.signal(signal.SIGINT, exit)

# Client MMSock
mmsock = None
# Akes
akes = None

def send():
	while True:
		s = input('>> ')
		if not akes:
			print('wait ...')
			continue
		if s:
			mmsock.send(akes.encrypt(s.encode()), MMT.CIPHER_TEXT)

def recv():
	while True:
		data,mmt = mmsock.recv()
		flag = msg_proc(data, mmt)
		if not flag:
			print('\nERROR: connect to server closed\n>> ', end='')
			os._exit(1)


def wprint(*objects, **kwargs):
	'''print, may have to wait for a while'''
	print(*objects, **kwargs)

def sem_proc(mmt):
	'''Semaphore processing'''
	global akes
	if mmt == MMT.SM_NONE:
		print('No one is online, waiting...')
	elif mmt == MMT.SM_PUBGEN:
		akes = Akes.new('RSA')
		print('generate RSA keys ...')
		rsa = akes.generate_key()
		akes.fernet(rsa)
		der = rsa.publickey().exportKey('DER')
		print('send public key ...')
		mmsock.send(der, MMT.PUBLIC_KEY)
		print('wait for AES key ...')
	elif mmt == MMT.SM_SYMGEN:
		print('wait for public key ...')
	elif mmt == MMT.SM_ENCRYPT:
		print('Now encrypt messages with aes !')
	else:
		return False
	return True

def msg_proc(data, mmt=MMT.PLAIN_TEXT):
	'''Message processing'''
	global akes
	if not data:
		return sem_proc(mmt)
	if mmt == MMT.URGENT_MSG:
		print('\nURGENT_MSG<<', data.decode())
	elif mmt == MMT.SERVER_MSG:
		wprint(f'SERVER_MSG<< {data.decode()}')
	elif mmt == MMT.PUBLIC_KEY:
		print('received the public key')
		rsa = Akes.new('RSA')
		try:
			pubkey = rsa.import_key(data)
		except Exception as e:
			print('Bad public key:', e)
			return False
		rsa.fernet(pubkey)
		print('generate AES key ...')
		aes = Akes.new('AES')
		symkey = aes.generate_key(256)
		print('encrypt AES key with public key ...')
		symkey_rsa = rsa.encrypt(symkey)
		print('send AES key ...')
		mmsock.send(symkey_rsa, MMT.SYMM_KEY)
		akes = aes
		akes.fernet(symkey)

	elif mmt == MMT.SYMM_KEY:
		print('received the AES key')
		print('decrypt AES key with private key ...')
		symkey = akes.decrypt(data)
		print('set AES key ...')
		akes = Akes.new('AES')
		akes.fernet(symkey)
		mmsock.sendsem(MMT.SM_ENCRYPT)
		print('Now encrypt messages with aes !')
	elif mmt == MMT.PLAIN_TEXT:
		wprint(f'P<< {data.decode()}')
	elif mmt == MMT.CIPHER_TEXT:
		# decrypt
		wprint('cipher text:', data)
		data = akes.decrypt(data)
		wprint(f'C<< {data.decode()}')
	elif mmt == MMT.COMMAND:
		pass
	else:
		raise ValueError('msg_proc error', mmt)
	return True


@unique
class OPT(IntEnum):
	'''options'''
	IP = 0x2411
	PORT = 0x2412
	HELP = 0x2499
	NULL = 0

options = {
	'-ip': OPT.IP,
	'-p': OPT.PORT,
	'-port': OPT.PORT,
	'-h': OPT.HELP,
	'-help': OPT.HELP
}


def main(argv):
	argc = len(argv); optind = 0

	ip = '0.0.0.0'
	port = 10024

	while optind+1 < argc:
		optind += 1
		optstr = argv[optind]
		opt = options.get(optstr)

		if not opt:
			print('unrecognized command line option \''+optstr+'\'')
			sys.exit(1)

		if opt == OPT.IP:
			optind += 1
			if optind < argc:
				argstr = argv[optind]
				ip = argstr
			else:
				opt = OPT.NULL
		elif opt == OPT.PORT:
			optind += 1
			if optind < argc:
				argstr = argv[optind]
				try:
					port = int(argstr)
				except ValueError:
					print('Port must be in (0, 65535) not', argstr)
					sys.exit(1)
			else:
				opt = OPT.NULL
		elif opt == OPT.HELP:
			help(argv)
			sys.exit()
		else:
			assert False,'getopt error'

		if opt == OPT.NULL:
			print('missing argument after \''+optstr+'\'')
			sys.exit(1)

	sock = socket.socket()
	socket_reuse(sock)

	global mmsock
	mmsock = MMSock(sock)

	sock.connect((ip, port))

	try:
		t_send = Thread(target=send)
		t_recv = Thread(target=recv)

		t_send.start()
		t_recv.start()

		t_send.join()
		t_recv.join()
	except Exception as e:
		print('Client Error:', 'KeyboardInterrupt or maybe other errors')
	os._exit(1)

if __name__ == '__main__':
	import sys
	main(sys.argv)

