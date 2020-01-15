#!/usr/bin/env python3

__all__ = ('OPT', 'help', 'main')

import socket, os, sys, signal
from threading import Thread
from queue import Queue
from enum import IntEnum,unique
from akm.aktalk.mmsock import *
from akm.akes import Akes
from akm.io.o import *

def exit():
	os._exit(1)

signal.signal(signal.SIGINT, exit)

# Client MMSock
mmsock = None
# Akes
akes_rsa = None
akes_aes = None
# status
conn_stat = False
# the other addr (ip, port)
the_other = None
# message list
msg_list = []
wait_print = 0

def send():
	while True:
		# need getch to wait print
		s = input('>> ')
		if not conn_stat:
			print('Please wait for others to connect ...')
			continue
		while msg_list:
			print(msg_list[0], end='')
			del msg_list[0]
		if s:
			mmsock.send(akes_aes.encrypt(s.encode()), MMT.CIPHER_TEXT)

def recv():
	while True:
		data,mmt = mmsock.recv()
		flag = msg_proc(data, mmt)
		if not flag:
			print('\nERROR: connect to server closed', end='')
			os._exit(1)


def wprint(*objects, **kwargs):
	'''print, may have to wait for a while'''
	if wait_print:
		s = sprint(*objects, **kwargs)
		msg_list.append(s)
	else:
		print(*objects, **kwargs)

def sem_proc(mmt):
	'''Semaphore processing'''
	global akes_rsa, akes_aes, conn_stat
	if mmt == MMT.SM_NONE:
		print('No one is online, waiting...')
	elif mmt == MMT.SM_PUBGEN:
		print()
		print('generate RSA keys ...')
		akes_rsa = Akes.new('RSA')
		rsa = akes_rsa.generate_key()
		akes_rsa.fernet(rsa)
		der = rsa.publickey().exportKey('DER')
		print('send public key ...')
		mmsock.send(der, MMT.PUBLIC_KEY)
		print('wait for AES key ...')
	elif mmt == MMT.SM_SYMGEN:
		print()
		print('wait for public key ...')
	elif mmt == MMT.SM_ENCRYPT:
		print('send my addr(AES encrypted)')
		laddr = str(mmsock.laddr()).encode()
		mmsock.send(akes_aes.encrypt(laddr), MMT.CIPHER_ADDR)
	elif mmt == MMT.SM_CLOSE:
		conn_stat = False
		print()
		print(f'Warning<< {the_other} is disconnected')
	else:
		return False
	return True

def msg_proc(data, mmt=MMT.PLAIN_TEXT):
	'''Message processing'''
	global akes_rsa, akes_aes, conn_stat, the_other

	if not data:
		return sem_proc(mmt)

	if mmt == MMT.URGENT_MSG:
		print('\nURGENT_MSG<<', data.decode())

	elif mmt == MMT.SERVER_MSG:
		wprint(f'SERVER_MSG<< {data.decode()}')

	elif mmt == MMT.PUBLIC_KEY:
		print('received the public key')
		print('check public key ...')
		akes_rsa = Akes.new('RSA')
		try:
			pubkey = akes_rsa.import_key(data)
		except Exception as e:
			print('Bad public key:', e)
			return False
		akes_rsa.fernet(pubkey)
		print('generate AES key ...')
		akes_aes = Akes.new('AES')
		symkey = akes_aes.generate_key(256)
		print('encrypt AES key with public key ...')
		symkey_rsa = akes_rsa.encrypt(symkey)
		print('send AES key ...')
		akes_aes.fernet(symkey)
		mmsock.send(symkey_rsa, MMT.SYMM_KEY)

	elif mmt == MMT.SYMM_KEY:
		print('received the AES key')
		print('decrypt AES key with private key ...')
		symkey = akes_rsa.decrypt(data)
		print('set AES key ...')
		akes_aes = Akes.new('AES')
		akes_aes.fernet(symkey)
		print('send my addr(AES encrypted) ...')
		mmsock.sendsem(MMT.SM_ENCRYPT)
		laddr = str(mmsock.laddr()).encode()
		mmsock.send(akes_aes.encrypt(laddr), MMT.CIPHER_ADDR)

	elif mmt == MMT.PLAIN_TEXT:
		wprint(f'{the_other:}P<< {data.decode()}')

	elif mmt == MMT.CIPHER_TEXT:
		# decrypt
		data = akes_aes.decrypt(data)
		wprint(f'{the_other:}C<< {data.decode()}')

	elif mmt == MMT.CIPHER_ADDR:
		print('recv the other addr ...')
		data = akes_aes.decrypt(data)
		the_other = data.decode()
		conn_stat = True
		print('Now encrypt messages with aes !')

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

