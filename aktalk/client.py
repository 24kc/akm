#!/usr/bin/env python3

__all__ = ('OPT', 'help', 'main')

import socket, os, sys, signal, time
from threading import Thread
from queue import Queue
from enum import IntEnum,unique
from akm.aktalk.mmsock import *
from akm.akes import Akes
from akm.io.o import *
from akm.io import fm
from akm.c import getch

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
# server
server_addr = None
# my ip
my_addr = None
# the other addr (ip, port)
the_other = None
# message list
msg_list = []
wait_print = False
msg_end = '\n>> '
# File storage directory
download_dir = 'download'


def send():
	global wait_print
	while True:
		wait_print = False
		print('>> ', end='', flush=True)
		# need getch to wait print
		c = getch.getche()
		if c == 0x0a:
			continue
		else:
			wait_print = True
			getch.ungetc(c)

		s = input()

		cache_print()

		is_cmd = command(s)

		if is_cmd:
			continue

		if not conn_stat:
			print('Please wait for others to connect ...')
			continue

		if s:
			mmsock.send(akes_aes.encrypt(s.encode()), MMT.CIPHER_TEXT)

def recv():
	while True:
		data,mmt = mmsock.recv()
		flag = msg_proc(data, mmt)
		if not flag:
			print(f'\n\nconnect to server{server_addr} closed')
			cache_print()
			os._exit(1)

@unique
class CMD(IntEnum):
	'''command'''
	NULL = 0
	EXIT = 0x2400
	EXIT_ = 0x2401
	SCP = 0x2410
	SCP_ = 0x2411
	WHO = 0x2420
	WHO_ = 0x2421
	ME = 0x2430
	ME_ = 0x2431

commands = {
	'exit': CMD.EXIT,
	'exit?': CMD.EXIT_,
	'scp': CMD.SCP,
	'scp?': CMD.SCP_,
	'who': CMD.WHO,
	'who?': CMD.WHO_,
	'me': CMD.ME,
	'me?': CMD.ME_,
}

def send_file(fname):
	fname = os.path.expanduser(fname)
	r = os.access(fname, os.F_OK | os.R_OK)
	if not r:
		print('File does not exist or is unreadable')
		return 1
	content = open(fname, 'rb').read()
	content = akes_aes.encrypt(content)
	if not content:
		print('Empty file, cancel sending')
		return 1
	fname = fm.basename(fname)
	fnb = fname.encode()
	data = int.to_bytes(len(fnb), 4, 'little') + fnb + content
	mmsock.send(data, MMT.SCP_FILE)
	return 0

def recv_file(data):
	ddir = download_dir
	try:
		if not os.access(ddir, os.F_OK):
			os.mkdir(ddir, 0o775)
		if not os.path.isdir(ddir):
			wprint('Warning<< scp<<', ddir, 'is not a directory, redirect to current directory', end='')
			ddir = '.'
		fnlen = int.from_bytes(data[:4], 'little')
		fname = data[4: fnlen+4].decode()
		fname = ddir + '/' + fname
		fname = fm.unique_fname(fname)
		content = akes_aes.decrypt(data[fnlen+4:])
		open(fname, 'wb').write(content)
		wprint(f'scp<< received a file \'{fname}\'', end='')
	except Exception as e:
		print('recv file:', e)
		return False
	return True

def cmd_proc(argv):
	argc = len(argv);
	if not argc:
		return

	cmdstr = argv[0]
	cmd = commands.get(cmdstr)

	if not cmd:
		print('unrecognized command \'' + cmdstr + '\'')
		return 1

	if cmd == CMD.EXIT_:
		print('Exit chat, close the connection to the server')
	elif cmd == CMD.EXIT:
		mmsock.sendsem(MMT.SM_EXIT)
	elif cmd == CMD.SCP_:
		print('scp [file]\nSend file to the other [AES]')
	elif cmd == CMD.SCP:
		if argc >= 2:
			if not conn_stat:
				print('Please wait for others to connect ...')
				return 1
			return send_file(argv[1])
		else:
			cmd = CMD.NULL
	elif cmd == CMD.WHO:
		print(the_other)
	elif cmd == CMD.WHO_:
		print('Print the ip address of the other')
	elif cmd == CMD.ME:
		print(my_addr)
	elif cmd == CMD.ME_:
		print('Print the ip address of me')
	else:
		assert False,'cmd_proc error'

	if not cmd:
		print('missing argument after \'' + cmdstr + '\'')

	return 0

def command(cmd:str):
	try:
		symbol = ':'
		if not cmd.startswith(symbol):
			return 0
		cmd = cmd[len(symbol):]
		cmd = cmd.replace('\t', ' ')
		argv = cmd.split(' ')
		try:
			while True:
				argv.remove('')
		except:
			pass
		cmd_proc(argv)
		return 1
	except Exception as e:
		print('command err:', e)
		pass

def heart_beat():
	while True:
		mmsock.sendsem(MMT.HEART_BEAT)
		time.sleep(MM_TMOUT)

def wprint(*objects, **kwargs):
	'''print, may have to wait for a while'''
	s = sprint(*objects, **kwargs)
	if wait_print:
		msg_list.append(s)
	else:
		print(f'\n{s}\n>> ', end='')

def cache_print():
	if msg_list:
		print()
	while msg_list:
		print('cache<<', msg_list[0])
		del msg_list[0]

def sem_proc(mmt):
	'''Semaphore processing'''
	global akes_rsa, akes_aes, conn_stat

	if mmt == MMT.SM_NONE:
		print('\nNo one is online, waiting...', end=msg_end)

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
		print('\n')
		print('wait for public key ...')

	elif mmt == MMT.SM_ENCRYPT:
		print('send my addr(AES encrypted)')
		laddr = str(my_addr).encode()
		mmsock.send(akes_aes.encrypt(laddr), MMT.CIPHER_ADDR)

	elif mmt == MMT.SM_BUSY:
		print('\ne, There are already at least 2 users connected to the server', end=msg_end)

	elif mmt in (MMT.SM_CLOSE, MMT.SM_EXIT):
		conn_stat = False
		cache_print()
		print()
		if mmt == MMT.SM_CLOSE:
			print(f'Warning<< {the_other} is disconnected', end=msg_end)
		else:
			print(f'Warning<< {the_other} has exited', end=msg_end)

	else:
		return False

	return True

def msg_proc(data, mmt=MMT.PLAIN_TEXT):
	'''Message processing'''
	global akes_rsa, akes_aes, conn_stat, my_addr, the_other

	if not data:
		return sem_proc(mmt)

	if mmt == MMT.URGENT_MSG:
		print('\nURGENT_MSG<<', data.decode(), end=msg_end)

	elif mmt == MMT.SERVER_MSG:
		wprint(f'SERVER_MSG<< {data.decode()}', end='')

	elif mmt == MMT.CLIENT_ADDR:
		my_ip = data.decode()
		ipaddr,port = mmsock.laddr()
		my_addr = (my_ip, port)

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
		laddr = str(my_addr).encode()
		mmsock.send(akes_aes.encrypt(laddr), MMT.CIPHER_ADDR)

	elif mmt == MMT.PLAIN_TEXT:
		wprint(f'P<< {data.decode()}', end='')

	elif mmt == MMT.CIPHER_TEXT:
		# decrypt
		try:
			data = akes_aes.decrypt(data)
		except Exception as e:
			print('AES decrypt ERR<<', e)
		else:
			wprint(f'C<< {data.decode()}', end='')

	elif mmt == MMT.CIPHER_ADDR:
		print('recv the other addr ...')
		data = akes_aes.decrypt(data)
		the_other = data.decode()
		conn_stat = True
		print(f'Connected to {the_other} [AES]', end=msg_end)

	elif mmt == MMT.COMMAND:
		pass

	elif mmt == MMT.SCP_FILE:
		return recv_file(data)

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

	global server_addr
	server_addr = (ip, port)
	sock.connect(server_addr)

	try:
		t_heart = Thread(target=heart_beat)
		t_send = Thread(target=send)
		t_recv = Thread(target=recv)

		t_heart.start()
		t_send.start()
		t_recv.start()

		t_send.join()
		t_recv.join()
	except Exception as e:
		print('\n\nClient Error:', 'KeyboardInterrupt or maybe other errors')
	getch.reset()
	cache_print()
	os._exit(1)

if __name__ == '__main__':
	import sys
	main(sys.argv)

