#!/usr/bin/env python3

__all__ = ('unique_fname', 'basename')

import os
from os import path

def unique_fname(fname:str)->str:
	if not os.access(fname, os.F_OK):
		return fname

	i = fname.rfind('.')
	if i < 0:
		i = len(fname)
	left = fname[:i] + '('
	right = ')' + fname[i:]

	name = [left, '', right]

	i = 1
	while True:
		name[1] = str(i)
		uname = ''.join(name)
		if not os.access(uname, os.F_OK):
			return uname
		i += 1

def basename(fname:str)->str:
	return path.basename(fname)

