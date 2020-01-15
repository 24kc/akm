#!/usr/bin/env python3

from ctypes import cdll

_getch = cdll.LoadLibrary('akm/c/_getch.so')

def getch():
	return _getch.getch()

def getche():
	return _getch.getche()

def ungetc(c):
	return _getch.unget(c)

def reset():
	_getch.end_getch()
