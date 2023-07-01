#!/usr/bin/python3
# coding: utf-8

###########
# IMPORTS #
###########
import socket
import os
import threading
import colorama
from datetime import datetime
from colorama import Fore

# ports to save when won't found
ports = []

class D0M3YScan():
	def __init__(self,target,mode):
		self.target = target
		self.mode = mode

	"""
	scan()
	the function to connect to the target
	and scan the ports

	connect with sockets
	"""

	def scan_tcp(self,port):
		connection = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		socket.setdefaulttimeout(1)
		try:
			connection.connect((self.target,port))
			connection.close()
			print(f'{Fore.WHITE}Port {Fore.GREEN}{port}{Fore.WHITE} is open')
			ports.append(port)
		except Exception:
			pass

	"""
	scan_udp()
	Scan ports using udp connections
	"""
	def scan_udp(self):
		# start the socket
		udp_connection = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
		socket.setdefaulttimeout(1)

		try:
			udp_connection((self.target,port))
			udp_connection.close()

			print(f'{Fore.WHITE}Port {Fore.GREEN}{port}{Fore.WHITE} is open')
		except Exception:
			pass

	"""
	dom3y_portscan()
	scan the ports from the 1 to 65550
	with very faster 
	"""

	def dom3y_portscan(self):
		if self.mode == "tcp":
			print('\n')
			print("-"*41)
			print(f'{Fore.YELLOW} Mode: TCP{Fore.WHITE}')
			print(f'{Fore.YELLOW} Scanning: {self.target} {Fore.WHITE}')
			print(f'{Fore.YELLOW} Time Started Scan: {str(datetime.now())} {Fore.WHITE}')
			print("-"*41)

			try:
				scanned = 1
				for port in range(1,65500):
					#thread = threading.Thread(target=self.scan,args=(self.target,port,))
					thread = threading.Thread(target=self.scan,kwargs={'port':scanned})
					scanned += 1
					thread.start()
				print(f'{scanned} ports were scanned for {self.target}')
				print('Open ports: ' + str(ports))
			except RuntimeError:
				pass
		elif self.mode == "udp":
			print('\n')
			print("-"*41)
			print(f'{Fore.YELLOW} Mode: UDP{Fore.WHITE}')
			print(f'{Fore.YELLOW} Scanning: {self.target} {Fore.WHITE}')
			print(f'{Fore.YELLOW} Time Started Scan: {str(datetime.now())} {Fore.WHITE}')
			print("-"*41)
			try:
				scanned = 1
				for port in range(1,65500):
					#thread = threading.Thread(target=self.scan,args=(self.target,port,))
					thread = threading.Thread(target=self.scan_udp,kwargs={'port':scanned})
					scanned += 1
					thread.start()
			except:
				pass

