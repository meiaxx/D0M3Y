#!/usr/bin/python3
# data: 23/08/22
# By M3Y

import urllib.request as urllib2
import threading
import queue
import urllib
import os, sys
import datetime

#Colors
white="\033[1;37m"
grey="\033[0;37m"
purple="\033[0;35m"
red="\033[1;31m"
green="\033[1;32m"
yellow="\033[1;33m"
Purple="\033[0;35m"
cyan="\033[0;36m"
Cafe="\033[0;33m"
Fiuscha="\033[0;35m"
blue="\033[1;34m"
nc="\e[0m"

# default settings

threads = 100

resume = None

user_agent = "Mozilla/5.0 (X11; Linux x86_64; rv:19.0) Gecko/20100101Firefox/19.0"

logo = "banner.txt"

found_urls = set()

def banner():
	os.system("clear")
	with open(logo,'r') as LG:
		print("%s %s %s" % (Purple,LG.read(),white))

class V3RD1R:
	def __init__(self,target,wordlist):
		self.target = target
		self.wordlist = wordlist

	def build_wordlist(self,wordlist_file):
		# read in the word list
		fd = open(wordlist_file,"rb")

		raw_words = fd.readlines()
		fd.close()

		found_resume = False
		words = queue.Queue()

		for word in raw_words:
			word = word.rstrip()

			if resume is not None:
				if found_resume:
					words.put(word)
				else:
					if word == resume:
						found_resume = True
						print("%s [!] Resuming wordlist from: %s %s" % yellow,resume,white)
			else:
				words.put(word)
		return words

	def dir_bruter(self,word_queue,extensions=None):
		while not word_queue.empty():
			attempt = word_queue.get()

			attempt_list = []

			if "." not in attempt:
				attempt_list.append("/%s/" % attempt)
			else:
				attempt_list.append("/%s/" % attempt)

			if extensions:
				for extension in extensions:
					attempt_list.append("/%s%s" % (attempt,extension))

			for brute in attempt_list:
				url = "%s%s" % (self.target,urllib.quote(brute))

				try:
					headers = {}
					
					headers["User-Agent"] = user_agent
					
					r = urllib2.Request(url,headers=headers)

					response = urllib2.urlopen(r)

					# chech all posibles response codes
					if response.code == 200:
						print("%s[+] Status: %d Method: (GET) Path: %s %s " % (green,response.code,url,white))

						found_urls.add(url)

				except urllib2.URLError as e:
					if hasattr(e,'code') and e.code != 404:
						print("%s[!] Status: %d Method: (GET) Path: %s %s" % (yellow,e.code,url,white))
					if hasattr(e,'code') and e.code in range(500,600):
						print("%s[+] Status: %d Method: (GET) Path: %s %s " % (red,e.code,url,white))
					pass
				# pass any exception
				except:
					pass
	def save_output(self,Filename,target,data):
		mode = 'w+'

		# URL/TARGET
		target_info = "Target: {}".format(target)

		# save the results
		with open(Filename,mode) as results:
			results.write("-"*100+"\n")
			results.write(target_info+"\n")
			results.write("-"*100+"\n")

			# sava all the data founded

			resulsts.write(str(data))
