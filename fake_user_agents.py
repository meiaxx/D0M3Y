#!/usr/bin/python3

import random

FILENAME = "agents.txt"

def generate_faker_agents():
	opened = open(FILENAME,'rb')

	# read all
	_alLines = opened.readlines()

	for _file in _alLines:
		# select random useragent
		random_header = random.choice(_file)

	print(random_header)

generate_faker_agents()
