#!/usr/bin/python3
# Code By M3Y

### *** Imports *** ###
import requests
#from sqli.DB import DB

"""
it will attack sqli flaws
on a specific server

get engine db
MYSQL
MSSQL
POSTGRESQL

##########
SQLI TYPES
##########
boolean-based
error-based
union-attack

boolean: it will get Boolan attacks
error-based: based on error
union: union, first it will get the column-length

1) * will get check DBS name
2) * will get Tables
3) * will get Columns
4) * Last the data 

"""
class SQLM3Y:
	def __init__(self,url):
		self.url = url

	def get_dbs(self):
		pass
