#!/usr/bin/python3

# Code BY M3Y
# Get info throw of dorking

import requests
from colorama import all

# set colors
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
RESET = colorama.Fore.RESET

# *** DEFAULT SETTINGS +**
ROUTES_FILENAME = open("/opt/Tools/Web-Test/directory-list-lowercase-2.3-medium.txt",'r')
EXTENSIONS = ['php','bak','html','js''jsp','asxp']


class DORK:
    def __init__(self,target):
        self.google = 'http://google.com'
        self.target = target
        self.domain_word_dork = 'site: '
        self.data_found = []
        self.user_agents = 'Mozilla/5.0 (X11; Linux x86_64; rv:2.2a1pre) Gecko/20110324 Firefox/4.2a1pre'
        
        for routes in ROUTES_FILENAME.readlines(): # RF -> ROUTES_FILENAME
            self.inurl_dork = "inurl: /{}".format(routes) # generated many routes using SECLITS wordlists
    

    def dork_search_domain_google(self):
        """ Dork SubDomains Using Google """
        
        print(f'{green} [+] Dorking Using Google ... {RESET}')

        # construct the search query
        search = self.google + '/search?q=' + self.domain_word_dork + target

        # throw the requests
        response = requests.get(search,headers=self.user_agents)

    def dork_search_inurl_google(self):
        """ Dork Routes Using Google """
        print(f'{green} [+] Finding Intresting Files Dorking ... {RESET}')

        # start building the all query
        found_filenames = self.google + '/search?q=' + self.domain_word_dork + self.target + self.inurl_dork

        response_f1l3s = requests.get(found_filenames,headers=headers)
