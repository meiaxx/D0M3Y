#!/usr/bin/python3

# coding: utf-8
# D0M3Y 1.0
# By M3Y

###########
# IMPORTS #
###########

try:
	import socket
	import time
	from time import perf_counter,sleep
	import requests
	import os
	import sys
	from threading import Thread,Lock
	import argparse
	from colorama import *
	import socket
	from datetime import datetime
	from concurrent.futures import ThreadPoolExecutor
	from multiprocessing.pool import Pool
	import urllib3
	from art import text2art
	from termcolor import colored
	import random
	import subprocess
	import re
	import concurrent.futures
	import json
	from tqdm import *
	import concurrent.futures
	from bs4 import BeautifulSoup
	import urllib.parse
	from collections import deque
	import requests.exceptions
	import builtwith
	from urllib.parse import urljoin
except ModuleNotFoundError as e:
	print(e)

# utilities d0m3y
from portscanner import *
from lib.SQLI import SQLM3Y
from lib.LFI import LFI

from v3rd1r import banner,V3RD1R

# disable all the warning msg's
urllib3.disable_warnings()

# AGENT
with open("agents.txt","r") as File:
    for f in File.readlines():
        random_agents = random.choice(f)

# Default Settings
extensions = ['.php','.bak','.html','.xml','.py','.js','.json','.rb',
              '.asp','.jsp','.aspx','.conf','.cgi','.htm','.pl','.do',
              '.php.bak','.bak.php']

# All Colors settings
GREEN = colorama.Fore.GREEN
GRAY = colorama.Fore.LIGHTBLACK_EX
RESET = colorama.Fore.RESET
YELLOW = colorama.Fore.YELLOW
WHITE = colorama.Fore.WHITE
BLUE = colorama.Fore.BLUE
RED = colorama.Fore.RED
CYAN = colorama.Fore.CYAN

parse = argparse.ArgumentParser(prog='D0M3Y')
parse.add_argument("-d","--domain",help="target")
parse.add_argument("-o","--output",help="output")
parse.add_argument("-t","--workers",help="threads",type=int)
parse.add_argument("-k","--ssl",help="ssl",action='store_true')
parse.add_argument("-df","--domainfile",help="wordlist domains")
parse.add_argument("-F","--FILE-DOMAINS",help="CHECK/GET INFO FROM A DOMAIN LIST FILE")

#TODO
parse.add_argument("--web-server","--WS")

# Scan arguments
parse.add_argument("-s","--scan",help="scan port's from the domain",action='store_true')
parse.add_argument("-scanmode","--modescan",help='Scan Mode TCP/UDP',type=str)

parse.add_argument("-e","--engine",help="search by engine",action='store_true')

# Find Dirs argumets
parse.add_argument("-sb","--subbrute",help="search by bruteforcing",action='store_true')
parse.add_argument("-sd","--searchdirectory",help="Search all the directories from the domains",action='store_true')
parse.add_argument("-dirfile","--dirfilename",help="BruteDirectory Wordlist")
parse.add_argument("-x","--extension",help='extension (php,html,txt)',required=False)
parse.add_argument("-hc","--hidechars",help="Hide specific characters",type=int)

# Find Emails arguments
parse.add_argument("-ems","--emailscrapper",help='Find Emails From the domain',action='store_true')
parse.add_argument("-maxurls","--maxurls",help="The max urls to find emails",type=int)

# cookies 
parse.add_argument("-c","--cookies",help='cookies')

# Find Web Applications bugs
parse.add_argument("-URL","--URLTARGET",help='Url target to test vulns')
parse.add_argument("-xss","--xssvuln",help='looking for XSS',type=str)
parse.add_argument("-lfi","--pathtrav",help='Path Travesal/LFI scan',action='store_true')

# Fastet Tools parmas
parse.add_argument("-ffuf","--FFUF",help="Use FFUF For Faster search directories",action='store_true')
parse.add_argument("-FFWW","--ffufwordlist",help='FFUF wordlist')

# get web technologies
parse.add_argument("-webtech","--WT",help="Get all the web technologies from all the domains",action='store_true')

# params to get cotent like :
# JS/CSS/IMGS
parse.add_argument('-getcontent',"--GETCONTENT",help='get content from the urls like: JS/CSS/IMG Files',action='store_true')

# NMAP ... more faster :|
parse.add_argument("-nmap","--nmapscanner",help='Scanning with Nmap',action='store_true')

# GOOGLE - DORKING
parse.add_argument("-dork","--dorking",help="Google Dorking for find information",action='store_true')

# SubDomain TakeOver
parse.add_argument("-sbt","--subtakeo",help="Subdomain Taker Over",action='store_true')

#scan ports
parse.add_argument("-host","--hosttarget",help='Host for portscan')

# v3rd1r utility
parse.add_argument("-v3rd1r","--v3rd1r_scanner",help='V3Rd1R path finder',action='store_true')

args = parse.parse_args()

# *** #
hostt = args.hosttarget


# v3rd1r params
v3rd1r = args.v3rd1r_scanner

# set all variables
domain = args.domain
output = args.output
workers = args.workers
scan = args.scan
modescan = args.modescan
domainfile = args.domainfile
ssl = args.ssl
engine = args.engine
subbrute = args.subbrute
searchdirectory = args.searchdirectory
extension = args.extension
emailscrapper = args.emailscrapper
maxurls = args.maxurls
cookies = args.cookies
dirfilename = args.dirfilename
FILEDOMAIN = args.FILE_DOMAINS

# WEB FUZZ PARAMS
URLTARGET = args.URLTARGET
pathtrav = args.pathtrav
xssvuln = args.xssvuln

# FTParams
FFUF = args.FFUF
ffufwordlist = args.ffufwordlist

# DORK
dorking = args.dorking

# FFUF
WT = args.WT

#NMAP..
nmapscanner = args.nmapscanner

# CONTENT FINDER
GETCONTENT = args.GETCONTENT

# SUBDOTAKE
subtakeo = args.subtakeo

# time
a = datetime.datetime.now()
t1 = "%s:%s:%s" % (a.minute, a.second, str(a.microsecond)[:2])

#user agents
headers_useragents = []

# HTTPS - SSL Domains
ssldomains = []

# domains founds
# save in this list
domains = []

# time set
start_time = perf_counter()


"""
ffuf() -> take 3 arguments
          1 -> url target
          2 -> wordlist with all the directories
          3 -> threads to work
"""
def ffuf(url,wordlist,threads):
    Fuzzer = subprocess.Popen(["ffuf -w {} -u {}/FUZZ -t {}".format(wordlist,url,threads)],stdout=subprocess.PIPE,shell=True)

    error = Fuzzer.communicate()

    if "Command 'ffuf' not found, but can be installed with:" in error:
        # ask install ffuf
        print("[!] ffuf not found")
        print("[!] Install With: sudo apt-get install ffuf -y")
        print()



try:
    def return_ttl(ip_address):
        try:
            proc = subprocess.Popen(["/bin/ping -c 1 %s" % ip_address, ""], stdout=subprocess.PIPE, shell=True)
            (out, err) = proc.communicate()
            out = out.split()

            out = out[13].decode('utf-8')
            ttl_value = re.findall(r"\d{1,3}", out)[0]

            return ttl_value
        except Exception as e:
            pass

    def return_ttl_os_name(ttl):

        ttl = int(ttl)

        if ttl >= 0 and ttl <= 64:
            return("Linux")
        elif ttl >= 64 and ttl <= 128:
            return("Windows")
        else:
            return("Not found")
except ValueError:
        sys.exit(1)

def banner():
	os.system("clear")
	banner = text2art("D0M3Y")
	print(colored(banner,'red'))
	print(colored("\t\t\t # Created By M3Y",'red'))
	print("\n"+t1)

def loading_bar(File):
    # start the proccess of bar loading ...
    lenfile =  os.popen(f"wc -l {File}").readline().split()[0]

    for i in trange(int(lenfile)):
        sleep(0.001)

def get_techs(url):
    try:
        website = builtwith.parse(url)
        print(" ".join(language))
    except:
        pass

"""
_get_files_content() ->
                        take only 1 argument
                        1) URL Target
example:
         http://www.google.com
"""
def _get_files_content(url):
    try:
        # throw the requests 
        # TYPE: GET
        content = requests.get(url,verify=False)

        print(f"{GREEN}[*] Javascript {RESET}")

        # :)
        ######
        # This is For Find Javascript Filenames...

        ##############
        ###  JS    ###
        ##############
        # now attempt to getting the JS files
        # convert to soup
        soup = BeautifulSoup(content.text,'html.parser')
        
        # GET the Javascript files
        script_files = []

        for script in soup.find_all("script"):
            if script.attrs.get("src"):
                script_url = urljoin(url,script.attrs.get("src"))
                script_files.append(script_url)

        # run on all the js file found
        for js in script_files:
            print('-'*50)
            print(js)   
            print('-'*50) 

        ########################
        ####   C   S  S    #####
        ########################

        print(f"{GREEN}[*] CSS {RESET}\n")
        css_files = []

        for css in soup.find_all("link"):
            if css.attrs.get("href"):
                css_url = urljoin(url,css.attrs.get("href"))
                css_files.append(css_url)

        # run on all the css file found
        for csf in css_files:
            print('-'*50)
            print(csf)
            print('-'*50)

        print(f"{GREEN}[*] Images: {RESET}")
        for image in re.findall("<img (.*)>",content.text):
            for images in image.split():
                    if re.findall("src=(.*)",images):
                            image = images[:-1].replace("src=\"","")
                            if(image.startswith("http")):
                                    print(image)
                            else:
                                print(url + image)
                                print('\n')
    except:
        pass

def save_file(filename,subdomains):
	print(f"\n{YELLOW}[+] Saving Domains in: {WHITE}{filename} {YELLOW}filename {RESET}")

	# save the output in a filename
	with open(filename,"w+") as f:
		for d in subdomains:
			f.write(d+os.linesep)
              
# here initialized the scan
def searchdomain(domain,filename):
    # domains found save in this list
    global domains
    try:
        ttl = return_ttl(domain)
        print(f"\nOS: {domain} -> {return_ttl_os_name(ttl)}")
    except:
        pass 
    
    # LOADING ...
    loading_bar(filename)
    
    # show pretty dates
    IP = socket.gethostbyname(domain)
    target = f"""
{YELLOW}Ip: {CYAN}{IP}{RESET} | {YELLOW}Target: {CYAN}{domain}{RESET}  |  {YELLOW}Filename: {CYAN}{filename}{RESET}  | {YELLOW} Threads: {CYAN}{workers}{RESET} """
    print(target+"\n")
    
    # Domains to Search  
    domains_to_search = open(filename,'r')
    # user-agents
    headers = {'User-Agent' : random_agents}
    
    for dts in domains_to_search.readlines():
        dts = dts.strip() # strip with a jump 
        
        if ssl:
            # create the full url
            full_url = f"https://{dts}.{domain}"
            try:
                # if the raise an ERROR) that means the subdomain does not exists 
                requests.get(full_url,headers=headers,verify=False)
            except requests.ConnectionError:
                pass
            except requests.exceptions.InvalidURL:
                pass
            else:
                try:
                    # stripped the domain for get the IP   
                    d0m4in1P = full_url.replace("https://","")
                    get_ip = socket.gethostbyname(d0m4in1P)
                    found_d = f"""
                    {YELLOW}Ip Address: {GREEN} {get_ip} {YELLOW}Subdomain: {GREEN} {full_url} {YELLOW}Code: {GREEN}200{RESET}
                    """
                    print(found_d)
                    
                    ssldomains.append(full_url)
                
                except socket.gaierror:
                    pass
                
                if output:
                    save_file(output,ssldomains)
                else:
                    #  create the full url
                    full_url = f"http://{dts}.{domain}"
                    try:
                        # if the raise an ERROR) that means the subdomain does not exists
                        r=requests.get(full_url,headers=headers)
                    except requests.ConnectionError:
                        pass
                    except requests.exceptions.ConnectionError:
                        pass
                    except requests.exceptions.InvalidURL:
                        pass
                    else:
                        try:
                            # stripped the domain for get the IP   
                            d0m4in1P = full_url.replace("http://","")
                            get_ip = socket.gethostbyname(d0m4in1P)
                            found_d = f"""
                            {YELLOW}Ip Address: {GREEN} {get_ip} {YELLOW}Subdomain: {GREEN} {full_url} {YELLOW}Code: {GREEN}{r.status_code}{RESET}
                            """
                            print(found_d)
                            domains.append(full_url)
                        except socket.gaierror:
                            pass
                        
                        if output:
                            save_file(output,domains)

    # clos the filename
    domains_to_search.close()

"""
Search Subdomains by Engines
For example:
Bin-Google-Shodan
"""

# set subdomains list
subdomains = set()

class EngineSearch():
    def __init__(self,domain,threads):
        self.domain = domain
        self.threads = threads

        print("\n\n")
        print(f"Finding Subdomains For {self.domain} ---- Threads: {self.threads}")

    # search all the domains from 
    # Internet
    def find(self):
        try:
            # find from crt.sh
            # getting Certificate
            print(f"{YELLOW}[*] Getting SubDomains [*]{RESET}\n")

            # sleep for microseconds

            time.sleep(0.001)

            crt = "https://crt.sh/?q={}&output=json".format(self.domain)

            # throw the requests
            crtsearch = requests.get(crt)

            if crtsearch.ok:
                # get all
                jsondata = json.loads(crtsearch.content)

                for i in range(len(jsondata)):
                    name_value = jsondata[i]['name_value']

                    if name_value.find('\n'):
                        subname_value = name_value.split('\n')

                        for subname_value in subname_value:
                                if subname_value.find('*'):
                                    if subname_value not in subdomains:
                                        subdomains.add(subname_value)
        except:
            pass
# domains directories
domains_directories = []

"""
checks the domain and 
show information
"""
def checklivedomains(DOMAINS):
    # check all the domains without HTTP ERRORS

    try:
        # https:// + www.google.com = https://www.google.com
        RequestVD = requests.get('https://' + DOMAINS,verify=False)

    except requests.exceptions.ConnectionError:
        print(f'{RED}{DOMAINS} : Invalid {RESET}')
    except urllib3.exceptions.ReadTimeoutError:
        pass
    except requests.exceptions.ReadTimeout:
        pass
    else:
        try:
            ttl = return_ttl(DOMAINS)
            ip_addr = socket.gethostbyname(DOMAINS)
            print(f"{GREEN}" + DOMAINS + f" : Valid {RESET}" + f"IP: {GREEN}" + ip_addr + f"{RESET}" + f" OS: {GREEN}" + return_ttl_os_name(int(ttl)) + f"{RESET}" )
            domains_directories.append(DOMAINS)
        except:
            pass

"""
check domains throw of a filename
"""
def CheckDomainsFromFile(filename):
    with open(filename,'r') as FILE:
        for D in FILE.readlines():
            D = D.strip()
            full_url = "https://" + D

            try:
                # we throw the requests
                r = requests.get(full_url,verify=False)
                ttl = return_ttl(D)
                ip_addr = socket.gethostbyname(D)
                print(f"{GREEN}" + D + f" : Valid {RESET}" + f"IP: {GREEN}" + ip_addr + f"{RESET}" + f" OS: {GREEN}" + return_ttl_os_name(int(ttl)) + f"{RESET}" )
            except Exception as e:
                print(f"{RED}{e}{RESET}")


# Find all the emails from the domain
# all the emails save it here:

scraped_urls = set()
emails = set()

def emails_scrapping(target):
    print(f"{YELLOW}\n\n[*] Extracting all the emails{RESET}\n")
    print(f"{YELLOW}[*] Max Emails To Found: {RESET}{maxurls}\n")

    urls = deque([target])

    count = 0

    try:
        while len(urls):
            count += 1

            if count == maxurls:
                break

            url = urls.popleft()
            scraped_urls.add(url)

            parts = urllib.parse.urlsplit(url)
            base_url = '{0.scheme}://{0.netloc}'.format(parts)

            path = url[:url.rfind('/') + 1] if '/' in parts.path else url

            print(f'[{BLUE}%d{RESET}] {GREEN}Processing {RESET}%s ' % (count,url))

            try:
                fe = requests.get(url)
            except (requests.exceptions.MissingSchema,requests.exceptions.ConnectionError,requests.exceptions.InvalidURL):
                continue

            new_emails = set(re.findall(r'[a-z0-9\.\-+_]+@[a-z0-9\.\-+_]+\.[a-z]+',fe.text,re.I))	
            emails.update(new_emails)
            
            soup = BeautifulSoup(fe.text,features="lxml")

            for anchor in soup.find_all("a"):
                link = anchor.attrs['href'] if 'href' in anchor.attrs else ''

                if link.startswith('/'):
                    link = base_url + link
                elif not link.startswith('http'):
                    link = path + link
                if not link in urls and not link in scraped_urls:
                    urls.append(link)

    except KeyboardInterrupt:
        print("[!] Interruped \n")


def display_dates(url_target,threads,extensions,size_wordlist):
    # display the target dates on a beautiful way
    print("%s[INFO] Extensions: %s %s %s" % (yellow,white,extensions,white))
    print("%s[INFO] Threads: %s %s %s" % (yellow,white,threads,white))
    print("%s[INFO] Method: %s (GET) %s" % (yellow,green,white))
    print("%s[INFO] Wordlist Size: %s %s" % (yellow,white,size_wordlist))

    print('\n')
    print("%s[INFO]%s Target: %s %s" % (yellow,cyan,white,url_target))
    print('\n')

def main():
    # Main application
    # banner
    banner()

    # V3rD1R default wordlist
    v3rd1r_wordlist = "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt"

    if v3rd1r and not ssl:
        url= f"http://{domain}"
        V3RD1R(url,v3rd1r_wordlist)
    else:
        url=f"https://{domain}"
        V3RD1R(url,v3rd1r_wordlist)

    if FILEDOMAIN:
        print(f"{YELLOW}[*] Scanning/Information from {RESET}{FILEDOMAIN}{YELLOW} Filename{RESET}\n")
        CheckDomainsFromFile(FILEDOMAIN)

    if subbrute:
        # start all of the threads
        #initialize
 
        # create threads
        threads = [Thread(target=searchdomain, args=(domain,domainfile,))]

        # start the threads
        for thread in threads:
            thread.start()

        # wait for the threads to complete
        for thread in threads:
            thread.join()

        end_time = perf_counter()
        # time take it
        print(f'{YELLOW}It took {end_time - start_time: 0.2f} second(s) to complete.{RESET}'+'\n')

        if scan:
            #for d0m4ins in domains:
           d0m3yscanner = D0M3YScan(hostt,modescan)
           d0m3yscanner.dom3y_portscan()

        # in the case of use it find dirs
        if searchdirectory:
            filebrute = BruteDirectory()
            filebrute.banner()

            if findir:
                for d in domains:
                    filebrute.search_directory(d,searchfile,workers)

            elif searchextension:
                 for d in domains:
                 	t1 = Thread(target=filebrute.search_directory_with_extension,args=(d,searchfile,extension,workers,))
                 	t1.start()
                 	t1.join()

        if ssl and searchdirectory:
        	FD = BruteDirectory()
        	if findir:
        		print("\n[*] Finding Directories HTTPS/SSL\n")
        		for ssld in ssldomains:
        			t2 = Thread(target=FD.search_directory,args=(ssld,searchfile,workers,))
        			t2.start()
        			t2.join()

        	elif searchextension:
        		for ssld in ssldomains:
        			t1 = Thread(target=FD.search_directory_with_extension,args=(ssld,searchfile,extension,workers,))
        			t1.start()
        			t1.join()
        elif ssl and scan:
            for ssls in ssldomains:
                d0m3yscanner = D0M3YScan(ssls)
                d0m3yscanner.dom3y_portscan()           


    if engine:
        enginesearch = EngineSearch(domain,workers)

        threads = [Thread(target=enginesearch.find())]

        # start the threads
        for thread in threads:
            thread.start()

        # wait for the threads to complete
        for thread in threads:
            thread.join()


        for SUBSDOMAINS in subdomains:
        	print(f"{GREEN}"+SUBSDOMAINS+f"{RESET}")

        if output:
        	domains.append(subdomains)
        	save_file(output,subdomains)

        	alldomains = open(output,'r')

        	print(f'\n{YELLOW}[*] Checking the lives subdomains found {RESET}\n')

        	for alld in alldomains.readlines():
        		alld = alld.strip()

        		with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        			executor.map(checklivedomains(alld))
        else:
        	print(f'\n{YELLOW}[*] Checking the lives subdomains found {RESET}\n')
        	for sbdo in subdomains:
        		with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        			executor.map(checklivedomains(sbdo))
        if scan:
        	print(f"\n\n{YELLOW}[*] Starting Portscanning...{RESET}")
        	d0m3yscanner = D0M3YScan(domain,modescan)
        	d0m3yscanner.dom3y_portscan()

        # in the case of use it find dirs
        if searchdirectory: 
            lenfile =  os.popen("wc -l {}".format(dirfilename)).readline().split()[0]
            exts = ' '.join(extensions)

            display_dates(domain,workers,exts,lenfile)
            for sb in subdomains:
                v3rd1r = V3RD1R(target,dirfilename)

                word_queue = v3rd1r.build_wordlist(dirfilename)

                for i in range(workers):
                    t = threading.Thread(target=v3rd1r.dir_bruter,args=(word_queue,extensions,))
                    t.start()

    # FOR FFUF
    if FFUF:
        print(f"\n{YELLOW}[!] Using FFUF For Fuzzing Directories ...{RESET}")
        # AGAIN :) The same loop
        for dr in domains_directories:
            # transform to url
            url = 'https://' + dr
            print('\n')
            print(f"{GREEN}[+] Testing on: {RESET}" + url + '\n')
            threads = [Thread(target=ffuf,args=(url,ffufwordlist,workers,))]

            # start the threads
            for thread in threads:
                thread.start()
            # wait for the threads to complete
            for thread in threads:
                thread.join()

    if nmapscanner:
        print('\n\n')
        print(f"{YELLOW}[*] Starting Processing of Scanning with nmap{RESET}")
        # scan all the valid domains found
        for nmapdo in domains_directories:
            print(f'{YELLOW}[*] Scanning: {RESET}' + nmapdo+'\n')
            process = subprocess.Popen(['nmap','-p-','--open','-sS','-vvv','-sV',f'{nmapdo}'],stdout=subprocess.PIPE,
stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            print(stdout.decode())


    if emailscrapper:
        valid_url = 'https://' + domain 
        emails_scrapping(valid_url)
        for mail in emails:
            print(mail) 
    # TECHS ...
    if WT:
        print('\n')
        print(f"{YELLOW}[*] Getting all the Technologies From all Domains{RESET}")
        for DOMAIN in domains_directories:
            url = 'https://' + DOMAIN
            get_techs(url)

    # In case of wanna get all the content 
    if GETCONTENT:
        # later from others valid subdomains found
        # example: www.test.com / wwww.assets.com.ru
        for domainsforgetcontent in domains_directories:
            # we need to transform 
            url_to_test = 'https://' + domainsforgetcontent
            print(f"{YELLOW}[*] Getting On: {url_to_test}{RESET}")
            print('\n')
            _get_files_content(url_to_test)


    """
    FUZZ TESTS FUNCTION HERE
    """
    if pathtrav:
        print(f"\n\n{YELLOW}[*] Testing For Local File Inclusion\n{RESET}")
        print(f"{YELLOW}[+] Target: {URLTARGET}{RESET}")
        time.sleep(2)
        lfi = LFI(URLTARGET)
        lfi.lfi_scan()

    # XSS param don't be based throw
    # of XSS DOM or XSS Reflected
    # inly test if there  are a xss vuln
    if xssvuln:
        xss = XSS(URLTARGET,cookies)
        xss.scan_xss()

    # subdomain takeover scanner
    if subtakeo:
        for subtover in subdomains:
            subjack = subprocess.Popen(["subjack "],stdout=subprocess.PIPE,shell=True)

if __name__ == "__main__":
    main()
