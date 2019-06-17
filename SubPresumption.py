#!/usr/bin/python3

import requests
from urllib.parse import urlparse
from threading import Thread
import urllib.request, urllib.error, urllib.parse
import sys
from queue import Queue
from blessings import Terminal
import dns.resolver
import re
import os

t = Terminal()
concurrent = 200

def doWork():
    t = Terminal()
    while True:
        netloc = q.get()
        url = "http://"+netloc
        status, url = getStatus(url)
        if status == 404:
            c_name = cname(netloc)
            print("------------------------------------------------------")
            doSomethingWithResult(status,url)
            print(t.bold_bright_cyan("[+] Check takeover posibility for "+ netloc+" using CNAME:  " + str(c_name)))
            
            print("------------------------------------------------------")
        else:
           doSomethingWithResult(status, url)
        q.task_done()
        
def getStatus(ourl):
    try:
        headers ={ "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:56.0) Gecko/20100101 Firefox/56.0" }
        res = requests.get(ourl, headers= headers)
        return res.status_code, ourl
    except:
        return "error", ourl
def cname(c_url):
    t = Terminal()
    try:
       result = dns.resolver.query(c_url, 'CNAME')
       for cnameval in result:
          return ' cname of '+ c_url+ ' address:', cnameval.target
    except Exception as error2:
        print("---------------------------------------------------")
        print(t.bold_bright_red("[+] "+ str(error2)))
        print("---------------------------------------------------")


print(t.bold_bright_green("""
====================================================================================

/ ___| _   _| |__ |  _ \ _ __ ___  ___ _   _ _ __ ___  _ __ | |_(_) ___  _ __  
\___ \| | | | '_ \| |_) | '__/ _ \/ __| | | | '_ ` _ \| '_ \| __| |/ _ \| '_ \ 
 ___) | |_| | |_) |  __/| | |  __/\__ \ |_| | | | | | | |_) | |_| | (_) | | | |
|____/ \__,_|_.__/|_|   |_|  \___||___/\__,_|_| |_| |_| .__/ \__|_|\___/|_| |_| V_1.0
                                                      |_|                                            
====================================================================================
"""))
print(t.bold_bright_green("Sub Presumption By @Manikanta - http://www.example.com/\nSpecially created for Bug Bounty Hunting!\n\n"))

def doSomethingWithResult(status, url):
    t = Terminal()
    if status == 200:
       print(t.bold_bright_white("[+] "+str(status)+ "    "+url))
    else:
       print(t.bold_bright_red("[+] "+str(status)+ "    "+url))

def parser_error(errmsg):
    '''
    Error Messages
    '''
    print(("Welcome: %s" % errmsg ))
    print("Usage: SubPresumption.py [argument] [Textfile]  Text file contains subdomains")
    print("       SubPresumption.py [argument] [hostname]   Target hostname (By default tool gets the subdomains from virus-total API)\n")
    print("Arguments\n     -d        Supply Target main Domain\n     -l        Supply Textfile as input\n") 
    print(("Usage: python %s -d example.com" % sys.argv[0]))
    print(("       python %s -l subdomains.txt" % sys.argv[0]))
    sys.exit()

def userHelpText(arg): 
     r = "(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{0,62}[a-zA-Z0-9]\.)+[a-zA-Z]{2,63}$)"
     if re.match(r, arg):
        getSubdomain(arg)
     else:
        msg = "User Help Text"
        parser_error(msg)
       

q = Queue(concurrent * 2)
for i in range(concurrent):
    t = Thread(target=doWork)
    t.daemon = True
    t.start()

# The code snippet is get the subdomains from the virustotal api
def getSubdomain(arg):
    hostname = arg
    apikey = os.environ.get('VIRUS_TOTAL_API_KEY')
    url = 'https://www.virustotal.com/vtapi/v2/domain/report'
    params = {'apikey': apikey, 'domain': hostname }
    response = requests.get(url, params=params)
    data = response.json()

    try:
        sub1 = data["subdomains"]
    except:
        sub1 = []

    sub2 = data["domain_siblings"]

    t = Terminal()

    subdomains = sub1 + sub2
    print(t.bold_bright_green("********************Subdomains of " + hostname+"************************"))
    print(t.bold_bright_green("----------------------------------------------------------------------\n"))
    for i in subdomains:
        print(t.bold_bright_blue("[+]  "+ i))

    print(t.bold_bright_green("********************Subdomains health map*******************************"))
    print(t.bold_bright_green("-----------------------------------------------------------------------\n"))
    try:
        for url in subdomains:
            q.put(url.strip())
        q.join()
    except KeyboardInterrupt:
         sys.exit()

def getDomainlist(domains):
    try:
       for url in open(domains,'r'):
          q.put(url.strip())
       q.join()
    except KeyboardInterrupt:
        userHelpText(sys.argv[1])
try:
   if os.environ.get('VIRUS_TOTAL_API_KEY') == None:
      print("Virus total api key is not found\n")
      print("Please configure VIRUS_TOTAL_API_KEY variable")
   elif sys.argv[1] == "-d":
      user_arg = sys.argv[2]
      userHelpText(user_arg)
   elif sys.argv[1] == "-l":
      getDomainlist(sys.argv[2])
   elif sys.argv[1] == "-h":
      userHelpText(sys.argv[1])
   else:
      userHelpText(sys.argv[1])
except KeyboardInterrupt:
      userHelpText(sys.argv[0])
