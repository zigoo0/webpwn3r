#!/usr/bin/env python
# WebPwn3r is a Web Applications Security Scanner
# By Ebrahim Hegazy - twitter.com/zigoo0
# First demo conducted 12Apr-2014 @OWASP Chapter Egypt
# https://www.owasp.org/index.php/Cairo
import re
import urllib
from headers import *
from vulnz import *

print ga.green+'''
	    __          __  _     _____                 ____       
	    \ \        / / | |   |  __ \               |___ \      
	     \ \  /\  / /__| |__ | |__) |_      ___ __   __) |_ __ 
	      \ \/  \/ / _ \ '_ \|  ___/\ \ /\ / / '_ \ |__ <| '__|
 	       \  /\  /  __/ |_) | |     \ V  V /| | | |___) | |   
 	        \/  \/ \___|_.__/|_|      \_/\_/ |_| |_|____/|_|   
                                                    
        ##############################################################
        #| "WebPwn3r" Web Applications Security Scanner   [Demo]     #
        #|  By Ebrahim Hegazy - @Zigoo0                              #
        #|  This Version Supports Remote Code/Command Execution, XSS #
	#|  Thanks @lnxg33k, @dia2diab @Aelhemily, @okamalo          #
        ##############################################################
        '''+ga.end

def urls_or_list():
	url_or_list = raw_input(" [!] Scan URL or List? [1/2]: ")
	if url_or_list == "1":
	 	 url = raw_input( ga.green+" [!] Enter the URL: "+ga.end)
		 if not url.startswith("http://"):
                     print ga.red+'''\n Invalid URL, Please Make Sure That The URL Starts With \"http://\" \n'''+ga.end
                     exit()
                 else:
                     try:
                         for params in url.split("?")[1].split("&"):
                             params.split("=")[1]
		     except IndexError:
                         print ga.red+'''\n Invalid URL, Please Enter a Valid URL With Valid Params '''+ga.end
                         print ga.blue+''' i.e http://www.site.com/page.php?key=value \n'''+ga.end
                         exit()
		 rce_func(url)
		 xss_func(url)
	if url_or_list =="2":
		 urls_list = raw_input( ga.green+" [!] Enter the list file name .e.g [list.txt]: "+ga.end)
		 open_list = open(urls_list).readlines()
		 for line in open_list:
			 links = line.strip()
		  	 url = links
		  	 print ga.green+" \n [!] Now Scanning %s"%url +ga.end
		  	 rce_func(url)
			 xss_func(url)
urls_or_list()
