#!/usr/bin/env python
# WebPwn3r is a Web Applications Security Scanner
# By Ebrahim Hegazy - twitter.com/zigoo0
# First demo conducted 12Apr-2014 @OWASP Chapter Egypt
# https://www.owasp.org/index.php/Cairo
try:
	import readline
except ImportError:
	pass
import re
import urllib
from headers import *
from vulnz import *
import re
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
	#|  More Details: http://www.sec-down.com/wordpress/?p=373   #
        ##############################################################
        '''+ga.end

def urls_or_list():
	url_or_list = raw_input(" [!] Scan URL or List of URLs? [1/2]: ")
	if url_or_list == "1":
	 	 url = raw_input(" [!] enter the url (e.g. http://localhost/index.php?id=1): ")
		 while not re.match("^(http|https)://\S*\w+\?\S*=", url):
		     #Thanks to Nu11 for the HTTP checker
		     print ga.red +"\n [Warning] "+ ga.end + ga.bold+"%s"%url +ga.end + ga.red +" is not a valid URL"+ga.end			
		     print ga.red +" [Warning] You should write a Full URL .e.g http://site.com/page.php?id=value \n"+ ga.end
                     #print ga.red+'''\n Invalid URL, Please Make Sure That The URL Starts With \"http://\" \n'''+ga.end
	 	     url = raw_input(" [!] enter the url: ")
                     #exit()
		 if "?" in url:
		 	rce_func(url)
		 	xss_func(url)		 
	if url_or_list =="2":
		 urls_list = raw_input( ga.green+" [!] Enter the list file name .e.g [list.txt]: "+ga.end)
		 open_list = open(urls_list).readlines()
		 for line in open_list:
			 if "?" in line:
			 	links = line.strip()
		  	 	url = links
		  	 	print ga.green+" \n [!] Now Scanning %s"%url +ga.end
		  	 	rce_func(url)
			 	xss_func(url)
			 else:
			 	links = line.strip()
		  	 	url = links
				print ga.red +"\n [Warning] "+ ga.end + ga.bold+"%s"%url +ga.end + ga.red +" is not a valid URL"+ga.end				
				print ga.red +" [Warning] You should write a Full URL .e.g http://site.com/page.php?id=value \n"+ ga.end
		 exit()				

urls_or_list()





