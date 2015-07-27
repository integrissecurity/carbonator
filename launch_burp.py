import argparse
import urllib2, socket,sys,base64,os
from xml.dom.minidom import parse, parseString
import socket
from google import search
from urlparse import urlparse
import os.path

# Initially written by milo2010 @ https://github.com/milo2012/carbonator/
# To install the google api library execute the following commandi as root
#	wget http://winappdbg.sourceforge.net/blog/google-1.06.tar.gz && tar -xf google-1.06.tar.gz && cd google-1.06 && python setup.py install
bingAPIKey = ''

#lets find the latest version of burp.
burp_paths = ['/usr/bin/',
	'/pentest/burp/',
	'./',
	'../burp_suite/',
	'../burp/',
	'../']

burp_filenames = [
	'burp',
	'burpsuite',
	'burpsuite_pro_v1.6.',
	'burpsuite_pro_v1.7.']

burpPath = ''
for test_path in reversed(burp_paths):
	for test_filename in reversed(burp_filenames): #run through path hunt list in reverse from newest version to oldest
		for version_guess in range(0,100):
			#print test_path + test_filename + str(version_guess) + ".jar"
			if os.path.isfile(test_path + test_filename + str(version_guess) + ".jar"):
				burpPath = test_path + test_filename + str(version_guess) + ".jar"
				print "Found Burp Suite Pro JAR file."
				break

		if len(burpPath) > 0: #double break out of nested for loops
			break
	if len(burpPath) > 0: #double break out of nested for loops
		break

if not os.path.isfile(burpPath):
	print "Could not find the Burp Suite Pro JAR file. Please update source."
	sys.exit(1)

runHeadless = False

def isOpen(ip,port):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    	try:
     		s.connect((ip, int(port)))
     		s.shutdown(2)
     		return True
    	except:
     		return False

def removeFile():
	try:
		os.remove('links.txt')
	except OSError:
		pass

def getIP(domain):
    return socket.gethostbyname(domain)

def getGoogleResults(domain):
    print "Google: "+str(domain)
    urls = []
    for url in search('site:'+domain, stop=50):
       urls.append(url)
    f = open('links.txt', 'w')
    for item in urls:
  	f.write("%s\n" % item)
    f.close()
    return urls

def reverseBing(ip):
    print "Bing: "+str(ip)
    sites = []
    skip = 0
    top = 50

    while skip < 200:
          url = "https://api.datamarket.azure.com/Data.ashx/Bing/Search/v1/Web?Query='ip:%s'&$top=%s&$skip=%s&$format=Atom"%(ip,top,skip)
          request = urllib2.Request(url)
          auth = base64.encodestring("%s:%s" % (bingAPIKey, bingAPIKey)).replace("\n", "")
          request.add_header("Authorization", "Basic %s" % auth)
          try:
          	res = urllib2.urlopen(request)
          except urllib2.HTTPError as e:
		print "Bing authentication failed. Please check your API key: "+str(e)
		sys.exit(1)

          data = res.read()

          xmldoc = parseString(data)
          site_list = xmldoc.getElementsByTagName('d:Url')
          for site in site_list:
              domain = site.childNodes[0].nodeValue
              domain = domain.split("/")[2]
              if domain not in sites:
                 sites.append(domain)

          skip += 50

    print "Total domains found: %s \n" %(len(sites))
    for site in sites:
        print site
    return sites	

def runBurp(url):
	print url
	if "http" not in url and "https" not in url:
		if isOpen(url,80):
			url = "http://"+url
		else:
			url = "https://"+url
	if runHeadless==True:
		cmd = 'java -jar -Xmx2048m -Djava.awt.headless=true '+burpPath+' '+url
	else:	
		cmd = 'java -jar -Xmx2048m '+burpPath+' '+url
	print cmd
	os.system(cmd)

parser = argparse.ArgumentParser(description='Burp automator')
parser.add_argument('-host', help='Enter an IP address or Domain name')
parser.add_argument('-saveState', action='store_true', help='Save Burpsuite State')
parser.add_argument('-enableBing', action='store_true', help='Enable Bing Reverse IP')
parser.add_argument('-enableGoogle', action='store_true', help='Enable Google Search')
parser.add_argument('-file',  help='File containing Domain names or IP addresses')
parser.add_argument('-headless', action='store_true', help='Run Burp headless')
args = parser.parse_args()
if args.host==None and args.file==None:
	print "\n[!] Please run 'python2.7 launch_burp.py -h'\n"
	sys.exit()
else:
	if args.headless:
		#global runHeadless
		runHeadless=True	
	if args.file:
	        if os.path.exists(args.file):
                	try:
                       		with open(args.file) as f:
                       	        	 for line in f:
                                        	host = line.strip("\n")
						tmpHost = host
                        			if "http" in host or "https" in tmpHost:
							parse_object = urlparse(tmpHost)
	        					fqdn = str(parse_object.hostname)
							tmpHost = fqdn
						if any(c.isalpha() for c in tmpHost)==False:
							if args.enableBing==True:
								if len(bingAPIKey)<1:
									sys.exit("[!] Please check your bingAPIKey !")
								sites = reverseBing(tmpHost)
								for site in sites:
									if args.saveState:
										site+=' save'
									if args.enableGoogle:
										getGoogleResults(site)
									else:
										removeFile()
									runBurp(site)
							else:
								site = tmpHost
								if args.saveState:
									site+=' save'
								if args.enableGoogle:
									getGoogleResults(site)
								else:
									removeFile()		

								runBurp(host)

						else:
							if args.enableBing==True:
								ip = getIP(tmpHost)
								sites = reverseBing(ip)
								for site in sites:
									ipSite = getIP(site)
									if ip==ipSite:
										if args.saveState:
											site+=' save'
										if args.enableGoogle:
											getGoogleResults(site)
										else:
											removeFile()
										runBurp(site)
							else:
								site = host
								if args.saveState:
									site+=' save'
								if args.enableGoogle:
									getGoogleResults(site)
								else:
									removeFile()
								runBurp(site)
			except:
				pass
		else:
			print "\n[!] Please check your input filename.\n"
		sys.exit()

	host = args.host
	print "Setting Target: " + host
    	if "http" in host or "https" in host:
		parse_object = urlparse(host)
		fqdn = str(parse_object.hostname)
		host = fqdn
	if any(c.isalpha() for c in host)==False:
		if args.enableBing==True:
			if len(bingAPIKey)<1:
				sys.exit("[!] Please check your bingAPIKey !")
			sites = reverseBing(host)
			for site in sites:
				if args.saveState:
					site+=' save'
				if args.enableGoogle:
					getGoogleResults(site)
				else:
					removeFile()
				runBurp(site)
		else:
			site = host
			if args.saveState:
				site+=' save'
			if args.enableGoogle:
				getGoogleResults(site)
			else:
				removeFile()		
			runBurp(args.host)

	else:
		if args.enableBing==True:
			ip = getIP(host)
			sites = reverseBing(ip)
			for site in sites:
				ipSite = getIP(site)
				if ip==ipSite:
					if args.saveState:
						site+=' save'
					if args.enableGoogle:
						getGoogleResults(site)
					else:
						removeFile()
					runBurp(site)
		else:
			site = host
			if args.saveState:
				site+=' save'
			if args.enableGoogle:
				getGoogleResults(site)
			else:
				removeFile()
			runBurp(site)
