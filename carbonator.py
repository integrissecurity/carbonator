# Created by Blake Cornell, CTO, Integris Security LLC
# Integris Security Carbonator - Beta Version - v0.1
# Released under GPL Version 2 license.
#
# See the INSTALL file for installation instructions.
# 
# For more information contact us at carbonator at integrissecurity dot com
# Or visit us at https://www.integrissecurity.com/
from burp import IBurpExtender
from burp import IHttpListener
from burp import IScannerListener
from java.net import URL
from java.io import File
import time

class BurpExtender(IBurpExtender, IHttpListener, IScannerListener):
    def registerExtenderCallbacks(self, callbacks):
	self._callbacks = callbacks
	self._callbacks.setExtensionName("Integris Security Carbonator")
	self._helpers = self._callbacks.getHelpers()
	self.clivars = None

	self.spider_results=[]
	self.scanner_results=[]
	self.packet_timeout=5

	self.last_packet_seen= int(time.time()) #initialize the start of the spider/scan

	if not self.processCLI():
		return None
	else:
		self.clivars = True

	print "Initiating Carbonator Against: ", str(self.url)
	#add to scope if not already in there.
	if self._callbacks.isInScope(self.url) == 0:
		self._callbacks.includeInScope(self.url)

	self._callbacks.sendToSpider(self.url)
	self._callbacks.registerHttpListener(self)
	self._callbacks.registerScannerListener(self)

	while int(time.time())-self.last_packet_seen <= self.packet_timeout:
		time.sleep(1)
	print "No packets seen in the last ", self.packet_timeout, " seconds."
	print "Removing Listeners"
	self._callbacks.removeHttpListener(self)
	self._callbacks.removeScannerListener(self)
	self._callbacks.excludeFromScope(self.url)

	print "Generating Report"
	self.generateReport('HTML')
	print "Report Generated"
	print "Closing Burp in ", self.packet_timeout, " seconds."
	time.sleep(self.packet_timeout)

	if self.clivars:
		self._callbacks.exitSuite(False)
		
	return

    def processHttpMessage(self, tool_flag, isRequest, current):
	self.last_packet_seen = int(time.time())
	if tool_flag == self._callbacks.TOOL_SPIDER and isRequest: #if is a spider request then send to scanner
		self.spider_results.append(current)
		print "Sending new URL to Vulnerability Scanner: URL #",len(self.spider_results)
		if self.scheme == 'https':
			self._callbacks.doActiveScan(self.fqdn,self.port,1,current.getRequest()) #returns scan queue, push to array
		else:
			self._callbacks.doActiveScan(self.fqdn,self.port,0,current.getRequest()) #returns scan queue, push to array
	return

    def newScanIssue(self, issue):
	self.scanner_results.append(issue)
	print "New issue identified: Issue #",len(self.scanner_results);
	return

    def generateReport(self, format):
	if format != 'XML':
		format = 'HTML'	
	self._callbacks.generateScanReport(format,self.scanner_results,File('IntegrisSecurity_Carbonator_'+self.scheme+'_'+self.fqdn+'_'+str(self.port)+'.'+format.lower()))
	return

    def processCLI(self):
	cli = self._callbacks.getCommandLineArguments()
	if len(cli) < 0:
		print "Incomplete target information provided."
		return False
	elif cli[0] == 'https' or cli[0] == 'http': #cli[0]=scheme,cli[1]=fqdn,cli[2]=port
		self.scheme = cli[0]
		self.fqdn = cli[1]
		self.port = int(cli[2])
		if len(cli) == 3:
			self.path = '/'
		elif len(cli) == 4:
			self.path = cli[3]
		else:
			print "Unknown number of CLI arguments"
			return False
		self.url = URL(self.scheme,self.fqdn,self.port,self.path)
	else:
		print "Invalid command line arguments supplied"
		return False
	return True
