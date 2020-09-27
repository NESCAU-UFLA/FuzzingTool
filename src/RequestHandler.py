import requests
import time
import datetime
from OutputHandler import *
import settings
import os

def getRequestTimeAndLength(request):
    return (request.elapsed.total_seconds(), request.headers.get('content-length'))

class RequestHandler:
    def __init__(self, url, method, defaultParam):
        self.__url = url
        self.__method = method
        self.__param = defaultParam
        self.__defaultParam = defaultParam
        self.__cookie = {}
        self.__delayBetweenRequests = 0
        self.__proxy = {}
        self.__proxyList = []
        self.__delay = 0
    
    def getUrl(self):
        return self.__url
    
    def getMethod(self):
        return self.__method

    def getParam(self):
        return self.__param
    
    def getDefaultParam(self):
        return self.__defaultParam

    def getCookie(self):
        return self.__cookie
    
    def getProxy(self):
        return self.__proxy

    def getProxyList(self):
        return self.__proxyList

    def getDelay(self):
        return self.__delay

    def setUrl(self, url):
        self.__url = url
    
    def setParam(self, param):
        self.__param = param
    
    def setDefaultParam(self, defaultParam):
        self.__defaultParam = defaultParam

    def setCookie(self, cookie):
        self.__cookie = cookie
    
    def setProxy(self, proxy):
        self.__proxy = proxy

    def setProxyList(self, proxyList):
        self.__proxyList = proxyList

    def setDelay(self, delay):
        self.__delay = delay

    def addProxy(self, proxy):
        self.__proxyList.append(proxy)

    def testConnection(self):
        try:
            r = requests.get(self.getUrl(), cookies=self.getCookie(), proxies=self.getProxy())
            r.raise_for_status()
            return r
        except Exception as e:
            return None

    def getPreparedRequest(self, paramValue):
        self.setParam({})
        for key, value in self.getDefaultParam().items():
            if (value != ''):
                self.getParam()[key] = value
            else:
                self.getParam()[key] = paramValue
        if (self.getMethod() == 'GET'):
            return requests.get(self.getUrl(), params=self.getParam(), cookies=self.getCookie(), proxies=self.getProxy())
        else:
            return requests.post(self.getUrl(), data=self.getParam(), cookies=self.getCookie(), proxies=self.getProxy())

    def testRedirection(self):
        request = self.getPreparedRequest(' ')
        if ('[302]' in str(request.history)):
            if (not oh.askYesNo("You was redirected to another page. Do you want to continue? (y/N): ")):
                exit(0)
        else:
            oh.infoBox("No redirections.")

    def readProxiesFromFile(self):
        for line in settings.proxiesFile:
            line = line.rstrip("\n")
            self.setProxy({
                'http://': 'http://'+line,
                'https://': 'http://'+line
            })
            self.testProxy()
        settings.proxiesFile.close()

    def testProxy(self):
        if (self.testConnection() != None):
            self.addProxy(self.getProxy())

    def setProxyByRequestIndex(self, i):
        proxyList = self.getProxyList()
        self.setProxy(proxyList[int(i/10)%len(proxyList)])

    def fuzzyingFromFile(self, hasProxies):
        numLines = sum(1 for line in settings.wordlistFile)
        settings.wordlistFile.seek(0)
        firstRequest = self.getPreparedRequest(' ')
        firstRequestTime, firstRequestLength = getRequestTimeAndLength(firstRequest)
        i = 0
        t = datetime.datetime.now()
        try:
            outputFile = open('../output/'+str(t.year)+'-'+str(t.month)+'-'+str(t.day)+'_'+str(t.hour)+':'+str(t.minute)+'.txt', 'w')
        except FileNotFoundError as e:
            os.system('mkdir ../output')
            outputFile = open('../output/'+str(t.year)+'-'+str(t.month)+'-'+str(t.day)+'_'+str(t.hour)+':'+str(t.minute)+'.txt', 'w')
        if (settings.verboseMode):
            oh.getHeader()
            oh.printContent([i, '', firstRequest.status_code, firstRequestLength, firstRequestTime], False)
        for line in settings.wordlistFile:
            line = line.rstrip("\n")
            if (hasProxies and i%10 == 0):
                self.setProxyByRequestIndex(i)
            i += 1
            r = self.getPreparedRequest(line)
            requestTime, requestLength = getRequestTimeAndLength(r)
            status = r.status_code
            probablyVulnerable = False
            if (int(requestLength) > (int(firstRequestLength)+settings.additionalLength) or requestTime > (firstRequestTime+settings.additionalTime)):
                probablyVulnerable = True
                writeOnFile(outputFile, i, line, status, requestLength, requestTime)
            if (settings.verboseMode):
                oh.printContent([i, oh.fixLineToOutput(line), status, requestLength, requestTime], probablyVulnerable)
            else:
                oh.progressStatus(str(int((i/numLines)*100)))
            time.sleep(self.getDelay())
        settings.wordlistFile.close()
        outputFile.close()
        if (settings.verboseMode):
            oh.getHeader()
        else:
            print("")

    def start(self):
        hasProxies = False
        if (settings.proxiesFile != None):
            hasProxies = True
            self.readProxiesFromFile()
        if (self.testConnection() != None):
            oh.infoBox("Connection status: OK")
        else:
            oh.errorBox("Failed to connect to the server.")
        oh.infoBox("Testing redirections ...")
        self.testRedirection()
        oh.infoBox("Starting test on '"+self.getUrl()+"' ...")
        self.fuzzyingFromFile(hasProxies)
        oh.infoBox("Test completed.")