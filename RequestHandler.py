import requests
import time
from OutputHandler import *

class RequestHandler:
    def __init__(self, url, method, args, defaultParam):
        self.__url = url
        self.__method = method
        self.__args = args
        self.__param = defaultParam
        self.__cookie = {}
        self.__delayBetweenRequests = 0
        self.__proxy = {}
        self.__proxyList = []
        self.__delay = 0
    
    def getUrl(self):
        return self.__url
    
    def getMethod(self):
        return self.__method

    def getArgs(self):
        return self.__args

    def getParam(self):
        return self.__param
    
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
    
    def setArgs(self, args):
        self.__args = args

    def setParam(self, param):
        self.__param = param
    
    def setCookie(self, cookie):
        self.__cookie = cookie
    
    def setProxy(self, proxy):
        self.__proxy = proxy

    def setProxyList(self, proxyList):
        self.__proxyList = proxyList

    def setDelay(self, delay):
        self.__delay = delay

    def addParam(self, index, value):
        self.__param[index] = value

    def addProxy(self, proxy):
        self.__proxyList.append(proxy)

    def testConnection(self):
        try:
            r = requests.get(self.getUrl(), cookies=self.getCookie(), proxies=self.getProxy())
            r.raise_for_status()
            return r
        except Exception as e:
            return None

    def testRedirection(self):
        request = requests.get(self.getUrl(), params=self.getParam(), cookies=self.getCookie(), proxies=self.getProxy())
        if ('[302]' in str(request.history)):
            if (not oh.askYesNo("You was redirected to another page. Do you want to continue? (y/N): ")):
                exit(0)

    def readProxiesFromFile(self, file):
        for line in file:
            line = line.rstrip("\n")
            self.setProxy({
                'http://': 'http://'+line,
                'https://': 'http://'+line
            })
            self.testProxy()

    def testProxy(self):
        if (self.testConnection() != None):
            self.addProxy(self.getProxy())

    def setProxyByRequestIndex(self, i):
        proxyList = self.getProxyList()
        self.setProxy(proxyList[int(i/10)%len(proxyList)])

    def fuzzyingFromFile(self, requestsFile, hasProxies):
        oh.getHeader()
        i = 0
        requestAux = requests.get(self.getUrl(), params=self.getParam(), cookies=self.getCookie(), proxies=self.getProxy())
        firstRequestTime = requestAux.elapsed.total_seconds()
        firstRequestLength = requestAux.headers.get('content-length')
        oh.printContent([i, self.getParam()[self.getArgs()[0]], requestAux.status_code, firstRequestLength, firstRequestTime], False)
        for line in requestsFile:
            if (hasProxies and i%10 == 0):
                self.setProxyByRequestIndex(i)
            i += 1
            line = line.rstrip("\n")
            self.setParam({arg: line for arg in self.getArgs()})
            if (self.getMethod() == 'GET'):
                r = requests.get(self.getUrl(), params=self.getParam(), cookies=self.getCookie(), proxies=self.getProxy())
            else:
                r = requests.post(self.getUrl(), data=self.getParam(), cookies=self.getCookie(), proxies=self.getProxy())
            requestTime = r.elapsed.total_seconds()
            requestLength = r.headers.get('content-length')
            probablyVulnerable = False
            if (requestTime > (firstRequestTime+1)):
                probablyVulnerable = True
            oh.printContent([i, oh.fixLineToOutput(line), r.status_code, requestLength, requestTime], probablyVulnerable)
            time.sleep(self.getDelay())
        oh.getHeader()
        requestsFile.close()

    def start(self, requestsFile, proxiesFile):
        hasProxies = False
        if (proxiesFile != None):
            hasProxies = True
            self.readProxiesFromFile(proxiesFile)
            proxiesFile.close()
        if (self.testConnection() != None):
            oh.infoBox("Connection estabilished.")
        else:
            oh.errorBox("Failed to connect to the server.")
        self.testRedirection()
        oh.infoBox("Starting test on '"+self.getUrl()+"' ...")
        self.fuzzyingFromFile(requestsFile, hasProxies)
        oh.infoBox("Test completed.")