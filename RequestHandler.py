import requests
from MessageHandler import *

class RequestHandler:
    def __init__(self, url, method, args):
        self.__url = url
        self.__method = method
        self.__args = args
        self.__param = {}
        self.__cookie = {}
        self.__delayBetweenRequests = 0
        self.__proxy = {}
        self.__proxyList = []
    
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

    def addParam(self, index, value):
        self.__param[index] = value

    def addProxy(self, proxy):
        self.__proxyList.append(proxy)

    def testConnection(self):
        try:
            self.setParam({self.getArgs()[0]: ''})
            r = requests.get(self.getUrl(), params=self.getParam(), cookies=self.getCookie(), proxies=self.getProxy())
            r.raise_for_status()
            return r
        except Exception as e:
            return None

    def testRedirection(self, request):
        if ('[302]' in str(request.history)):
            if (not mh.askYesNo("You was redirected to another page. Do you want to continue? (y/N): ")):
                exit(0)

    def readProxiesFromFile(self, fileName):
        try:
            file = open(fileName, 'r')
            for line in file:
                line = line.rstrip("\n")
                self.setProxy({
                    'http://': 'http://'+line,
                    'https://': 'http://'+line
                })
                self.testProxy()
        except FileNotFoundError as e:
            mh.errorBox("File '"+fileName+"' not found . . .")

    def testProxy(self):
        if (self.testConnection() != None):
            self.addProxy(self.getProxy())

    def setProxyByRequestIndex(self, i):
        proxyList = self.getProxyList()
        self.setProxy(proxyList[int(i/10)%len(proxyList)])

    def start(self, fileName, proxiesFileName):
        try:
            file = open(fileName, 'r')
        except FileNotFoundError as e:
            exit("File '"+fileName+"' not found . . .")
        hasProxies = False
        if (proxiesFileName != ""):
            hasProxies = True
            self.readProxiesFromFile(proxiesFileName)
        requestAux = self.testConnection()
        if (requestAux != None):
            mh.infoBox("Connection estabilished")
        else:
            mh.errorBox("Failed to connect to the server.")
        self.testRedirection(requestAux)
        mh.infoBox("Starting test on '"+self.getUrl()+"' ...")
        mh.getHeader()
        i = 0
        firstRequestTime = requestAux.elapsed.total_seconds()
        firstRequestLength = requestAux.headers.get('content-length')
        mh.printContent([i, '', requestAux.status_code, firstRequestLength, firstRequestTime])
        for line in file:
            if (hasProxies and i%10 == 0):
                self.setProxyByRequestIndex(i)
            i += 1
            line = line.rstrip("\n")
            self.setParam({})
            for arg in self.getArgs():
                self.addParam(arg, line)
            if (self.getMethod() == 'GET'):
                r = requests.get(self.getUrl(), params=self.getParam(), cookies=self.getCookie(), proxies=self.getProxy())
            requestTime = r.elapsed.total_seconds()
            requestLength = r.headers.get('content-length')
            #if (requestTime > 1):
            mh.printContent([i, mh.fixLineToOutput(line), r.status_code, requestLength, requestTime])
        mh.getInitOrEnd()