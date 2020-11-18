import requests
import time
from datetime import datetime
from OutputHandler import *
import settings
import os

class RequestHandler:
    """Class that handle with the requests
    
    Attributes:
        url: The target URL
        method: The request method (POST or GET)
        param: The parameter of the request
        defaultParam: The dictionary with request parameters and default values
        cookie: The HTTP Cookie header value
        proxy: The proxy used in the request
        proxyList: The list with valid proxies gived by a file
        delay: The delay time between each request
    """
    def __init__(self, url: str, method: str, defaultParam: dict):
        """Class constructor

        @type url: str
        @param url: The target URL
        @type method: str
        @param method: The request method
        @type defaultParam: dict
        @param defaultParam: The parameters of the request, with default values if is given
        """
        self.__url = url
        self.__method = method
        self.__param = defaultParam
        self.__defaultParam = defaultParam
        self.__cookie = {}
        self.__proxy = {}
        self.__proxyList = []
        self.__delay = 0
    
    def getUrl(self):
        """The url getter

        @returns str: The target URL
        """
        return self.__url

    def getMethod(self):
        """The method getter

        @returns str: The param method
        """
        return self.__method

    def getParam(self):
        """The param getter

        @returns dict: The parameters of the request
        """
        return self.__param
    
    def getDefaultParam(self):
        """The defaultParam getter

        @returns dict: The default parameters of the request
        """
        return self.__defaultParam

    def getCookie(self):
        """The cookie getter

        @returns dict: The HTTP Cookie header value
        """
        return self.__cookie
    
    def getProxy(self):
        """The proxy getter

        @returns dict: The proxy used in the request
        """
        return self.__proxy

    def getProxyList(self):
        """The proxyList getter

        @returns list: The proxies list
        """
        return self.__proxyList

    def getDelay(self):
        """The delay getter

        @returns float: The delay used between each request
        """
        return self.__delay

    def setUrl(self, url: str):
        """The url setter

        @param type: str
        @param url: The target URL
        """
        self.__url = url
    
    def setParam(self, param: dict):
        """The param setter

        @param type: dict
        @param param: The parameter of the request
        """
        self.__param = param
    
    def setDefaultParam(self, defaultParam: dict):
        """The defaultParam setter

        @param type: dict
        @param defaultParam: The default parameter of the request
        """
        self.__defaultParam = defaultParam

    def setCookie(self, cookie: dict):
        """The cookie setter

        @param type: dict
        @param cookie: The HTTP Cookie header value
        """
        self.__cookie = cookie
    
    def setProxy(self, proxy: dict):
        """The proxy setter

        @param type: dict
        @param proxy: The proxy used in the request
        """
        self.__proxy = proxy

    def setProxyList(self, proxyList: list):
        """The proxyList setter

        @param type: list
        @param proxyList: The proxies list
        """
        self.__proxyList = proxyList

    def setDelay(self, delay: float):
        """The delay setter

        @param type: float
        @param delay: The delay used between each request
        """
        self.__delay = delay

    def __testConnection(self):
        """Test the connection with the target, and returns the request obj

        @returns object: The request object
        """
        try:
            r = requests.get(self.getUrl(), cookies=self.getCookie(), proxies=self.getProxy())
            r.raise_for_status()
            return r
        except Exception:
            return None

    def __getPreparedRequest(self, paramValue: str):
        """Get the prepared request with a custom parameter

        @param type: str
        @param paramValue: The value used in the parameter of the request
        @returns object: The prepared request with a custom parameter
        """
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

    def __testRedirection(self):
        """Test if the connection will has a redirection"""
        request = self.__getPreparedRequest(' ')
        if ('[302]' in str(request.history)):
            if (not oh.askYesNo("You was redirected to another page. Continue? (y/N): ")):
                exit(0)
        else:
            oh.infoBox("No redirections.")

    def __readProxiesFromFile(self):
        """Read the proxies from a file"""
        for line in settings.proxiesFile:
            line = line.rstrip("\n")
            self.setProxy({
                'http://': 'http://'+line,
                'https://': 'http://'+line
            })
            self.__testProxy()
        settings.proxiesFile.close()

    def __testProxy(self):
        """Test if the proxy can be used on the connection, and insert it into the proxies list"""
        if (self.__testConnection() != None):
            self.__proxyList.append(self.getProxy())

    def __setProxyByRequestIndex(self, i: int):
        """Set the proxy based on request index

        @param type: int
        @param i: The request index
        """
        proxyList = self.getProxyList()
        self.setProxy(proxyList[int(i/10)%len(proxyList)])

    def __getRequestTimeAndLength(self, request: object):
        """Get the request time and length

        @type request: object
        @param request: The request
        @rtype: tuple(float, int)
        @returns (requestTime, requestLength): The request time and length
        """
        return (request.elapsed.total_seconds(), request.headers.get('content-length'))

    def __makeOutputFile(self):
        """Makes the output file with the probably vulnerable response data

        @returns object: The output file
        """
        t = datetime.now()
        try:
            outputFile = open('../output/'+str(t.year)+'-'+str(t.month)+'-'+str(t.day)+'_'+str(t.hour)+':'+str(t.minute)+'.txt', 'w')
        except FileNotFoundError:
            os.system('mkdir ../output')
            outputFile = open('../output/'+str(t.year)+'-'+str(t.month)+'-'+str(t.day)+'_'+str(t.hour)+':'+str(t.minute)+'.txt', 'w')
        return outputFile

    def __fuzzy(self, hasProxies: bool):
        """Make the fuzzy

        @param type: bool
        @param hasProxies: Case will use proxies from a list
        """
        firstRequest = self.__getPreparedRequest(' ')
        firstRequestTime, firstRequestLength = self.__getRequestTimeAndLength(firstRequest)
        i = 0 # The request index
        outputFile = self.__makeOutputFile()
        if (settings.verboseMode):
            oh.getHeader()
            oh.printContent([i, '', firstRequest.status_code, firstRequestLength, firstRequestTime], False)
        else:
            numLines = sum(1 for line in settings.wordlistFile)
            settings.wordlistFile.seek(0)
        for line in settings.wordlistFile:
            line = line.rstrip("\n")
            if (hasProxies and i%10 == 0):
                self.__setProxyByRequestIndex(i)
            i += 1
            r = self.__getPreparedRequest(line)
            requestTime, requestLength = self.__getRequestTimeAndLength(r)
            requestStatus = str(r.status_code)
            probablyVulnerable = False
            # If the request content has some predefined characteristics (settings.py) based on a parameter, it'll be considered as vulnerable
            if (int(requestLength) > (int(firstRequestLength)+settings.additionalLength) or requestTime > (firstRequestTime+settings.additionalTime)):
                probablyVulnerable = True
                oh.writeOnFile(outputFile, str(i), line, requestStatus, str(requestLength), str(requestTime))
            if (settings.verboseMode):
                oh.printContent([i, oh.fixLineToOutput(line), requestStatus, requestLength, requestTime], probablyVulnerable)
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
        """Start the application, test the connection and redirection before make the fuzzing"""
        hasProxies = False
        if (settings.proxiesFile != None):
            hasProxies = True
            self.__readProxiesFromFile()
        if (self.__testConnection() != None):
            oh.infoBox("Connection status: OK")
        else:
            oh.errorBox("Failed to connect to the server.")
        oh.infoBox("Testing redirections ...")
        self.__testRedirection()
        oh.infoBox("Starting test on '"+self.getUrl()+"' ...")
        self.__fuzzy(hasProxies)
        oh.infoBox("Test completed.")