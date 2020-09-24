import requests
from MessageHandler import *

class FuzzyTool:
    def __init__(self, method):
        self.__url = ""
        self.__args = []
        self.__param = {}
        self.__cookie = {}
        self.__method = method
    
    def getUrl(self):
        return self.__url
    
    def getArgs(self):
        return self.__args

    def getParam(self):
        return self.__param
    
    def getCookie(self):
        return self.__cookie
    
    def setUrl(self, url):
        self.__url = url
    
    def setArgs(self, args):
        self.__args = args

    def setParam(self, param):
        self.__param = param
    
    def setCookie(self, cookie):
        self.__cookie = cookie
    
    def getMethod(self):
        return self.__method

    def testConnection(self):
        try:
            self.setParam({self.getArgs()[0]: ''})
            r = requests.get(self.getUrl(), params=self.getParam(), cookies=self.getCookie())
            r.raise_for_status()
            mh.infoBox("Connection estabilished")
            return r
        except Exception as e:
            exit("An error has occured during connection process...")

    def testRedirection(self, request):
        if ('[302]' in str(request.history)):
            if (not mh.askYesNo("You was redirected to another page. Do you want to continue? (y/N): ")):
                exit("Ended process...")

    def start(self, fileName):
        try:
            file = open(fileName, 'r')
        except FileNotFoundError as e:
            exit("File '"+fileName+"' not found . . .")
        requestAux = self.testConnection()
        self.testRedirection(requestAux)
        mh.infoBox("Starting test on '"+self.getUrl()+"' ...")
        mh.getHeader()
        i = 0
        firstRequestTime = requestAux.elapsed.total_seconds()
        firstRequestLength = requestAux.headers.get('content-length')
        mh.printContent([i, '', requestAux.status_code, firstRequestLength, firstRequestTime])
        for line in file:
            i += 1
            line = line.rstrip("\n")
            for arg in self.getArgs():
                self.setParam({arg: line})
                if (self.getMethod() == 'GET'):
                    r = requests.get(self.getUrl(), params=self.getParam(), cookies=self.getCookie())
            requestTime = r.elapsed.total_seconds()
            requestLength = r.headers.get('content-length')
            #if (requestTime > 1):
            mh.printContent([i, mh.fixLineToOutput(line), r.status_code, requestLength, requestTime])
            
        mh.getInitOrEnd()