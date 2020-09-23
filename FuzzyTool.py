import requests

class FuzzyTool:
    def __init__(self, isGet):
        self.__url = ""
        self.__args = []
        self.__param = {}
        self.__cookie = {}
        self.__isGet = isGet
    
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
    
    def isGet(self):
        return self.__isGet

    def start(self, fileName):
        try:
            file = open(fileName, 'r')
        except FileNotFoundError as e:
            exit("File '"+fileName+"' not found . . .")
        for line in file:
            for arg in self.getArgs():
                param = {arg: line}
                if (self.isGet()):
                    r = requests.get(self.getUrl(), params=param, cookies=self.getCookie())
                    print(line + '|' + str(r.elapsed.total_seconds()))