from OutputHandler import *
from FileHandler import *
import requests

class RequestHandler:
    """Class that handle with the requests
    
    Attributes:
        url: The target URL
        method: The request method
        param: The parameter of the request
        cookie: The HTTP Cookie header value
        proxy: The proxy used in the request
        proxyList: The list with valid proxies gived by a file
        session: The session of the requests
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
        self.__cookie = {}
        self.__proxy = {}
        self.__proxyList = []
        self.__session = requests.Session()
    
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

    def testConnection(self):
        """Test the connection with the target, and returns the request obj

        @returns object: The request object
        """
        try:
            r = requests.get(self.getUrl(), cookies=self.getCookie(), proxies=self.getProxy())
            r.raise_for_status()
            return r
        except Exception:
            return None

    def request(self, payload: str):
        response = self.__getRequestResponse(payload)
        return self.__getResponseData(response)

    def testRedirection(self):
        """Test if the connection will has a redirection"""
        response = self.__getRequestResponse(' ')
        if ('[302]' in str(response.history)):
            if (not oh.askYesNo("You was redirected to another page. Continue? (y/N): ")):
                exit(0)
        else:
            oh.infoBox("No redirections.")

    def setProxiesFromFile(self):
        """Get the proxies from a file and test each one"""
        for proxy in fh.readProxies():
            self.setProxy(proxy)
            self.__testProxy()

    def setProxyByRequestIndex(self, i: int):
        """Set the proxy based on request index

        @param type: int
        @param i: The request index
        """
        proxyList = self.getProxyList()
        self.setProxy(proxyList[int(i/10)%len(proxyList)])

    def __getRequestParameters(self, payload: str):
        """Get the request parameters using in the request fields

        @param type: str
        @param payload: The payload used in the parameter of the request
        @returns dict: The parameters dict of the request
        """
        requestParameters = {
            'Method': self.getMethod(),
            'Url': self.getUrl(),
            'Data': {},
            'HttpHeader': {},
        }
        for key, value in self.getParam().items():
            if (value != ''):
                requestParameters['Data'][key] = value
            else:
                requestParameters['Data'][key] = payload
        return requestParameters

    def __getRequestResponse(self, payload: str):
        """Get the response of a request with a custom parameter

        @param type: str
        @param payload: The payload used in the parameter of the request
        @returns object: The response of the request
        """
        requestParameters = self.__getRequestParameters(payload)
        request = requests.Request(requestParameters['Method'], requestParameters['Url'], data=requestParameters['Data'], params=requestParameters['Data'], cookies=self.getCookie())
        return self.__session.send(request.prepare(), proxies=self.getProxy())

    def __getResponseData(self, response: object):
        responseTime, responseLength = self.__getResponseTimeAndLength(response)
        responseStatus = str(response.status_code)
        responseData = {
            'Time': responseTime,
            'Length': responseLength,
            'Status': responseStatus,
        }
        return responseData

    def __getResponseTimeAndLength(self, response: object):
        """Get the response time and length

        @type response: object
        @param response: The Response object
        @rtype: tuple(float, int)
        @returns (responseTime, responseLength): The response time and length
        """
        responseLength = response.headers.get('Content-Length')
        if (responseLength == None):
            responseLength = 0
        return (response.elapsed.total_seconds(), responseLength)

    def __testProxy(self):
        """Test if the proxy can be used on the connection, and insert it into the proxies list"""
        if (self.__testConnection() != None):
            self.__proxyList.append(self.getProxy())