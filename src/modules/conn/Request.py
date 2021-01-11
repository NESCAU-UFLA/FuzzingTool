from .Response import Response
from ..parsers.RequestParser import getIndexesToParse, RequestParser
from ..IO.OutputHandler import outputHandler as oh
from ..IO.FileHandler import fileHandler as fh
import time
try:
    import requests
except:
    exit("Requests package not installed. Install all dependencies first.")

class Request:
    """Class that handle with the requests
    
    Attributes:
        url: The target URL
        method: The request method
        param: The parameter of the request
        httpHeader: The HTTP header
        proxy: The proxy used in the request
        proxyList: The list with valid proxies gived by a file
        requestIndex: The request index
    """
    def __init__(self, url: str, method: str, defaultParam: dict, httpHeader: dict):
        """Class constructor

        @type url: str
        @param url: The target URL
        @type method: str
        @param method: The request method
        @type defaultParam: dict
        @param defaultParam: The parameters of the request, with default values if are given
        @type httpHeader: dict
        @param httpHeader: The HTTP header of the request
        """
        self.__url = {
            'content': url,
            'indexToParse': getIndexesToParse(url),
        }
        self.__method = method
        self.__param = defaultParam
        self.__httpHeader = httpHeader
        self.__proxy = {}
        self.__proxyList = []
        self.__requestIndex = 0
        self.__setupHeader()
    
    def getUrl(self):
        """The url getter

        @returns str: The target URL
        """
        return self.__url['content']

    def getUrlIndexToPayload(self):
        """The urlIndexToPayload getter
        
        @returns int: The URL index to insert the payload
        """
        return self.__url['indexToParse']

    def setHeaderContent(self, key: str, value: str):
        """The cookie setter

        @type key: str
        @param key: The HTTP Header key
        @type value: str
        @param value: The HTTP Header value
        """
        if '$' in value:
            self.__httpHeader['keysCustom'].append(key)
            self.__httpHeader['content'][key] = self.__parser.parseHeaderValue(value)
        else:
            self.__httpHeader['content'][key] = value

    def setProxy(self, proxy: dict):
        """The proxy setter

        @type proxy: dict
        @param proxy: The proxy used in the request
        """
        self.__proxy = proxy

    def testConnection(self):
        """Test the connection with the target, and raise an exception if couldn't connect (by status code)"""
        parser = RequestParser(self.__url, self.__httpHeader)
        connectionTest = requests.get(parser.getTargetFromUrl(), proxies=self.__proxy, headers=parser.getHeader())
        connectionTest.raise_for_status()

    def request(self, payload: str):
        """Make a request and get the response

        @type payload: str
        @param payload: The payload used in the request
        @returns dict: The response data dictionary
        """
        if (self.__proxyList and self.__requestIndex%1000 == 0):
            self.__updateProxy()
        parser = RequestParser(self.__url, self.__httpHeader, self.__method, self.__param)
        parser.setPayload(payload)
        requestParameters = parser.getRequestParameters()
        try:
            before = time.time()
            response = Response(requests.request(requestParameters['Method'], requestParameters['Url'], data=requestParameters['Data'], params=requestParameters['Data'], headers=requestParameters['Header'], proxies=self.__proxy))
            timeTaken = (time.time() - before)
        except requests.exceptions.RequestException:
            oh.abortBox("Connection aborted due an error.")
            exit()
        self.__requestIndex += 1
        return response.getResponseData(payload, timeTaken, self.__requestIndex)

    def testRedirection(self):
        """Test if the connection will have a redirection"""
        parser = RequestParser(self.__url, self.__httpHeader, self.__method, self.__param)
        parser.setPayload(' ')
        requestParameters = parser.getRequestParameters()
        response = requests.request(requestParameters['Method'], requestParameters['Url'], data=requestParameters['Data'], params=requestParameters['Data'], headers=requestParameters['Header'], proxies=self.__proxy)
        if ('[302]' in str(response.history)):
            if (not oh.askYesNo("You was redirected to another page. Continue? (y/N): ")):
                exit()
        else:
            oh.infoBox("No redirections")

    def setProxiesFromFile(self):
        """Get the proxies from a file and test each one"""
        oh.infoBox("Testing proxies ...")
        for proxy in fh.readProxies():
            self.setProxy(proxy)
            self.__testProxy()

    def __setupHeader(self):
        """Setup the HTTP Header

        @type header: dict
        @param header: The HTTP Header
        """
        self.__httpHeader = {
            'content': self.__httpHeader,
            'keysCustom': [],
        }
        for key, value in self.__httpHeader['content'].items():
            self.setHeaderContent(key, value)

    def __updateProxy(self):
        """Set the proxy based on request index"""
        self.setProxy(self.__proxyList[(self.__requestIndex%1000)%len(self.__proxyList)])

    def __testProxy(self):
        """Test if the proxy can be used on the connection, and insert it into the proxies list"""
        try:
            self.testConnection()
            oh.infoBox(f"Proxy {self.__proxy['http://']} worked.")
            self.__proxyList.append(self.__proxy)
        except:
            oh.warningBox(f"Proxy {self.__proxy['http://']} not worked.")