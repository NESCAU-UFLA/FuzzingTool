from modules.IO.OutputHandler import outputHandler as oh
from modules.IO.FileHandler import fileHandler as fh
import requests

class RequestHandler:
    """Class that handle with the requests
    
    Attributes:
        url: The target URL
        method: The request method
        param: The parameter of the request
        urlIndexToPayload: The URL index to set the payload
        headers: The HTTP headers
        proxy: The proxy used in the request
        proxyList: The list with valid proxies gived by a file
        session: The session of the requests
    """
    def __init__(self, url: str, method: str, defaultParam: dict, headers: dict):
        """Class constructor

        @type url: str
        @param url: The target URL
        @type method: str
        @param method: The request method
        @type defaultParam: dict
        @param defaultParam: The parameters of the request, with default values if are given
        @type headers: dict
        @param headers: The HTTP headers of the request
        """
        self.__url = {
            'content': url,
            'indexToParse': self.__getIndexesToParse(url),
        }
        self.__method = method
        self.__param = defaultParam
        self.__headers = headers
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

    def getHeaders(self):
        '''The headers getter

        @returns dict: The HTTP headers
        '''
        return self.__headers

    def getUrlIndexToPayload(self):
        """The urlIndexToPayload getter
        
        @returns int: The URL index to insert the payload
        """
        return self.__url['indexToParse']

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

        @type url: str
        @param url: The target URL
        """
        self.__url['content'] = url
    
    def setParam(self, param: dict):
        """The param setter

        @type param: dict
        @param param: The parameter of the request
        """
        self.__param = param

    def setCookie(self, cookie: dict):
        """The cookie setter

        @type cookie: dict
        @param cookie: The HTTP Cookie header value
        """
        self.__headers['Cookie'] = cookie
    
    def setProxy(self, proxy: dict):
        """The proxy setter

        @type proxy: dict
        @param proxy: The proxy used in the request
        """
        self.__proxy = proxy

    def setProxyList(self, proxyList: list):
        """The proxyList setter

        @type proxyList: list
        @param proxyList: The proxies list
        """
        self.__proxyList = proxyList

    def testConnection(self):
        """Test the connection with the target"""
        r = requests.get(self.__url['content'], proxies=self.__proxy)
        r.raise_for_status()

    def request(self, payload: str):
        """Make a request and get the response

        @type payload: str
        @param payload: The payload used in the request
        @returns dict: The response data dictionary
        """
        try:
            response = self.__getRequestResponse(payload)
        except requests.exceptions.RequestException:
            oh.errorBox("Connection aborted due an error.")
        return self.__getResponseData(response, payload)

    def testRedirection(self):
        """Test if the connection will have a redirection"""
        response = self.__getRequestResponse(' ')
        if ('[302]' in str(response.history)):
            if (not oh.askYesNo("You was redirected to another page. Continue? (y/N): ")):
                exit(0)
        else:
            oh.infoBox("No redirections.")

    def setProxiesFromFile(self):
        """Get the proxies from a file and test each one"""
        oh.infoBox("Testing proxies ...")
        for proxy in fh.readProxies():
            self.setProxy(proxy)
            self.__testProxy()

    def setProxyByRequestIndex(self, i: int):
        """Set the proxy based on request index

        @type i: int
        @param i: The request index
        """
        self.setProxy(self.__proxyList[int(i/1000)%len(self.__proxyList)])

    def __getIndexesToParse(self, paramContent: str):
        """If the fuzzing tests will occur on the given value,
        so get the list of positions of it to insert the payloads
        
        @type paramContent: str
        @param paramContent: The parameter content
        @returns list: The positions indexes to insert the payload.
                       Returns an empty list if the tests'll not occur
        """
        if '$' in paramContent:
            return [i for i, char in enumerate(paramContent) if char == '$']
        return []

    def __getAjustedUrl(self, payload: str):
        """Put the payload into the URL requestParameters dictionary

        @type payload: str
        @param payload: The payload used in the parameter of the request
        @returns str: The ajusted URL
        """
        url = self.__url['content']
        i = self.__url['indexToParse'][0]
        head = url[:i]
        tail = url[(i+1):]
        return head+payload+tail

    def __getAjustedData(self, payload: str):
        """Put the payload into the Data requestParameters dictionary

        @type payload: str
        @param payload: The payload used in the parameter of the request
        @returns dict: The data dictionary of the request
        """
        data = {}
        for key, value in self.__param.items():
            if (value != ''):
                data[key] = value
            else:
                data[key] = payload
        return data

    def __getRequestParameters(self, payload: str):
        """Get the request parameters using in the request fields

        @type payload: str
        @param payload: The payload used in the parameter of the request
        @returns dict: The parameters dict of the request
        """
        requestParameters = {
            'Method': self.__method,
            'Url': self.__url['content'] if not self.__url['indexToParse'] else self.__getAjustedUrl(payload),
            'Headers': self.__headers,
            'Data': {} if not self.__param else self.__getAjustedData(payload),
        }
        return requestParameters

    def __getRequestResponse(self, payload: str):
        """Get the response of a request with a custom parameter

        @type payload: str
        @param payload: The payload used in the parameter of the request
        @returns object: The response of the request
        """
        requestParameters = self.__getRequestParameters(payload)
        request = requests.Request(requestParameters['Method'], requestParameters['Url'], data=requestParameters['Data'], params=requestParameters['Data'], headers=requestParameters['Headers'])
        return self.__session.send(request.prepare(), proxies=self.__proxy)

    def __getResponseData(self, response: object, payload: str):
        """Get the response data parsed into a dictionary

        @type response: object
        @param response: The response of a request
        @returns dict: The response data parsed into a dictionary
        """
        responseTime, responseLength = self.__getResponseTimeAndLength(response)
        responseStatus = response.status_code
        responseData = {
            'Request': 0,
            'Payload': payload,
            'Status': responseStatus,
            'Length': responseLength,
            'Time': responseTime,
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
        try:
            self.__testConnection()
            oh.infoBox(f"Proxy {self.__proxy['http://']} worked.")
            self.__proxyList.append(self.__proxy)
        except:
            oh.warningBox(f"Proxy {self.__proxy['http://']} not worked.")