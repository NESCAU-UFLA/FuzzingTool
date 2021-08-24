# Copyright (c) 2020 - present Vitor Oriel <https://github.com/VitorOriel>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from ..RequestParser import *
from ...utils.consts import *
from ...utils.http_utils import *
from ...utils.utils import getIndexesToParse
from ...exceptions.RequestExceptions import RequestException

from threading import Lock
import random
import time
import urllib3.exceptions
from typing import List, Dict, Tuple
try:
    import requests
except:
    exit("Requests package not installed. Install all dependencies first.")

class Request:
    """Class that handle with the requests
    
    Attributes:
        url: The target URL
        method: The request method
        body: The body data of the request
        headers: The HTTP header
        proxy: The proxy used in the request
        proxies: The list with valid proxies gived by a file
        timeout: The request timeout before raise a TimeoutException
        followRedirects: The follow redirections flag
        methods: The methods list to be used on fuzzing
        lock: The threads locker to set up the payload on the fuzzing entries
    """
    def __init__(self,
        url: str,
        method: str = 'GET',
        methods: List[str] = [],
        body: str = '',
        headers: Dict[str, str] = {},
        followRedirects: bool = True,
        proxy: str = '',
        proxies: List[str] = [],
        timeout: int = 0,
        cookie: str = '',
        isSession: bool = False,
    ):
        """Class constructor

        @type url: str
        @param url: The target URL
        @type method: str
        @param method: The request http verb (method)
        @type methods: list
        @param methods: The request methods list
        @type body: str
        @param body: The body data of the request
        @type headers: dict
        @param headers: The HTTP header of the request
        @type followRedirects: bool
        @param followRedirects: The follow redirects flag
        @type proxy: str
        @param proxy: The proxy used in the request
        @type proxies: list
        @param proxies: The list with the proxies used in the requests
        @type timeout: int
        @param timeout: The request timeout
        @type cookie: str
        @param cookie: The cookie HTTP header value
        @type isSession: bool
        @param isSession: The flag to say if the requests will be made as session request
        """
        self._url = self.__setupUrl(url)
        self.__method = self.__setupMethod(method)
        self.__data = self.__setupData(body)
        self.__header = self.__setupHeader(headers)
        self.__proxy = self.__setupProxy(proxy) if proxy else {}
        self.__proxies = [self.__setupProxy(proxy) for proxy in proxies]
        self.__followRedirects = followRedirects
        self.__fuzzingType = self._setFuzzingType()
        self.__timeout = None if not self.isUrlDiscovery() else 10 if not timeout else timeout
        if isSession or self.isPathFuzzing():
            self.__session = requests.Session()
            self.__request = self.__sessionRequest
        else:
            self.__request = self.__commonRequest
        self.methods = methods
        if cookie:
            self.setHeaderContent('Cookie', cookie)
        self._lock = Lock()
    
    def getUrl(self) -> str:
        """The url content getter

        @returns str: The target URL
        """
        return self._url['content']

    def getUrlDict(self) -> dict:
        """The url getter

        @returns dict: The target URL dictionary
        """
        return self._url

    def isMethodFuzzing(self) -> bool:
        """The method fuzzing flag getter

        @returns bool: The method fuzzing flag
        """
        return self.__fuzzingType == HTTP_METHOD_FUZZING

    def isDataFuzzing(self) -> bool:
        """The data fuzzing flag getter

        @returns bool: The data fuzzing flag
        """
        return self.__fuzzingType == DATA_FUZZING

    def isUrlDiscovery(self) -> bool:
        """Checks if the fuzzing is for url discovery (path or subdomain)

        @returns bool: A flag to say if is url discovery fuzzing type
        """
        return self.__fuzzingType == PATH_FUZZING or self.__fuzzingType == SUBDOMAIN_FUZZING

    def isPathFuzzing(self) -> bool:
        """Checks if the fuzzing will be path discovery

        @returns bool: A flag to say if is path fuzzing
        """
        return self.__fuzzingType == PATH_FUZZING

    def getFuzzingType(self) -> int:
        """The fuzzing type getter

        @returns int: The fuzzing type
        """
        return self.__fuzzingType

    def setMethod(self, method: str) -> None:
        """The request method setter

        @type method: str
        @param method: The request method
        """
        self.__method = self.__setupMethod(method)

    def setBody(self, body: str) -> None:
        """The body data setter

        @type body: str
        @param body: The body data of the request
        """
        self.__buildDataDict(self.__data, 'BODY', body)

    def setHeaderContent(self,
        key: str,
        value: str,
        header: dict = {}
    ) -> None:
        """The header content setter

        @type key: str
        @param key: The HTTP header key
        @type value: str
        @param value: The HTTP header value
        @type header: dict
        @param header: The header to set the content
        """
        if not header:
            header = self.__header
        if FUZZING_MARK in value:
            header['payloadKeys'].append(key)
            header['content'][key] = self.__parseHeaderValue(value)
        else:
            header['content'][key] = value

    def testConnection(self) -> None:
        """Test the connection with the target, and raise an exception if couldn't connect"""
        try:
            url = getPureUrl(self._url['content'])
            requests.get(
                url,
                proxies=self.__proxy,
                headers=requestParser.getHeader(self.__header),
                timeout=self.__timeout if self.__timeout else 10, # Default 10 seconds to make a request
            )
        except requests.exceptions.ProxyError:
            raise RequestException(f"Can't connect to the proxy")
        except requests.exceptions.SSLError:
            raise RequestException(f"SSL couldn't be validated on {url}")
        except requests.exceptions.Timeout:
            raise RequestException(f"Connection to {url} timed out")
        except requests.exceptions.InvalidHeader as e:
            e = str(e)
            invalidHeader = e[e.rindex(': ')+2:]
            raise RequestException(f"Invalid header {invalidHeader}")
        except (
            requests.exceptions.ConnectionError,
            requests.exceptions.RequestException
        ):
            raise RequestException(f"Failed to establish a connection to {url}")

    def hasRedirection(self) -> bool:
        """Test if the connection will have a redirection
        
        @returns bool: The flag to say if occur a redirection or not
        """
        response, *_ = self.request(' ')
        if '302' in str(response.history):
            return True
        return False

    def request(self, payload: str = '') -> Tuple[requests.Response, float]:
        """Make a request and get the response

        @type payload: str
        @param payload: The payload used in the request
        @returns Response: The response object of the request
        """
        if self.__proxies:
            self.__proxy = random.choice(self.__proxies)
        method, url, headers, data = self.__getRequestParameters(payload)
        try:
            before = time.time()
            response = self.__request(method, url, headers, data)
            RTT = (time.time() - before)
        except requests.exceptions.ProxyError:
            raise RequestException("Can't connect to the proxy")
        except requests.exceptions.TooManyRedirects:
            raise RequestException(f"Too many redirects on {url}")
        except requests.exceptions.SSLError:
            raise RequestException(f"SSL couldn't be validated on {url}")
        except requests.exceptions.Timeout:
            raise RequestException(f"Connection to {url} timed out")
        except requests.exceptions.InvalidHeader as e:
            e = str(e)
            invalidHeader = e[e.rindex(': ')+2:]
            raise RequestException(f"Invalid header {invalidHeader}: {headers[invalidHeader].decode('utf-8')}")
        except (
            requests.exceptions.ConnectionError,
            requests.exceptions.RequestException
        ):
            raise RequestException(f"Failed to establish a connection to {url}")
        except (
            UnicodeError,
            urllib3.exceptions.LocationParseError
        ):
            raise RequestException(f"Invalid hostname {getHost(url)} for HTTP request")
        except ValueError as e:
            raise RequestException(str(e))
        else:
            return (response, RTT)

    def _setFuzzingType(self) -> int:
        """Sets the fuzzing type
        
        @returns int: The fuzzing type int value
        """
        def _isMethodFuzzing() -> bool:
            """Checks if the fuzzing type is MethodFuzzing
            
            @returns bool: The fuzzing flag
            """
            return False if not self.__method['fuzzingIndexes'] else True

        def _isUrlFuzzing() -> bool:
            """Checks if the fuzzing type is UrlFuzzing
            
            @returns bool: The fuzzing flag
            """
            return False if not self._url['fuzzingIndexes'] else True

        def _isUrlDiscovery() -> bool:
            """Checks if the fuzzing type is UrlFuzzing for discovery
            
            @returns bool: The fuzzing flag
            """
            return (_isUrlFuzzing() and not '?' in self._url['content'])

        def _isDataFuzzing() -> bool:
            """Checks if the fuzzing type is DataFuzzing
            
            @returns bool: The fuzzing flag
            """
            for _, value in self.__data['PARAM'].items():
                if not value:
                    return True
            for _, value in self.__data['BODY'].items():
                if not value:
                    return True
            if self.__header['payloadKeys']:
                return True
            return False
        
        if _isMethodFuzzing():
            return HTTP_METHOD_FUZZING
        if _isUrlDiscovery():
            return PATH_FUZZING
        if _isDataFuzzing():
            return DATA_FUZZING
        return UNKNOWN_FUZZING

    def __setupUrl(self, url: str) -> dict:
        """The URL setup

        @returns dict: The target URL dictionary
        """
        if '://' not in url:
            # No schema was defined, default protocol http
            url = f'http://{url}'
        if '/' not in getUrlWithoutScheme(url):
            # Insert a base path if wasn't specified
            url += '/'
        if '?' in url:
            url, self.__param = url.split('?', 1)
        else:
            self.__param = ''
        return {
            'content': url,
            'fuzzingIndexes': getIndexesToParse(url)
        }

    def __setupMethod(self, method: str) -> dict:
        """The method setup

        @returns dict: The target method dictionary
        """
        return {
            'content': method,
            'fuzzingIndexes': getIndexesToParse(method)
        }

    def __setupHeader(self, header: dict) -> dict:
        """Setup the HTTP Header
        
        @type header: dict
        @param header: The HTTP header dictionary
        @returns dict: The HTTP header dictionary
        """
        header = {
            'content': {**header},
            'payloadKeys': [],
        }
        for key, value in header['content'].items():
            self.setHeaderContent(key, value, header)
        if not header['content']:
            header['content']['User-Agent'] = 'FuzzingTool Requester Agent'
        else:
            if 'Content-Length' in header['content'].keys():
                del header['content']['Content-Length']
        header['content']['Accept-Encoding'] = 'gzip, deflate'
        return header

    def __parseHeaderValue(self, value: str) -> List[str]:
        """Parse the header value into a list

        @type value: str
        @param value: The HTTP Header value
        @returns List[str]: The list with the HTTP Header value content
        """
        headerValue = []
        lastIndex = 0
        for i in getIndexesToParse(value):
            headerValue.append(value[lastIndex:i])
            lastIndex = i+1
        if lastIndex == len(value):
            headerValue.append('')
        else:
            headerValue.append(value[lastIndex:len(value)])
        return headerValue

    def __setupData(self, body: str) -> dict:
        """Split all the request parameters into a list of arguments used in the request

        @type body: str
        @param body: The body data of the request
        @returns dict: The entries data of the request
        """
        dataDict = {
            'PARAM': {},
            'BODY': {},
        }
        if self.__param:
            self.__buildDataDict(dataDict, 'PARAM', self.__param)
        del self.__param
        if body:
            self.__buildDataDict(dataDict, 'BODY', body)
        return dataDict

    def __buildDataDict(self, dataDict: dict, where: str, content: str) -> None:
        """Build the content into the data dict

        @type dataDict: dict
        @param dataDict: The final data dict
        @type where: str
        @param where: Is on POST or GET?
        @type content: str
        @param content: The content of the data
        """
        def buildContent(dataDict: dict, content: str) -> None:
            """Build the inner content (for each splited &) into the data dict

            @type dataDict: dict
            @param dataDict: The final data dict
            @type content: str
            @param content: The content of the data
            """
            if '=' in content:
                key, value = content.split('=')
                if not FUZZING_MARK in value:
                    dataDict[key] = value
                else:
                    dataDict[key] = ''
            else:
                dataDict[content] = ''
        
        for content in content.split('&'):
            buildContent(dataDict[where], content)

    def __setupProxy(self, proxy: str) -> Dict[str, str]:
        """Setup the proxy

        @type proxy: str
        @param proxy: The proxy used in the request
        @returns Dict[str, str]: The proxy dictionary
        """
        return {
            'http': f"http://{proxy}",
            'https': f"https://{proxy}",
        }

    def __getRequestParameters(self, payload: str) -> Tuple[
        str, str, dict, dict
    ]:
        """Get the request parameters using in the request fields

        @type payload: str
        @param payload: The payload used in the request
        @returns tuple(str, str, dict, dict): The parameters of the request
        """
        with self._lock:
            requestParser.setPayload(payload)
            return (
                requestParser.getMethod(self.__method),
                requestParser.getUrl(self._url),
                requestParser.getHeader(self.__header),
                requestParser.getData(self.__data),
            )
    
    def __sessionRequest(self,
        method: str,
        url: str,
        headers: dict,
        data: dict
    ) -> requests.Response:
        """Performs a request to the target using Session object

        @type method: str
        @param method: The request method
        @type url: str
        @param url: The target URL
        @type headers: dict
        @param headers: The http header of the request
        @type data: dict
        @param data: The data to be send with the request
        @returns Response: The response object of the request
        """
        return self.__session.send(
            self.__session.prepare_request(requests.Request(
                method,
                url,
                data=data['BODY'],
                params=data['PARAM'],
                headers=headers,
            )),
            proxies=self.__proxy,
            timeout=self.__timeout,
            allow_redirects=self.__followRedirects,
        )
    
    def __commonRequest(self,
        method: str,
        url: str,
        headers: dict,
        data: dict
    ) -> requests.Response:
        """Performs a request to the target

        @type method: str
        @param method: The request method
        @type url: str
        @param url: The target URL
        @type headers: dict
        @param headers: The http header of the request
        @type data: dict
        @param data: The data to be send with the request
        @returns Response: The response object of the request
        """
        return requests.request(
            method,
            url,
            data=data['BODY'],
            params=data['PARAM'],
            headers=headers,
            proxies=self.__proxy,
            timeout=self.__timeout,
            allow_redirects=self.__followRedirects,
        )