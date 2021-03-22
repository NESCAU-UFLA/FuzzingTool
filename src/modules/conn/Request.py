## FuzzingTool
# 
# Authors:
#    Vitor Oriel C N Borges <https://github.com/VitorOriel>
# License: MIT (LICENSE.md)
#    Copyright (c) 2021 Vitor Oriel
#    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
#    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
#    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
## https://github.com/NESCAU-UFLA/FuzzingTool

from .Response import Response
from .RequestException import RequestException, InvalidHostname
from ..parsers.RequestParser import requestParser as parser

import time
import socket
import urllib3.exceptions
try:
    import requests
except:
    exit("Requests package not installed. Install all dependencies first.")

class Request:
    """Class that handle with the requests
    
    Attributes:
        url: The target URL
        method: The request method
        data: The parameter data of the request
        httpHeader: The HTTP header
        proxy: The proxy used in the request
        proxyList: The list with valid proxies gived by a file
        timeout: The request timeout before raise a TimeoutException
        followRedirects: The follow redirections flag
        requestIndex: The request index
        subdomainFuzzing: A flag to say if the fuzzing will occur on subdomain
    """
    def __init__(self, url: str, method: str, data: dict, httpHeader: dict):
        """Class constructor

        @type url: str
        @param url: The target URL
        @type method: str
        @param method: The request method
        @type data: dict
        @param data: The parameters of the request, with default values if are given
        @type httpHeader: dict
        @param httpHeader: The HTTP header of the request
        """
        self.__url = parser.setupUrl(url)
        self.__method = method
        self.__data = data
        self.__httpHeader = httpHeader
        self.__proxy = {}
        self.__proxyList = []
        self.__timeout = None if not parser.isUrlFuzzing(self.__url) else 10
        self.__followRedirects = True
        self.__requestIndex = 0
        self.__setupHeader()
        self.__subdomainFuzzing = parser.checkForSubdomainFuzz(self.__url)
    
    def getUrl(self):
        """The url content getter

        @returns str: The target URL
        """
        return self.__url['content']

    def getUrlDict(self):
        """The url getter

        @returns dict: The target URL dictionary
        """
        return self.__url

    def isUrlFuzzing(self):
        """The URL Fuzzing flag getter
        
        @returns bool: The URL Fuzzing flag
        """
        return parser.isUrlFuzzing(self.__url)

    def getProxy(self):
        """The proxy getter

        @returns dict: The proxy
        """
        return self.__proxy

    def getProxyList(self):
        """The proxies list getter

        @returns list: The proxies list
        """
        return self.__proxyList

    def getRequestIndex(self):
        """The request index getter

        @returns int: The request index
        """
        return self.__requestIndex

    def getParser(self):
        """The request parser getter

        @returns RequestParser: The request parser
        """
        return parser

    def isSubdomainFuzzing(self):
        """The Subdomain Fuzzing flag getter

        @returns bool: The Subdomain Fuzzing flag
        """
        return self.__subdomainFuzzing

    def setHeaderContent(self, key: str, value: str):
        """The header content setter

        @type key: str
        @param key: The HTTP Header key
        @type value: str
        @param value: The HTTP Header value
        """
        if '$' in value:
            self.__httpHeader['payloadKeys'].append(key)
            self.__httpHeader['content'][key] = parser.parseHeaderValue(value)
        else:
            self.__httpHeader['content'][key] = value

    def setProxy(self, proxy: dict):
        """The proxy setter

        @type proxy: dict
        @param proxy: The proxy used in the request
        """
        self.__proxy = proxy

    def setProxyList(self, proxyList: list):
        """The proxy list setter

        @type proxyList: list
        @param proxyList: The list with the proxies used in the requests
        """
        self.__proxyList = proxyList

    def setTimeout(self, timeout: int):
        """The timeout setter

        @type timeout: int
        @param timeout: The request timeout
        """
        self.__timeout = timeout

    def setFollowRedirects(self, followRedirects: bool):
        """The follow redirects setter

        @type followRedirects: bool
        @param followRedirects: The follow redirects flag
        """
        self.__followRedirects = followRedirects

    def testConnection(self, proxy: bool = False):
        """Test the connection with the target, and raise an exception if couldn't connect (by status code)"""
        try:
            target = parser.getTargetUrl(self.__url)
            response = requests.get(
                target,
                proxies=self.__proxy if proxy else {},
                headers=parser.getHeader(self.__httpHeader),
                timeout=self.__timeout if self.__timeout else 10, # Default 10 seconds to make a request
            )
            response.raise_for_status()
        except:
            raise RequestException(target)

    def hasRedirection(self):
        """Test if the connection will have a redirection"""
        response = self.request(' ')
        self.__requestIndex -= 1
        if '302' in str(response.getResponse().history):
            return True
        return False

    def request(self, payload: str):
        """Make a request and get the response

        @type payload: str
        @param payload: The payload used in the request
        @returns dict: The response data dictionary
        """
        if self.__proxyList and self.__requestIndex%1000 == 0:
            self.__updateProxy()
        parser.setPayload(payload)
        requestParameters = self.__getRequestParameters()
        targetUrl = requestParameters['Url']
        targetIp = ''
        try:
            if self.__subdomainFuzzing:
                try:
                    hostname = parser.getHost(targetUrl)
                    targetIp = socket.gethostbyname(hostname)
                    payload = targetUrl
                except:
                    raise InvalidHostname(f"Can't resolve hostname {hostname}")
            try:
                before = time.time()
                response = Response(requests.request(
                    requestParameters['Method'],
                    targetUrl,
                    data=requestParameters['Data']['POST'],
                    params=requestParameters['Data']['GET'],
                    headers=requestParameters['Headers'],
                    proxies=self.__proxy,
                    timeout=self.__timeout,
                    allow_redirects=self.__followRedirects,
                ))
                timeTaken = (time.time() - before)
            except requests.exceptions.ProxyError:
                raise RequestException("The actual proxy isn't working anymore.")
            except requests.exceptions.TooManyRedirects:
                raise RequestException(f"Too many redirects on {targetUrl}")
            except requests.exceptions.SSLError:
                raise RequestException(f"SSL couldn't be validated on {targetUrl}")
            except requests.exceptions.Timeout:
                raise RequestException(f"Connection to {targetUrl} timed out")
            except requests.exceptions.InvalidHeader as e:
                e = str(e)
                invalidHeader = e[e.rindex(': ')+2:]
                raise RequestException(f"Invalid header {invalidHeader}: {requestParameters['Headers'][invalidHeader].decode('utf-8')}")
            except (
                requests.exceptions.ConnectionError,
                requests.exceptions.RequestException
            ):
                raise RequestException(f"Failed to establish a connection to {targetUrl}")
            except (
                UnicodeError,
                urllib3.exceptions.LocationParseError
            ):
                try:
                    hostname
                except:
                    hostname = targetUrl
                raise RequestException(f"Invalid hostname {hostname} for HTTP request")
            else:
                response.setRequestData(payload, timeTaken, self.__requestIndex, targetIp)
                return response
        finally:
            self.__requestIndex += 1

    def __getRequestParameters(self):
        """Get the request parameters using in the request fields

        @returns dict: The parameters dict of the request
        """
        requestParameters = {
            'Method': self.__method,
            'Url': parser.getUrl(self.__url),
            'Headers': parser.getHeader(self.__httpHeader),
            'Data': parser.getData(self.__data),
        }
        return requestParameters

    def __setupHeader(self):
        """Setup the HTTP Header"""
        self.__httpHeader = {
            'content': self.__httpHeader,
            'payloadKeys': [],
        }
        for key, value in self.__httpHeader['content'].items():
            self.setHeaderContent(key, value)
        if not self.__httpHeader['content']:
            self.__httpHeader['content']['User-Agent'] = 'FuzzingTool Requester Agent'
        else:
            if 'Content-Length' in self.__httpHeader['content'].keys():
                del self.__httpHeader['content']['Content-Length']

    def __updateProxy(self):
        """Set the proxy based on request index"""
        self.setProxy(self.__proxyList[(self.__requestIndex%1000)%len(self.__proxyList)])