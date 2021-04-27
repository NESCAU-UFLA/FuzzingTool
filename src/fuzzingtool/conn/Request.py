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
from ..parsers.RequestParser import getHost, getPureUrl, requestParser as parser
from ..exceptions.RequestExceptions import RequestException, InvalidHostname

import random
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
        headers: The HTTP header
        proxy: The proxy used in the request
        proxies: The list with valid proxies gived by a file
        timeout: The request timeout before raise a TimeoutException
        followRedirects: The follow redirections flag
        requestIndex: The request index
        subdomainFuzzing: A flag to say if the fuzzing will occur on subdomain
        methods: The methods list to be used on fuzzing
    """
    def __init__(self,
        url: str,
        method: str = 'GET',
        methods: list = [],
        data: dict = {},
        headers: dict = {},
        followRedirects: bool = True,
        proxy: dict = {},
        proxies: list = [],
    ):
        """Class constructor

        @type url: str
        @param url: The target URL
        @type method: str
        @param method: The request http verb (method)
        @type methods: list
        @param methods: The request methods list
        @type data: dict
        @param data: The parameters of the request, with default values if are given
        @type headers: dict
        @param headers: The HTTP header of the request
        @type followRedirects: bool
        @param followRedirects: The follow redirects flag
        @type proxy: dict
        @param proxy: The proxy used in the request
        @type proxies: list
        @param proxies: The list with the proxies used in the requests
        """
        self.__url = parser.setupUrl(url)
        self.__method = parser.setupMethod(method)
        self.__data = data
        self.__headers = headers
        self.__proxy = proxy
        self.__proxies = proxies
        self.__timeout = None if not self.isUrlFuzzing() else 10
        self.__followRedirects = followRedirects
        self.__requestIndex = 0
        self.__setupHeader()
        self.__subdomainFuzzing = parser.checkForSubdomainFuzz(self.__url)
        if self.isUrlFuzzing():
            self.__session = requests.Session()
            self.__request = self.__sessionRequest
        else:
            self.__request = self.__commonRequest
        self.methods = methods
    
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
        """The URL fuzzing flag getter
        
        @returns bool: The URL Fuzzing flag
        """
        return False if not self.__url['fuzzingIndexes'] else True

    def isSubdomainFuzzing(self):
        """The Subdomain Fuzzing flag getter

        @returns bool: The Subdomain Fuzzing flag
        """
        return self.__subdomainFuzzing

    def isMethodFuzzing(self):
        """The method fuzzing flag getter

        @returns bool: The method fuzzing flag
        """
        return False if not self.__method['fuzzingIndexes'] else True

    def isDataFuzzing(self):
        """The data fuzzing flag getter

        @returns bool: The data fuzzing flag
        """
        for key, value in self.__data['PARAM'].items():
            if not value:
                return True
        for key, value in self.__data['BODY'].items():
            if not value:
                return True
        if self.__headers['payloadKeys']:
            return True
        return False

    def getProxy(self):
        """The proxy getter

        @returns dict: The proxy
        """
        return self.__proxy

    def getProxies(self):
        """The proxies list getter

        @returns list: The proxies list
        """
        return self.__proxies

    def getRequestIndex(self):
        """The request index getter

        @returns int: The request index
        """
        return self.__requestIndex

    def setMethod(self, method: str):
        """The request method setter

        @type method: str
        @param method: The request method
        """
        self.__method = parser.setupMethod(method)

    def setHeaderContent(self, key: str, value: str):
        """The header content setter

        @type key: str
        @param key: The HTTP Header key
        @type value: str
        @param value: The HTTP Header value
        """
        parser.setHeaderContent(self.__headers, key, value)

    def setTimeout(self, timeout: int):
        """The timeout setter

        @type timeout: int
        @param timeout: The request timeout
        """
        self.__timeout = timeout

    def resetRequestIndex(self):
        """Resets the request index"""
        if not self.__subdomainFuzzing:
            self.__requestIndex = 1
        else:
            self.__requestIndex = 0

    def testConnection(self):
        """Test the connection with the target, and raise an exception if couldn't connect"""
        try:
            url = getPureUrl(self.__url)
            response = requests.get(
                url,
                proxies=self.__proxy,
                headers=parser.getHeader(self.__headers),
                timeout=self.__timeout if self.__timeout else 10, # Default 10 seconds to make a request
            )
            response.raise_for_status()
        except requests.exceptions.HTTPError:
            raise RequestException(f"Connected to {url}, but raised a 404 status code")
        except requests.exceptions.ProxyError:
            raise RequestException(f"Can't connect to proxy")
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

    def hasRedirection(self):
        """Test if the connection will have a redirection
        
        @returns bool: The flag to say if occur a redirection or not
        """
        response = self.request(' ')
        if '302' in str(response.getResponse().history):
            return True
        return False

    def request(self, payload: str):
        """Make a request and get the response

        @type payload: str
        @param payload: The payload used in the request
        @returns Response: The response object of the request
        """
        if self.__proxies:
            self.__proxy = random.choice(self.__proxies)
        method, url, headers, data = self.__getRequestParameters(payload)
        try:
            if self.__subdomainFuzzing:
                try:
                    hostname = getHost(url)
                    ip = socket.gethostbyname(hostname)
                    payload = url
                except:
                    raise InvalidHostname(f"Can't resolve hostname {hostname}")
            else:
                ip = ''
                hostname = url
            try:
                before = time.time()
                response = self.__request(method, url, headers, data)
                timeTaken = (time.time() - before)
            except requests.exceptions.ProxyError:
                raise RequestException("Can't connect to proxy")
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
                raise RequestException(f"Invalid hostname {hostname} for HTTP request")
            except ValueError as e:
                raise RequestException(str(e))
            else:
                response.setRequestData(method, payload, timeTaken, self.__requestIndex, ip)
                return response
        finally:
            self.__requestIndex += 1

    def __getRequestParameters(self, payload: str):
        """Get the request parameters using in the request fields

        @type payload: str
        @param payload: The payload used in the request
        @returns tuple(str, str, dict, dict): The parameters of the request
        """
        parser.setPayload(payload)
        return (
            parser.getMethod(self.__method),
            parser.getUrl(self.__url),
            parser.getHeader(self.__headers),
            parser.getData(self.__data),
        )

    def __setupHeader(self):
        """Setup the HTTP Header"""
        self.__headers = parser.setupHeader(self.__headers)
        if not self.__headers['content']:
            self.__headers['content']['User-Agent'] = 'FuzzingTool Requester Agent'
        else:
            if 'Content-Length' in self.__headers['content'].keys():
                del self.__headers['content']['Content-Length']
        self.__headers['content']['Accept-Encoding'] = 'gzip, deflate'
    
    def __sessionRequest(self,
        method: str,
        url: str,
        headers: dict,
        data: dict
    ):
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
        return Response(self.__session.send(
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
        ))
    
    def __commonRequest(self,
        method: str,
        url: str,
        headers: dict,
        data: dict
    ):
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
        return Response(requests.request(
            method,
            url,
            data=data['BODY'],
            params=data['PARAM'],
            headers=headers,
            proxies=self.__proxy,
            timeout=self.__timeout,
            allow_redirects=self.__followRedirects,
        ))