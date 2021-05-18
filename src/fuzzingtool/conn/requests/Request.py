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

from ..RequestParser import *
from ..responses.Response import Response
from ...exceptions.RequestExceptions import RequestException, InvalidHostname

import random
import time
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
        methods: The methods list to be used on fuzzing
    """
    def __init__(self,
        url: str,
        method: str = 'GET',
        methods: list = [],
        data: str = "",
        headers: dict = {},
        followRedirects: bool = True,
        proxy: dict = {},
        proxies: list = [],
        timeout: int = 0,
        cookie: str = '',
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
        self._url = self.__setupUrl(url)
        self.__method = self.__setupMethod(method)
        self.__data = self.__setupData(data)
        self.__header = self.__setupHeader(headers)
        self.__proxy = self.__setupProxy(proxy) if proxy else {}
        self.__proxies = [self.__setupProxy(proxy) for proxy in proxies]
        self.__timeout = None if not self.isUrlFuzzing() else 10 if not timeout else timeout
        self.__followRedirects = followRedirects
        if self.isUrlFuzzing():
            self.__session = requests.Session()
            self.__request = self.__sessionRequest
        else:
            self.__request = self.__commonRequest
        self._requestIndex = 0
        self.methods = methods
        if cookie:
            self.setHeaderContent('Cookie', cookie)
    
    def getUrl(self):
        """The url content getter

        @returns str: The target URL
        """
        return self._url['content']

    def getUrlDict(self):
        """The url getter

        @returns dict: The target URL dictionary
        """
        return self._url

    def isUrlFuzzing(self):
        """The URL fuzzing flag getter
        
        @returns bool: The URL Fuzzing flag
        """
        return False if not self._url['fuzzingIndexes'] else True

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
        if self.__header['payloadKeys']:
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
        return self._requestIndex

    def setMethod(self, method: str):
        """The request method setter

        @type method: str
        @param method: The request method
        """
        self.__method = self.__setupMethod(method)

    def setHeaderContent(self, key: str, value: str, header: dict = {}):
        """The header content setter

        @type key: str
        @param key: The HTTP header key
        @type value: str
        @param value: The HTTP header value
        """
        if not header:
            header = self.__header
        if '$' in value:
            header['payloadKeys'].append(key)
            header['content'][key] = self.__parseHeaderValue(value)
        else:
            header['content'][key] = value

    def setTimeout(self, timeout: int):
        """The timeout setter

        @type timeout: int
        @param timeout: The request timeout
        """
        self.__timeout = timeout

    def resetRequestIndex(self):
        """Resets the request index"""
        self._requestIndex = 1

    def testConnection(self):
        """Test the connection with the target, and raise an exception if couldn't connect"""
        try:
            url = getPureUrl(self._url)
            response = requests.get(
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
            before = time.time()
            response = self.__request(method, url, headers, data)
            timeTaken = (time.time() - before)
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
            response.setRequestData(url, method, payload, timeTaken, self._requestIndex)
            return response
        finally:
            self._requestIndex += 1

    def __setupUrl(self, url: str):
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

    def __setupMethod(self, method: str):
        """The method setup

        @returns dict: The target method dictionary
        """
        return {
            'content': method,
            'fuzzingIndexes': getIndexesToParse(method)
        }

    def __setupHeader(self, header: dict):
        """Setup the HTTP Header
        
        @type header: dict
        @param header: The HTTP header dictionary
        @returns dict: The HTTP header dictionary
        """
        header = {
            'content': header,
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

    def __parseHeaderValue(self, value: str):
        """Parse the header value into a list

        @type value: str
        @param value: The HTTP Header value
        @returns list: The list with the HTTP Header value content
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

    def __setupData(self, data: str):
        """Split all the request parameters into a list of arguments used in the request

        @type data: str
        @param data: The body data of the request
        @returns dict: The entries data of the request
        """
        rawData = {
            'PARAM': '',
            'BODY': '',
        }
        dataDict = {
            'PARAM': {},
            'BODY': {},
        }
        keys = []
        if self.__param:
            rawData['PARAM'] = self.__param
            keys.append('PARAM')
        del self.__param
        if data:
            rawData['BODY'] = data
            keys.append('BODY')
        for key in keys:
            if '&' in rawData[key]:
                rawData[key] = rawData[key].split('&')
                for arg in rawData[key]:
                    self.__buildDataDict(dataDict[key], arg)
            else:
                self.__buildDataDict(dataDict[key], rawData[key])
        return dataDict

    def __buildDataDict(self, dataDict: dict, key: str):
        """Set the default parameter values if are given

        @type data: dict
        @param data: The entries data of the request
        @type key: str
        @param key: The parameter key of the request
        """
        if '=' in key:
            key, value = key.split('=')
            if not '$' in value:
                dataDict[key] = value
            else:
                dataDict[key] = ''
        else:
            dataDict[key] = ''

    def __setupProxy(proxy: str):
        return {
            'http': f"http://{proxy}",
            'https': f"https://{proxy}",
        }

    def __getRequestParameters(self, payload: str):
        """Get the request parameters using in the request fields

        @type payload: str
        @param payload: The payload used in the request
        @returns tuple(str, str, dict, dict): The parameters of the request
        """
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