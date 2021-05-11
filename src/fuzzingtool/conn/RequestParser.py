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

from ..utils.utils import getIndexesToParse

def getHost(url: str):
    """Get the target host from url

    @type url: str
    @param url: The target URL
    @returns str: The payloaded target
    """
    url = getUrlWithoutScheme(url)
    return url[:url.index('/')]

def getPath(url: str):
    """Get the target path from url

    @type url: str
    @param url: The target URL
    @returns str: The payloaded path
    """
    url = getUrlWithoutScheme(url)
    return url[url.index('/'):]

def getPureUrl(url: dict):
    """Gets the URL without the $ variable

    @type url: dict
    @param url: The target url
    @returns str: The target url
    """
    if url['fuzzingIndexes']:
        if '$.' in url['content']:
            return url['content'].replace('$.', '')
        return url['content'].replace('$', '')
    return url['content']

def getUrlWithoutScheme(url: str):
    """Get the target url without scheme

    @type url: str
    @param url: The target URL
    @returns str: The url without scheme
    """
    return url[(url.index('://')+3):]

def checkForSubdomainFuzz(url: str):
    """Checks if the fuzzing tests will occur on subdomain

    @type url: str
    @param url: The target URL
    @returns bool: The subdomain fuzzing flag
    """
    if ('.' in url and '$' in url) and url.index('$') < url.index('.'):
        return True
    return False

class RequestParser:
    """Class that handle with request arguments parsing
    
    Attributes:
        payload: The payload used in the request
    """
    def __init__(self):
        self.__payload = ''

    def getMethod(self, method: dict):
        """The new method getter
        
        @type method: dict
        @param method: The method dictionary
        @returns str: The new target method
        """
        return method['content'] if not method['fuzzingIndexes'] else self.__getAjustedContentByIndexes(method)

    def getUrl(self, url: dict):
        """The new url getter
        
        @type url: dict
        @param url: The URL dictionary
        @returns str: The new target URL
        """
        return url['content'] if not url['fuzzingIndexes'] else self.__getAjustedContentByIndexes(url)

    def getHeader(self, headers: dict):
        """The new HTTP Header getter
        
        @type httpHeder: dict
        @param headers: The HTTP Header
        @returns dict: The new HTTP Header
        """
        return headers['content'] if not headers['payloadKeys'] else self.__getAjustedHeader(headers)

    def getData(self, data: dict):
        """The new data getter

        @type data: dict
        @param data: The request parameters
        @returns dict: The new request parameters
        """
        return {
            'PARAM': {} if not data['PARAM'] else self.__getAjustedData(data['PARAM']),
            'BODY': {} if not data['BODY'] else self.__getAjustedData(data['BODY'])
        }

    def setPayload(self, payload: str):
        """The payload setter

        @type payload: str
        @param payload: The payload used in the request
        """
        self.__payload = payload

    def __getAjustedContentByIndexes(self, content: dict):
        """Put the payload into the given content

        @type content: dict
        @param content: The target content dictionary
        @returns str: The new content
        """
        ajustedContent = content['content']
        for i in content['fuzzingIndexes']:
            head = ajustedContent[:i]
            tail = ajustedContent[(i+1):]
            ajustedContent = head + self.__payload + tail
        return ajustedContent

    def __getAjustedHeader(self, header: dict):
        """Put the payload in the header value that contains $

        @type header: dict
        @param header: The HTTP Header dictionary
        @returns dict: The new HTTP Header
        """
        ajustedHeader = {}
        for key, value in header['content'].items():
            ajustedHeader[key] = value
        for key in header['payloadKeys']:
            result = ''
            value = ajustedHeader[key]
            for i in range(len(value)-1):
                result += value[i] + self.__payload
            result += value[len(value)-1]
            ajustedHeader[key] = result.encode('utf-8')
        return ajustedHeader

    def __getAjustedData(self, data: dict):
        """Put the payload into the Data requestParameters dictionary

        @type data: dict
        @param dara: The request parameters
        @returns dict: The new request parameters
        """
        ajustedData = {}
        for key, value in data.items():
            if value:
                ajustedData[key] = value
            else:
                ajustedData[key] = self.__payload
        return ajustedData

requestParser = RequestParser()