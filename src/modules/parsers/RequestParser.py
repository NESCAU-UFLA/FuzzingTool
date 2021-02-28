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

def getIndexesToParse(paramContent: str):
    """If the fuzzing tests will occur on the given value,
       so get the list of positions of it to insert the payloads
    
    @type paramContent: str
    @param paramContent: The parameter content
    @returns list: The positions indexes to insert the payload.
                    Returns an empty list if the tests'll not occur
    """
    return [i for i, char in enumerate(paramContent) if char == '$']

class RequestParser:
    """Class that handle with request arguments parsing
    
    Attributes:
        payload: The payload used in the request
        urlFuzzing: The URL Fuzzing flag
    """
    def __init__(self):
        """Class constructor"""
        self.__payload = ''
        self.__urlFuzzing = False

    def setupUrl(self, url: str):
        """The URL setup.
           Insert an schema if it wasn't present into URL

        @returns str: The target URL
        """
        if '://' not in url:
            # No schema was defined, default protocol http
            url = 'http://' + url
        url = {
            'content': url,
            'indexesToParse': getIndexesToParse(url)
        }
        return url

    def parseHeaderValue(self, value: str):
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

    def checkForUrlFuzz(self, url: dict):
        """Checks if the fuzzing tests will occur on URL

        @type url: dict
        @param url: The URL dictionary
        """
        self.__urlFuzzing = True if url['indexesToParse'] else False

    def checkForSubdomainFuzz(self, url: dict):
        """Checks if the fuzzing tests will occur on subdomain

        @type url: dict
        @param url: The URL dictionary
        @returns bool: The subdomain fuzzing flag
        """
        url = url['content']
        if self.__urlFuzzing:
            if '.' in url and url.index('$') < url.index('.'):
                return True
        return False

    def getUrl(self, url: dict):
        """The new url getter
        
        @type url: dict
        @param url: The URL dictionary
        @returns str: The new target URL
        """
        return url['content'] if not self.__urlFuzzing else self.__getAjustedUrl(url)

    def getHeader(self, httpHeader: dict):
        """The new HTTP Header getter
        
        @type httpHeder: dict
        @param httpHeader: The HTTP Header
        @returns dict: The new HTTP Header
        """
        return httpHeader['content'] if not httpHeader['keysCustom'] else self.__getAjustedHeader(httpHeader)

    def getData(self, param: dict):
        """The new param getter

        @type param: dict
        @param param: The request parameters
        @returns dict: The new request parameters
        """
        return {} if not param else self.__getAjustedData(param)

    def isUrlFuzzing(self):
        """The URL Fuzzing flag getter
           if the tests will occur on URL return true, else return false

        @returns bool: The URL Fuzzing flag
        """
        return self.__urlFuzzing

    def setPayload(self, payload: str):
        """The payload setter

        @type payload: str
        @param payload: The payload used in the request
        """
        self.__payload = payload

    def getHost(self, url: str):
        """Get the target host

        @type url: str
        @param url: The target URL
        @returns str: The payloaded target
        """
        host = url[(url.index('://')+3):]
        try:
            return host[:host.index('/')]
        except ValueError:
            return host

    def getTargetUrl(self, url: str):
        """Gets the URL without the $ variable

        @type url: str
        @param url: The target url
        @returns str: The target url
        """
        if self.__urlFuzzing:
            if '$.' in url:
                return url.replace('$.', '')
            return url.replace('$', '')
        return url

    def __getAjustedUrl(self, url: dict):
        """Put the payload into the URL requestParameters dictionary

        @type url: dict
        @param url: The target URL dictionary
        @returns str: The new URL
        """
        ajustedUrl = url['content']
        for i in url['indexesToParse']:
            head = ajustedUrl[:i]
            tail = ajustedUrl[(i+1):]
            ajustedUrl = head + self.__payload + tail
        return ajustedUrl

    def __getAjustedHeader(self, httpHeader: dict):
        """Put the payload in the header value that contains $

        @type httpHeader: dict
        @param httpHeader: The HTTP Header dictionary
        @returns dict: The new HTTP Header
        """
        header = {}
        for key, value in httpHeader['content'].items():
            header[key] = value
        for key in httpHeader['keysCustom']:
            result = ''
            value = header[key]
            for i in range(len(value)-1):
                result += value[i] + self.__payload
            result += value[len(value)-1]
            header[key] = result.encode('utf-8')
        return header

    def __getAjustedData(self, data: dict):
        """Put the payload into the Data requestParameters dictionary

        @type data: dict
        @param dara: The request parameters
        @returns dict: The new request parameters
        """
        ajustedData = {}
        for key, value in data.items():
            if (value != ''):
                ajustedData[key] = value
            else:
                ajustedData[key] = self.__payload
        return ajustedData