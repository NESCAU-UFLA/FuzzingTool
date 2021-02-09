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

def parseHeaderValue(value: str):
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

class RequestParser:
    """Class that handle with request arguments parsing
    
    Attributes:
        url: The target URL
        method: The request method
        param: The parameter of the request
        httpHeader: The HTTP header
        payload: The payload used in the request
    """
    def __init__(self, url: dict, httpHeader: dict, method: str = '', param: dict = {}):
        """Class constructor

        @type url: dict
        @param url: The target URL
        @type httpHeader: dict
        @param httpHeader: The HTTP header
        @type method: str
        @param method: The request method
        @type param: dict
        @param param: The parameter of the request
        """
        self.__url = url
        self.__method = method
        self.__param = param
        self.__httpHeader = httpHeader
        self.__payload = ''
        self.__prefix = ''
        self.__suffix = ''
        self.__urlFuzzing = True if getIndexesToParse(self.__url['content']) else False

    def isUrlFuzzing(self):
        """The URL Fuzzing flag getter
           if the tests will occur on URL return true, else return false

        @returns bool: The URL Fuzzing flag
        """
        return self.__urlFuzzing

    def getUrl(self):
        """The url getter
        
        @returns str: The target url
        """
        return self.__url['content'] if not self.__url['indexToParse'] else self.__getAjustedUrl(self.__payload)

    def getHeader(self):
        """The HTTP Header getter

        @returns dict: The HTTP Header
        """
        return self.__httpHeader['content'] if not self.__httpHeader['keysCustom'] else self.__getAjustedHeader()

    def getData(self):
        """The param getter

        @returns dict: The param data of the request
        """
        return {} if not self.__param else self.__getAjustedData(self.__payload)

    def getAjustedPayload(self, payload: str):
        """The ajusted payload getter

        @returns str: The payload used in the request
        """
        return self.__prefix + payload + self.__suffix

    def setPayload(self, payload: str):
        """The payload setter

        @type payload: str
        @param payload: The payload used in the request
        """
        self.__payload = payload

    def setPrefix(self, prefix: str):
        """The prefix setter

        @type prefix: str
        @param prefix: The prefix used in the payload
        """
        self.__prefix = prefix
    
    def setSuffix(self, suffix: str):
        """The suffix setter

        @type suffix: str
        @param suffix: The suffix used in the payload
        """
        self.__suffix = suffix

    def getTargetFromUrl(self):
        """Gets the host from an URL

        @returns str: The target url
        """
        url = self.__url['content']
        if self.__url['indexToParse']:
            return url[:self.__url['indexToParse'][0]]
        return url

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

    def __getAjustedHeader(self):
        """Put the payload in the header value that contains $

        @type payload: str
        @param payload: The payload used in the parameter of the request
        @returns dict: The new HTTP Header
        """
        header = {}
        for key, value in self.__httpHeader['content'].items():
            header[key] = value
        for key in self.__httpHeader['keysCustom']:
            result = ''
            value = header[key]
            for i in range(len(value)-1):
                result += value[i] + self.__payload
            result += value[len(value)-1]
            header[key] = result.encode('utf-8')
        return header

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

    def getRequestParameters(self):
        """Get the request parameters using in the request fields

        @returns dict: The parameters dict of the request
        """
        requestParameters = {
            'Method': self.__method,
            'Url': self.getUrl(),
            'Header': self.getHeader(),
            'Data': self.getData(),
        }
        return requestParameters