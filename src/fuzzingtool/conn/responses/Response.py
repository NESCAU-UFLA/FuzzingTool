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

class Response:
    """Class that handle with the response

    Attributes:
        response: The response object of the request
        custom: A dict to handle with the custom information of a response
    """
    def __init__(self, response: object):
        """Class constructor

        @type response: object
        @param response: The response of a request
        """
        self.__response = response
        self.custom = {}
        self.__loadResponseData()
    
    def getResponse(self):
        """The response (requests object) getter

        @returns object: The response object
        """
        return self.__response

    def setRequestData(self,
        url: str,
        method: str,
        payload: str,
        timeTaken: float,
        requestIndex: int
    ):
        """Set the request data to be used into the dictionary

        @type url: str
        @param url: The target URL
        @type payload: str
        @param payload: The payload used in the request
        @type timeTaken: float
        @param timeTaken: The time taken after make the request
        @type requestIndex: int
        @param requestIndex: The request index
        """
        self.requestUrl = url
        self.requestMethod = method
        self.requestPayload = payload
        self.RTT = float('%.6f'%(timeTaken))
        self.requestIndex = requestIndex

    def __loadResponseData(self):
        """Loads the response data"""
        self.headers = self.__response.headers
        self.content = self.__response.content
        self.text = self.__response.text
        self.length = self.__response.headers.get('Content-Length')
        if self.length == None:
            self.length = len(self.content)
        self.elapsedTime = self.__response.elapsed.total_seconds()
        self.status = self.__response.status_code
        self.quantityOfWords = len(self.content.split())
        self.quantityOfLines = self.content.count(b'\n')