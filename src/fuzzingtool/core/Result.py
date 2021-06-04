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

class Result:
    """The FuzzingTool result handler

    Attributes:
        index: The index of the result (same as the request index)
        payload: The payload used in the request
        url: The requested target URL
        method: The method used in the request
        RTT: The elapsed time on both request and response
        requestTime: The elapsed time only for the request
        responseTime: The elapsed time only for the response
        status: The response HTTP status code
        length: The length of the response body content
        words: The quantitty of words in the response body
        lines: The quantity of lines in the response body
        custom: A dictionary to store custom data from the plugins
        response: The raw response object
    """
    def __init__(self,
        response: object,
        RTT: float,
        requestIndex: int = 0,
        payload: str = '',
    ):
        """Class constructor

        @type response: Response
        @param response: The response given in the reuest
        @type RTT: float
        @param RTT: The elapsed time on both request and response
        @type requestIndex: int
        @param requestIndex: The index of the request
        @type payload: str
        @param payload: The payload used in the request
        """
        self.index = str(requestIndex)
        self.payload = payload
        self.url = response.url
        self.method = response.request.method
        self.RTT = float('%.6f'%(RTT))
        responseTime = response.elapsed.total_seconds()
        self.requestTime = float('%.6f'%(RTT-responseTime))
        self.responseTime = responseTime
        self.status = response.status_code
        content = response.content
        self.length = response.headers.get('Content-Length')
        if self.length == None:
            self.length = len(content)
        self.words = len(content.split())
        self.lines = content.count(b'\n')
        self._custom = {}
        self.__response = response
    
    def __iter__(self):
       yield 'index', self.index
       yield 'payload', self.payload
       yield 'url', self.url
       yield 'method', self.method
       yield 'RTT', self.RTT
       yield 'requestTime', self.requestTime
       yield 'responseTime', self.responseTime
       yield 'status', self.status
       yield 'length', self.length
       yield 'words', self.words
       yield 'lines', self.lines
       for key, value in self._custom.items():
           yield key, value

    def getResponse(self):
        """The response getter

        @returns Response: The response of the request
        """
        return self.__response