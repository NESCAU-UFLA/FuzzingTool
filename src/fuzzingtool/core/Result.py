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
    """
    def __init__(self,
        response: object,
        requestIndex: int,
        payload: str,
        RTT: float,
    ):
        self.index = str(requestIndex)
        self.url = response.url
        self.method = response.request.method
        self.payload = payload
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
       yield 'url', self.url
       yield 'method', self.method
       yield 'payload', self.payload
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