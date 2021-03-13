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
    """
    def __init__(self, response: object):
        """Class constructor

        @type response: object
        @param response: The response of a request
        """
        self.__response = response

    def getResponseDict(self):
        """Get the response data parsed into a dictionary"""
        responseDict = {
            'Request': str(self.requestIndex),
            'Payload': self.payload,
            'Time Taken': self.RTT,
            'Request Time': float('%.6f'%(self.RTT-self.elapsedTime)),
            'Response Time': self.elapsedTime,
            'Status': self.status,
            'Length': self.length,
            'Words': self.quantityOfWords,
            'Lines': self.quantityOfLines,
        }
        if self.targetIp:
            responseDict['IP'] = self.targetIp
        return responseDict
    
    def setRequestData(self, payload: str, timeTaken: float, requestIndex: int, ip: str):
        """Set the request data to be used into the dictionary

        @type payload: str
        @param payload: The payload used in the request
        @type timeTaken: float
        @param timeTaken: The time taken after make the request
        @type requestIndex: int
        @param requestIndex: The request index
        @type ip: str
        @param ip: The target IP
        @returns dict: The response data parsed into a dictionary
        """
        self.payload = payload
        self.RTT = float('%.6f'%(timeTaken))
        self.requestIndex = requestIndex
        self.targetIp = ip

    def loadResponseData(self):
        """Loads the response data"""
        self.content = self.__response.content
        self.length = self.__response.headers.get('Content-Length')
        if self.length == None:
            self.length = len(self.content)
        self.elapsedTime = self.__response.elapsed.total_seconds()
        self.status = self.__response.status_code
        self.quantityOfWords = len(self.content.split())
        self.quantityOfLines = self.content.count(b'\n')