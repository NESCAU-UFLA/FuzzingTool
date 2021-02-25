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
        self.__getResponseHeaders()
        responseDict = {
            'Request': str(self.__requestIndex),
            'Payload': self.__payload,
            'Time Taken': self.__RTT,
            'Request Time': float('%.6f'%(self.__RTT-self.__elapsedTime)),
            'Response Time': self.__elapsedTime,
            'Status': self.__status,
            'Length': self.__length,
            'Words': self.__quantityOfWords,
            'Lines': self.__quantityOfLines,
        }
        if self.__targetIp:
            responseDict['IP'] = self.__targetIp
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
        self.__payload = payload
        self.__RTT = float('%.6f'%(timeTaken))
        self.__requestIndex = requestIndex
        self.__targetIp = ip
    
    def __getResponseHeaders(self):
        """Get the response data"""
        responseContent = self.__response.content
        self.__length = self.__response.headers.get('Content-Length')
        if (self.__length == None):
            self.__length = len(responseContent)
        self.__elapsedTime = self.__response.elapsed.total_seconds()
        self.__status = self.__response.status_code
        self.__quantityOfWords = len(responseContent.split())
        self.__quantityOfLines = responseContent.count(b'\n')