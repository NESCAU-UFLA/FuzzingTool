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

    def __getResponseTimeAndLength(self):
        """Get the response time and length

        @type response: object
        @param response: The Response object
        @rtype: tuple(float, int)
        @returns (responseTime, responseLength): The response time and length
        """
        responseLength = self.__response.headers.get('Content-Length')
        if (responseLength == None):
            responseLength = len(self.__response.content)
        return (self.__response.elapsed.total_seconds(), responseLength)

    def getResponseData(self, payload: str, timeTaken: float, requestIndex: int, ip: str):
        """Get the response data parsed into a dictionary

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
        responseTime, responseLength = self.__getResponseTimeAndLength()
        responseStatus = self.__response.status_code
        responseData = {
            'Request': str(requestIndex),
            'Req Time': float('%.6f'%(timeTaken-responseTime)),
            'Payload': payload,
            'Status': responseStatus,
            'Length': responseLength,
            'Resp Time': responseTime,
        }
        if ip:
            responseData['IP'] = ip
        return responseData