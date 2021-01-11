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

    def getResponseData(self, payload: str, timeTaken: float, requestIndex: int):
        """Get the response data parsed into a dictionary

        @type payload: str
        @param payload: The payload used in the request
        @type timeTaken: float
        @param timeTaken: The time taken after make the request
        @type requestIndex: int
        @param requestIndex: The request index
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
        return responseData