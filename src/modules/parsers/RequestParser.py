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
    def __init__(self, url: dict, httpHeader: dict, method: str = '', param: dict = {}):
        self.__url = url
        self.__method = method
        self.__param = param
        self.__httpHeader = httpHeader
        self.__payload = ''

    def getUrl(self):
        return self.__url['content'] if not self.__url['indexToParse'] else self.__getAjustedUrl(self.__payload)

    def getHeader(self):
        return self.__httpHeader['content'] if not self.__httpHeader['keysCustom'] else self.__getAjustedHeader()

    def getData(self):
        return {} if not self.__param else self.__getAjustedData(self.__payload)

    def setPayload(self, payload: str):
        self.__payload = payload

    def getTargetFromUrl(self):
        """Gets the host from an URL

        @returns str: The target url
        """
        url = self.__url['content']
        if self.__url['indexToParse']:
            return url[:self.__url['indexToParse'][0]]
        return url

    def __parseHeaderValue(self, value: str):
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
        print('aaaaaaaaaaa')
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