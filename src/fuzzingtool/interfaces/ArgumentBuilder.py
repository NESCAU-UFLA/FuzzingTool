from ..utils.utils import splitStrToList
from ..utils.FileHandler import fileHandler as fh

from collections import deque

class ArgumentBuilder:
    @staticmethod
    def buildTargetsFromArgs(urls: list, method: str, data: str):
        methods = splitStrToList(method)
        targets = []
        for url in urls:
            if not methods:
                if data and not ('?' in url or '$' in url):
                    methods = ['POST']
                else:
                    methods = ['GET']
            targets.append({
                'url': url,
                'methods': methods,
                'data': data,
                'header': {},
            })
        return targets

    @staticmethod
    def buildTargetsFromRawHttp(headerFilenames: list, scheme: str):
        def buildHeaderFromRawHttp(headerList: list):
            """Get the HTTP header

            @tyoe headerList: list
            @param headerList: The list with HTTP header
            @returns dict: The HTTP header parsed into a dict
            """
            headers = {}
            i = 0
            thisHeader = headerList.popleft()
            headerLength = len(headerList)
            while i < headerLength and thisHeader != '':
                key, value = thisHeader.split(': ', 1)
                headers[key] = value
                thisHeader = headerList.popleft()
                i += 1
            return headers
        
        targets = []
        for headerFilename in headerFilenames:
            try:
                headerList = deque(fh.read(headerFilename))
            except Exception as e:
                raise Exception(str(e))
            method, path, httpVer = headerList.popleft().split(' ')
            methods = splitStrToList(method)
            headers = buildHeaderFromRawHttp(headerList)
            url = f"{scheme}://{headers['Host']}{path}"
            if len(headerList) > 0:
                data = headerList.popleft()
            else:
                data = ''
            targets.append({
                'url': url,
                'methods': methods,
                'data': data,
                'header': headers,
            })
        return targets

    @staticmethod
    def buildPrefixSuffix(string: str):
        return splitStrToList(string)

    @staticmethod
    def buildBlacklistStatus(status: str):
        try:
            return [int(status) for status in splitStrToList(status)]
        except:
            raise Exception("Status code must be an integer")

    @staticmethod
    def buildMatcherAllowedStatus(allowedStatus: str):
        def getAllowedStatus(status: str, allowedList: list, allowedRange: list):
            """Get the allowed status code list and range

            @type status: str
            @param status: The status cod given in the terminal
            @type allowedList: list
            @param allowedList: The allowed status codes list
            @type allowedRange: list
            @param allowedRange: The range of allowed status codes
            """
            try:
                if '-' not in status:
                    allowedList.append(int(status))
                else:
                    codeLeft, codeRight = (int(code) for code in status.split('-', 1))
                    if codeRight < codeLeft:
                        codeLeft, codeRight = codeRight, codeLeft
                    allowedRange[:] = [codeLeft, codeRight]
            except:
                raise Exception(f"The match status argument ({status}) must be integer")

        allowedList = []
        allowedRange = []
        for status in splitStrToList(allowedStatus):
            getAllowedStatus(status, allowedList, allowedRange)
        return {
            'List': allowedList,
            'Range': allowedRange,
        }

    @staticmethod
    def buildMatcherComparator(length: int, time: float):
        return {
            'Length': None if not length else length,
            'Time': None if not time else time,
        }