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

from ..utils.utils import splitStrToList
from ..utils.FileHandler import fileHandler as fh

from collections import deque

class ArgumentBuilder:
    @staticmethod
    def buildTargetsFromArgs(urls: list, method: str, data: str):
        """Build the targets from arguments

        @type urls: list
        @param urls: The target URLs
        @type method: str
        @param method: The request methods
        @type data: str
        @param data: The raw request body data
        @returns dict: The targets data builded into a dictionary
        """
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
    def buildTargetsFromRawHttp(rawHttpFilenames: list, scheme: str):
        """Build the targets from raw http files

        @type rawHttpFilenames: list
        @param rawHttpFilenames: The list with the raw http filenames
        @type scheme: str
        @param scheme: The scheme used in the URL
        @returns dict: The targets data builded into a dictionary
        """
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
        for rawHttpFilename in rawHttpFilenames:
            try:
                headerList = deque(fh.read(rawHttpFilename))
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
        """Build the prefix or suffix arguments

        @type string: str
        @param string: The prefix or suffix argument
        @returns list: The string parsed into a list
        """
        return splitStrToList(string)

    @staticmethod
    def buildBlacklistStatus(status: str):
        """Build the blacklisted status codes

        @type status: str
        @param status: The blacklisted status codes
        @returns list: The parsed blacklisted status codes
        """
        try:
            return [int(status) for status in splitStrToList(status)]
        except:
            raise Exception("Status code must be an integer")

    @staticmethod
    def buildMatcherAllowedStatus(allowedStatus: str):
        """Build the matcher attribute for allowed status

        @type allowedStatus: str
        @param allowedStatus: The allowed status codes to match results
        @returns dict: The allowed status code, list and range, parsed into a dict
        """
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
        """Build the matcher attribute for data comparator

        @type length: int
        @param length: The length attribute for match results
        @type time: float
        @param time: The time attribute for match results
        @returns dict: The data comparators parsed into a dict
        """
        return {
            'Length': None if not length else length,
            'Time': None if not time else time,
        }