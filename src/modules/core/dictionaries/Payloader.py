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

import binascii
import html

class Payloader:
    """Class that handle with the payload options

    Attributes:
        prefix: The prefix used in the payload
        suffix: The suffix used in the payload
    """
    def __init__(self):
        """Class constructor"""
        self.__prefix = []
        self.__suffix = []
        self.__case = lambda ajustedPayload : ajustedPayload
        self.__encode = lambda ajustedPayload : ajustedPayload

    def setPrefix(self, prefix: list):
        """The prefix setter

        @type prefix: list
        @param prefix: The prefix used in the payload
        """
        self.__prefix = prefix
    
    def setSuffix(self, suffix: list):
        """The suffix setter

        @type suffix: list
        @param suffix: The suffix used in the payload
        """
        self.__suffix = suffix

    def setUppecase(self):
        """The uppercase setter"""
        self.__case = lambda ajustedPayload : [payload.upper() for payload in ajustedPayload]
    
    def setLowercase(self):
        """The lowercase setter"""
        self.__case = lambda ajustedPayload : [payload.lower() for payload in ajustedPayload]

    def setCapitalize(self):
        """The capitalize setter"""
        self.__case = lambda ajustedPayload : [payload.capitalize() for payload in ajustedPayload]
    
    def setBin(self):
        """The binary encoding"""
        self.__encode = lambda ajustedPayload : [bytearray(payload, 'utf-8') for payload in ajustedPayload]
    
    def setHex(self):
        """The hexadecimal encoding"""
        self.__encode = lambda ajustedPayload : [binascii.hexlify(bytearray(payload, 'utf-8')) for payload in ajustedPayload]

    def setHtmlentity(self):
        """The html entities escaping"""
        self.__encode = lambda ajustedPayload : [html.escape(payload) for payload in ajustedPayload]

    def _getCustomizedPayload(self, payload: str):
        """Gets the payload list ajusted with the console options

        @type payload: str
        @param payload: The string payload gived by the payloads queue
        @returns list: The payloads used in the request
        """
        ajustedPayload = [payload]
        if self.__prefix:
            ajustedPayload = [(prefix+payload) for prefix in self.__prefix for payload in ajustedPayload]
        if self.__suffix:
            ajustedPayload = [(payload+suffix) for suffix in self.__suffix for payload in ajustedPayload]
        return self.__encode(self.__case(ajustedPayload))