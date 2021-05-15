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

from ..BaseEncoder import BaseEncoder

from urllib.parse import quote, unquote

class Url(BaseEncoder):
    __name__ = "Url"
    __author__ = ("Vitor Oriel C N Borges")
    __params__ = "ENCODE_LEVEL"
    __desc__ = "Replace special characters in string using the %xx escape. Letters, digits, and the characters '_.-~' are never quoted."
    __type__ = "DataFuzzing"

    def __init__(self, encodeLevel: int):
        super().__init__()
        if not encodeLevel:
            encodeLevel = 1
        else:
            try:
                encodeLevel = int(encodeLevel)
            except:
                raise Exception("the encoding level must be an integer")
        self.encodeLevel = encodeLevel

    def encode(self, payload: str):
        return self.__recursivelyEncode(payload, self.encodeLevel)

    def decode(self, payload: str):
        return self.__recursivelyDecode(payload, self.encodeLevel)
    
    def __recursivelyEncode(self, payload: str, i: int):
        """Recursively encode the payload

        @type payload: str
        @param payload: The payload used in the request
        @type i: int
        @param i: The actual encoding level
        @returns str: The encoded payload
        """
        if i == 0:
            return payload
        return self.__recursivelyEncode(quote(payload), (i-1))
    
    def __recursivelyDecode(self, payload: str, i: int):
        """Recursively decode the payload

        @type payload: str
        @param payload: The payload used in the request
        @type i: int
        @param i: The actual decoding level
        @returns str: The decoded payload
        """
        if i == 0:
            return payload
        return self.__recursivelyDecode(unquote(payload), (i-1))