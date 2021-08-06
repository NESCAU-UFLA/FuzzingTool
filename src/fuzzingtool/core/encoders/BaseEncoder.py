# Copyright (c) 2021 Vitor Oriel <https://github.com/VitorOriel>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from abc import ABC, abstractmethod
import re

class BaseEncoder(ABC):
    charset = 'utf-8'
    regexer = None

    @staticmethod
    def setRegex(regex: str = ''):
        try:
            BaseEncoder.regexer = re.compile(regex, re.IGNORECASE)
        except re.error:
            raise Exception(f"Invalid regex format {regex}")

    def encode(self, payload: str):
        """Encode a payload into an specific encoding type

        @type payload: str
        @param payload: The payload used in the request
        @returns str: The encoded payload
        """
        def encodeSubstring(payload: str, i: int, strings: list):
            for string in strings:
                lastIndex = i+len(string)
                toCheck = payload[i:lastIndex]
                if toCheck == string:
                    return (lastIndex, self._encode(toCheck))
            return ((i+1), payload[i])

        if not BaseEncoder.regexer:
            return self._encode(payload)
        strings = set([match.group() for match in BaseEncoder.regexer.finditer(payload)])
        if not strings:
            return payload
        encoded = ''
        i = 0
        while i < len(payload):
            i, char = encodeSubstring(payload, i, strings)
            encoded += char
        return encoded

    @abstractmethod
    def _encode(self, payload: str):
        """Encode a payload into an specific encoding type

        @type payload: str
        @param payload: The payload used in the request
        @returns str: The encoded payload
        """
        pass