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

from .encoders import *

import re

class EncodeManager:
    """Class that handle with the encoder management

    Attributes:
        encoders: The encoders used in the program
    """
    def __init__(self):
        self.encoders = []
        self.encode = lambda ajustedPayload : ajustedPayload
        self.regexer = None
    
    def __len__(self):
        return len(self.encoders)

    def setRegex(self, regex: str = ''):
        """The regex setter

        @type regex: str
        @param regex: The regular expression to set
        """
        try:
            self.regexer = re.compile(regex, re.IGNORECASE)
        except re.error:
            raise Exception(f"Invalid regex format {regex}")

    def setEncoders(self, encoders: tuple):
        """The encoders setter

        @type encoders: tuple(list, list)
        @param encoders: The encoders used in the payloads
        """
        def encode(ajustedPayload: list):
            """The encode callback for the payloads

            @type ajustedPayload: list
            @param ajustedPayload: The payload list ajusted previously
            @returns list: The encoded payloads list
            """
            encodedList = []
            for payload in ajustedPayload:
                for encoder in self.encoders:
                    encodedList.append(self._encode(encoder, payload))
            return encodedList

        encodersDefault, encodersChain = encoders
        self.encoders = encodersDefault+[ChainEncoder(encoders) for encoders in encodersChain]
        self.encode = encode

    def _encode(self, encoder: BaseEncoder, payload: str):
        """Encode a payload into an specific encoding type

        @type encoder: BaseEncoder
        @param encoder: The encoder used to encode the payload
        @type payload: str
        @param payload: The payload used in the request
        @returns str: The encoded payload
        """
        def encodeSubstring(
            encoder: BaseEncoder,
            payload: str,
            i: int,
            strings: list
        ):
            """Encode a substring using the actual encoder

            @type encoder: BaseEncoder
            @param encoder: The encoder used to encode the payload
            @type payload: str
            @param payload: The payload used in the request
            @type i: int
            @param i: The index of the actual char of the payload
            @type strings: list
            @param strings: The matched strings list from the regexer
            @returns tuple(int, str): The encoded substring if match the regex, else return the actual char
            """
            for string in strings:
                lastIndex = i+len(string)
                toCheck = payload[i:lastIndex]
                if toCheck == string:
                    return (lastIndex, encoder.encode(toCheck))
            return ((i+1), payload[i])

        if not self.regexer:
            return encoder.encode(payload)
        strings = set([match.group() for match in self.regexer.finditer(payload)])
        if not strings:
            return payload
        encoded = ''
        i = 0
        while i < len(payload):
            i, char = encodeSubstring(encoder, payload, i, strings)
            encoded += char
        return encoded

class Payloader:
    """Class that handle with the payload options

    Attributes:
        prefix: The prefix used in the payload
        suffix: The suffix used in the payload
        encoder: The encoder used in the payload
    """
    prefix = []
    suffix = []
    encoder = EncodeManager()
    _case = lambda ajustedPayload : ajustedPayload

    @staticmethod
    def setPrefix(prefix: list):
        """The prefix setter

        @type prefix: list
        @param prefix: The prefix used in the payload
        """
        Payloader.prefix = prefix
    
    @staticmethod
    def setSuffix(suffix: list):
        """The suffix setter

        @type suffix: list
        @param suffix: The suffix used in the payload
        """
        Payloader.suffix = suffix

    @staticmethod
    def setUppercase():
        """The uppercase setter"""
        Payloader._case = lambda ajustedPayload : [payload.upper() for payload in ajustedPayload]
    
    @staticmethod
    def setLowercase():
        """The lowercase setter"""
        Payloader._case = lambda ajustedPayload : [payload.lower() for payload in ajustedPayload]

    @staticmethod
    def setCapitalize():
        """The capitalize setter"""
        Payloader._case = lambda ajustedPayload : [payload.capitalize() for payload in ajustedPayload]

    @staticmethod
    def getCustomizedPayload(payload: str):
        """Gets the payload list ajusted with the console options

        @type payload: str
        @param payload: The string payload gived by the payloads queue
        @returns list: The payloads used in the request
        """
        ajustedPayload = [payload]
        if Payloader.prefix:
            ajustedPayload = [(prefix+payload) for prefix in Payloader.prefix for payload in ajustedPayload]
        if Payloader.suffix:
            ajustedPayload = [(payload+suffix) for suffix in Payloader.suffix for payload in ajustedPayload]
        return Payloader._case(Payloader.encoder.encode(ajustedPayload))