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

class Payloader:
    """Class that handle with the payload options

    Attributes:
        encoder: The encoder used in the payload
        prefix: The prefix used in the payload
        suffix: The suffix used in the payload
    """
    def __init__(self):
        self.encoders = {
            'default': [],
            'chain': [],
        }
        self._prefix = []
        self._suffix = []
        self.__case = lambda ajustedPayload : ajustedPayload
        self.__encode = lambda ajustedPayload : ajustedPayload

    def setPrefix(self, prefix: list):
        """The prefix setter

        @type prefix: list
        @param prefix: The prefix used in the payload
        """
        self._prefix = prefix
    
    def setSuffix(self, suffix: list):
        """The suffix setter

        @type suffix: list
        @param suffix: The suffix used in the payload
        """
        self._suffix = suffix

    def setUppercase(self):
        """The uppercase setter"""
        self.__case = lambda ajustedPayload : [payload.upper() for payload in ajustedPayload]
    
    def setLowercase(self):
        """The lowercase setter"""
        self.__case = lambda ajustedPayload : [payload.lower() for payload in ajustedPayload]

    def setCapitalize(self):
        """The capitalize setter"""
        self.__case = lambda ajustedPayload : [payload.capitalize() for payload in ajustedPayload]

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
                for encoder in self.encoders['default']:
                    encodedList.append(encoder.encode(payload))
                for encoder in self.encoders['chain']:
                    encodedPayloadWithChain = payload
                    for e in encoder:
                        encodedPayloadWithChain = e.encode(encodedPayloadWithChain)
                    encodedList.append(encodedPayloadWithChain)
            return encodedList
        
        encodersDefault, encodersChain = encoders
        self.encoders = {
            'default': encodersDefault,
            'chain': encodersChain,
        }
        self.__encode = encode

    def _getCustomizedPayload(self, payload: str):
        """Gets the payload list ajusted with the console options

        @type payload: str
        @param payload: The string payload gived by the payloads queue
        @returns list: The payloads used in the request
        """
        ajustedPayload = [payload]
        if self._prefix:
            ajustedPayload = [(prefix+payload) for prefix in self._prefix for payload in ajustedPayload]
        if self._suffix:
            ajustedPayload = [(payload+suffix) for suffix in self._suffix for payload in ajustedPayload]
        return self.__case(self.__encode(ajustedPayload))