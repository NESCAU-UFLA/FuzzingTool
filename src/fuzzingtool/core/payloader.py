# Copyright (c) 2020 - present Vitor Oriel <https://github.com/VitorOriel>
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

import re
from typing import List, Tuple

from .bases.base_encoder import BaseEncoder
from .defaults.encoders import ChainEncoder


class EncodeManager:
    """Class that handle with the encoder management

    Attributes:
        encoders: The encoders used in the program
        regexer: The object to handle with the encoding based on a regex
    """
    def __init__(self):
        self.encoders = []
        self.encode = lambda ajusted_payload: ajusted_payload
        self.regexer = None

    def __len__(self) -> int:
        return len(self.encoders)

    def set_regex(self, regex: str = '') -> None:
        """The regexer setter

        @type regex: str
        @param regex: The regular expression to set
        """
        try:
            self.regexer = re.compile(regex, re.IGNORECASE)
        except re.error:
            raise Exception(f"Invalid regex format {regex}")

    def set_encoders(self,
                     encoders: Tuple[
                         List[BaseEncoder], List[List[BaseEncoder]]
                     ]) -> None:
        """The encoders setter

        @type encoders: Tuple[list, list]
        @param encoders: The encoders used in the payloads
        """
        def encode(ajusted_payload: List[str]) -> List[str]:
            """The encode callback for the payloads

            @type ajusted_payload: List[str]
            @param ajusted_payload: The payload list ajusted previously
            @returns List[str]: The encoded payloads list
            """
            encoded_list = []
            for payload in ajusted_payload:
                for encoder in self.encoders:
                    encoded_list.append(self._encode(encoder, payload))
            return encoded_list

        encoders_default, encoders_chain = encoders
        self.encoders = encoders_default+[ChainEncoder(encoders)
                                          for encoders in encoders_chain]
        self.encode = encode

    def _encode(self, encoder: BaseEncoder, payload: str) -> str:
        """Encode a payload into an specific encoding type

        @type encoder: BaseEncoder
        @param encoder: The encoder used to encode the payload
        @type payload: str
        @param payload: The payload used in the request
        @returns str: The encoded payload
        """
        def encode_substring(
            encoder: BaseEncoder,
            payload: str,
            i: int,
            strings: list
        ) -> Tuple[int, str]:
            """Encode a substring using the actual encoder

            @type encoder: BaseEncoder
            @param encoder: The encoder used to encode the payload
            @type payload: str
            @param payload: The payload used in the request
            @type i: int
            @param i: The index of the actual char of the payload
            @type strings: list
            @param strings: The matched strings list from the regexer
            @returns Tuple[int, str]: The encoded substring if match
                                      the regex, else return the actual char
            """
            for string in strings:
                last_index = i+len(string)
                to_check = payload[i:last_index]
                if to_check == string:
                    return (last_index, encoder.encode(to_check))
            return ((i+1), payload[i])

        if not self.regexer:
            return encoder.encode(payload)
        strings = set([match.group()
                       for match in self.regexer.finditer(payload)])
        if not strings:
            return payload
        encoded = ''
        i = 0
        while i < len(payload):
            i, char = encode_substring(encoder, payload, i, strings)
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
    _case = lambda ajusted_payload: ajusted_payload

    @staticmethod
    def set_prefix(prefix: List[str]) -> None:
        """The prefix setter

        @type prefix: List[str]
        @param prefix: The prefix used in the payload
        """
        Payloader.prefix = prefix

    @staticmethod
    def set_suffix(suffix: List[str]) -> None:
        """The suffix setter

        @type suffix: List[str]
        @param suffix: The suffix used in the payload
        """
        Payloader.suffix = suffix

    @staticmethod
    def set_uppercase() -> None:
        """The uppercase setter"""
        Payloader._case = lambda ajusted_payload: [
            payload.upper() for payload in ajusted_payload
        ]

    @staticmethod
    def set_lowercase() -> None:
        """The lowercase setter"""
        Payloader._case = lambda ajusted_payload: [
            payload.lower() for payload in ajusted_payload
        ]

    @staticmethod
    def set_capitalize() -> None:
        """The capitalize setter"""
        Payloader._case = lambda ajusted_payload: [
            payload.capitalize() for payload in ajusted_payload
        ]

    @staticmethod
    def get_customized_payload(payload: str) -> List[str]:
        """Gets the payload list ajusted with the console options

        @type payload: str
        @param payload: The string payload gived by the payloads queue
        @returns List[str]: The payloads used in the request
        """
        ajusted_payload = [payload]
        if Payloader.prefix:
            ajusted_payload = [(prefix+payload)
                               for prefix in Payloader.prefix
                               for payload in ajusted_payload]
        if Payloader.suffix:
            ajusted_payload = [(payload+suffix)
                               for suffix in Payloader.suffix
                               for payload in ajusted_payload]
        return Payloader._case(Payloader.encoder.encode(ajusted_payload))