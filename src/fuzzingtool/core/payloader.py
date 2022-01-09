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
from ..objects.payload import Payload
from ..exceptions.main_exceptions import BadArgumentFormat


class EncodeManager:
    """Class that handle with the encoder management

    Attributes:
        encoders: The encoders used in the program
        regexer: The object to handle with the encoding based on a regex
    """
    def __init__(self):
        self.encoders = []
        self.regexer = None

    def __len__(self) -> int:
        return len(self.encoders)

    def encode(self, ajusted_payloads: List[Payload]) -> List[Payload]:
        """The encode callback for the payloads

        @type ajusted_payloads: List[Payload]
        @param ajusted_payloads: The payload list ajusted previously
        @returns List[Payload]: The encoded payloads list
        """
        return ajusted_payloads

    def set_regex(self, regex: str = '') -> None:
        """The regexer setter

        @type regex: str
        @param regex: The regular expression to set
        """
        try:
            self.regexer = re.compile(regex, re.IGNORECASE)
        except re.error:
            raise BadArgumentFormat(f"Invalid regex format {regex}")

    def set_encoders(self,
                     encoders: Tuple[
                         List[BaseEncoder], List[List[BaseEncoder]]
                     ]) -> None:
        """The encoders setter

        @type encoders: Tuple[list, list]
        @param encoders: The encoders used in the payloads
        """
        def encode(ajusted_payloads: List[Payload]) -> List[Payload]:
            return [
                Payload().update(payload).with_encoder(self._encode(encoder, payload.final), str(encoder))
                for encoder in self.encoders
                for payload in ajusted_payloads
            ]

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
            m_strings: set
        ) -> Tuple[int, str]:
            """Encode a substring using the actual encoder

            @type encoder: BaseEncoder
            @param encoder: The encoder used to encode the payload
            @type payload: str
            @param payload: The payload used in the request
            @type i: int
            @param i: The index of the actual char of the payload
            @type m_strings: set
            @param m_strings: The matched strings list from the regexer
            @returns Tuple[int, str]: The encoded substring if match
                                      the regex, else return the actual char
            """
            for string in m_strings:
                last_index = i+len(string)
                to_check = payload[i:last_index]
                if to_check == string:
                    return (last_index, encoder.encode(to_check))
            return ((i+1), payload[i])

        if not self.regexer:
            return encoder.encode(payload)
        m_strings = set([match.group()
                         for match in self.regexer.finditer(payload)])
        if not m_strings:
            return payload
        encoded = ''
        i = 0
        while i < len(payload):
            i, char = encode_substring(encoder, payload, i, m_strings)
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

    @staticmethod
    def case(ajusted_payloads: List[Payload]) -> List[Payload]:
        """Update the case letter

        @type ajusted_payloads: List[Payload]
        @param ajusted_payloads: The payload list ajusted previously
        @returns List[Payload]: The new payloads list
        """
        return ajusted_payloads

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
        def case(ajusted_payloads: List[Payload]) -> List[Payload]:
            return [
                payload.with_case(str.upper, "Upper")
                for payload in ajusted_payloads
            ]

        Payloader.case = case

    @staticmethod
    def set_lowercase() -> None:
        """The lowercase setter"""
        def case(ajusted_payloads: List[Payload]) -> List[Payload]:
            return [
                payload.with_case(str.lower, "Lower")
                for payload in ajusted_payloads
            ]

        Payloader.case = case

    @staticmethod
    def set_capitalize() -> None:
        """The capitalize setter"""
        def case(ajusted_payloads: List[Payload]) -> List[Payload]:
            return [
                payload.with_case(str.capitalize, "Capitalize")
                for payload in ajusted_payloads
            ]

        Payloader.case = case

    @staticmethod
    def get_customized_payload(payload: str) -> List[Payload]:
        """Gets the payload list ajusted with the console options

        @type payload: str
        @param payload: The string payload gived by the payloads queue
        @returns List[Payload]: The payloads used in the request
        """
        ajusted_payloads = [Payload(payload)]
        if Payloader.prefix:
            ajusted_payloads = [Payload().update(payload).with_prefix(prefix)
                                for prefix in Payloader.prefix
                                for payload in ajusted_payloads]
        if Payloader.suffix:
            ajusted_payloads = [Payload().update(payload).with_suffix(suffix)
                                for suffix in Payloader.suffix
                                for payload in ajusted_payloads]
        return Payloader.case(Payloader.encoder.encode(ajusted_payloads))
