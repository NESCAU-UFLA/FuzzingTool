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

from typing import Callable


class Payload:
    """Class to represent a Payload

    Attributes:
        raw: The payload before the mutation
        final: The payloa after the mutation
        config: The config of the payload mutation
    """
    def __init__(self, payload: str = ''):
        """Class constructor

        @type payload: str
        @param payload: The payload that'll be mutated
        """
        self.raw = payload
        self.final = payload
        self.config = {}

    def __str__(self) -> str:
        return self.final

    def update(self, other: object) -> object:
        """Update the base payload from another payload

        @type other: Payload
        @param other: The previous payload that'll update the next one
        @returns Payload: The updated payload
        """
        self.raw = other.raw
        self.final = other.final
        self.config = {key: value for key, value in other.config.items()}
        return self

    def with_prefix(self, prefix: str) -> object:
        """Build the payload with prefix

        @type prefix: str
        @param prefix: The prefix used in the payload
        @returns Payload: The updated payload
        """
        self.config['prefix'] = prefix
        self.final = prefix + self.final
        return self

    def with_suffix(self, suffix: str) -> object:
        """Build the payload with suffix

        @type suffix: str
        @param suffix: The suffix used in the payload
        @returns Payload: The updated payload
        """
        self.config['suffix'] = suffix
        self.final += suffix
        return self

    def with_case(self, case_callback: Callable, case_method: str) -> object:
        """Build the payload with case (upper, lower, cap)

        @type case_callback: Callable
        @param case_callback: The callback for the string case
        @type case_method: str
        @param case_method: The method of the case
        @returns Payload: The updated payload
        """
        self.config['case'] = case_method
        self.final = case_callback(self.final)
        return self

    def with_encoder(self, encoded: str, encoder: str) -> object:
        """Build the payload with an encoder

        @type encoded: str
        @param encoded: The encoded payload
        @type encoder: str
        @param encoder: The encoder name
        @returns Payload: The updated payload
        """
        self.config['encoder'] = encoder
        self.final = encoded
        return self
