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

from urllib.parse import quote, unquote

from ...bases.base_plugin import Plugin
from ...bases.base_encoder import BaseEncoder
from ....decorators.plugin_meta import plugin_meta
from ....exceptions.main_exceptions import BadArgumentFormat


@plugin_meta
class Url(BaseEncoder, Plugin):
    __author__ = ("Vitor Oriel",)
    __params__ = {
        'metavar': "ENCODE_LEVEL",
        'type': str,
    }
    __desc__ = "Replace special characters in string using the %xx escape. Letters, digits, and the characters '_.-~' are never quoted."
    __type__ = ''
    __version__ = "0.2"

    def __init__(self, encode_level: int):
        if not encode_level:
            encode_level = 1
        else:
            try:
                encode_level = int(encode_level)
            except ValueError:
                raise BadArgumentFormat("the encoding level must be an integer")
        self.encode_level = encode_level

    def encode(self, payload: str) -> str:
        encoded = payload
        for _ in range(self.encode_level):
            encoded = quote(encoded)
        return encoded

    def decode(self, payload: str) -> str:
        decoded = payload
        for _ in range(self.encode_level):
            decoded = unquote(decoded)
        return decoded
