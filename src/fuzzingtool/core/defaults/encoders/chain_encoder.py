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

from typing import List

from ...bases.base_encoder import BaseEncoder


class ChainEncoder(BaseEncoder):
    """Class that handle with the chain encoders

    Attributes:
        encoders: The encoders list to be chained
    """
    def __init__(self, encoders: List[BaseEncoder]):
        """Class constructor

        @type encoders: List[BaseEncoder]
        @param encoders: The encoders list to be chained
        """
        self.__encoders = encoders
        self.__str_repr = '@'.join(str(encoder) for encoder in encoders)

    def __str__(self) -> str:
        return self.__str_repr

    def getEncoders(self) -> List[BaseEncoder]:
        """The encoders list getter

        @return List[BaseEncoder]: The encoders list
        """
        return self.__encoders

    def encode(self, payload: str) -> str:
        encoded = payload
        for encoder in self.__encoders:
            encoded = encoder.encode(encoded)
        return encoded
