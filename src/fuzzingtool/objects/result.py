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

from typing import Iterator, Tuple

from requests import Response

from .base_objects import BaseItem
from .payload import Payload


class Result(BaseItem):
    """The FuzzingTool result object

    Attributes:
        payload: The string payload used in the request
        url: The requested target URL
        method: The method used in the request
        rtt: The elapsed time on both request and response
        request_time: The elapsed time only for the request
        response_time: The elapsed time only for the response
        status: The response HTTP status code
        length: The length of the response body content
        words: The quantitty of words in the response body
        lines: The quantity of lines in the response body
        custom: A dictionary to store custom data from the scanners
        _payload: The Payload object
        response: The Response object from python requests
    """
    def __init__(self,
                 response: Response,
                 rtt: float = 0.0,
                 payload: Payload = Payload()):
        """Class constructor

        @type response: Response
        @param response: The response given in the request
        @type rtt: float
        @param rtt: The elapsed time on both request and response
        @type request_index: int
        @param request_index: The index of the request
        @type payload: Payload
        @param payload: The payload used in the request
        """
        super().__init__()
        self.payload = payload.final
        self.url = response.url
        self.method = response.request.method
        self.rtt = float('%.6f' % (rtt))
        response_time = response.elapsed.total_seconds()
        self.request_time = float('%.6f' % (rtt-response_time))
        self.response_time = response_time
        self.status = response.status_code
        content = response.content
        self.length = len(content)
        self.words = len(content.split())
        self.lines = content.count(b'\n')
        self.custom = {}
        self._payload = payload
        self.__response = response

    def __iter__(self) -> Iterator[Tuple]:
        yield 'index', self.index
        yield 'url', self.url
        yield 'method', self.method
        yield 'rtt', self.rtt
        yield 'request_time', self.request_time
        yield 'response_time', self.response_time
        yield 'status', self.status
        yield 'length', self.length
        yield 'words', self.words
        yield 'lines', self.lines
        for key, value in self.custom.items():
            yield key, value
        yield 'payload', self.payload
        yield 'payload_raw', self._payload.raw
        for key, value in self._payload.config.items():
            yield f"payload_{key}", value

    def get_response(self) -> Response:
        """The response getter

        @returns Response: The response of the request
        """
        return self.__response
