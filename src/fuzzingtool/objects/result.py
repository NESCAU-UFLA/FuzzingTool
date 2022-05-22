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

from typing import Iterator, Tuple, Dict

from .base_objects import BaseItem
from .http_history import HttpHistory
from .payload import Payload
from .scanner_result import ScannerResult
from ..utils.consts import FuzzType, MAX_PAYLOAD_LENGTH_TO_OUTPUT
from ..utils.result_utils import ResultUtils
from ..utils.utils import fix_payload_to_output


class Result(BaseItem):
    """The FuzzingTool result object

    Attributes:
        history: The HTTP history of the result
        payload: The string payload used in the request
        words: The quantitty of words in the response body
        lines: The quantity of lines in the response body
        scanners_res: The results dict provided from the scanners
        _payload: The Payload object
    """
    save_payload_configs = False
    save_headers = False
    save_body = False

    def __init__(self,
                 history: HttpHistory,
                 payloads: Tuple[Payload] = (Payload(),),
                 fuzz_type: int = FuzzType.UNKNOWN_FUZZING):
        """Class constructor

        @type history: HttpHistory
        @param history: The HTTP history of this result
        @type payload: Payload
        @param payload: The payload used in the request
        @type fuzz_type: int
        @param fuzz_type: The request fuzzing type
        """
        super().__init__()
        self.history = history
        self.payloads = [payload.final for payload in payloads]
        content = self.history.response.content
        self.words = len(content.split())
        self.lines = content.count(b'\n')
        self.fuzz_type = fuzz_type
        self.job_description = ''
        self.scanners_res: Dict[str, ScannerResult] = {}
        self._payloads = payloads

    def __str__(self) -> str:
        rtt, length, words, lines = ResultUtils.get_formatted_result(
            self.history.rtt, self.history.body_size,
            self.words, self.lines
        )
        returned_str = (
            f"[Code {self.history.status} | "
            f"RTT {rtt} | "
            f"Size {length} | "
            f"Words {words} | "
            f"Lines {lines}]"
        )
        if len(self.payloads) == 1:
            returned_str = (
                f"{fix_payload_to_output(self.payloads[0]):<{MAX_PAYLOAD_LENGTH_TO_OUTPUT}}"
                f" {returned_str}"
            )
        else:
            for payload in self._payloads:
                returned_str += (
                    "\n"
                    f"    {payload.fuzz_mark}: "
                    f"{fix_payload_to_output(payload.final):<{MAX_PAYLOAD_LENGTH_TO_OUTPUT}}"
                )
        returned_str += self.get_description()
        return returned_str

    def __iter__(self) -> Iterator[Tuple]:
        yield 'index', self.index
        yield 'url', self.history.url
        yield 'method', self.history.method
        yield 'rtt', self.history.rtt
        yield 'request_time', self.history.request_time
        yield 'response_time', self.history.response_time
        yield 'status', self.history.status
        yield 'headers_length', self.history.headers_length
        yield 'body_size', self.history.body_size
        yield 'words', self.words
        yield 'lines', self.lines
        if self.history.ip:
            yield 'ip', self.history.ip
        for s_res in self.scanners_res.values():
            for key, value in s_res.data.items():
                yield key, ResultUtils.format_data_field(value, force_detailed=True)
        for payload in self._payloads:
            payload_key = f"payload_{payload.fuzz_mark}"
            yield payload_key, payload.final
            if Result.save_payload_configs:
                yield f'{payload_key}_raw', payload.raw
                for key, value in payload.config.items():
                    yield f"{payload_key}_{key}", value
        if Result.save_headers:
            yield 'headers', self.history.raw_headers
        if Result.save_body:
            yield 'body', self.history.response.text

    def get_description(self) -> str:
        """Get the description from the result

        @returns str: The job description and scanners descriptions
        """
        description = ''
        if self.job_description:
            description += f"\n|_ {self.job_description}"
        for scanner, s_res in self.scanners_res.items():
            for key, value in s_res.data.items():
                if (value is not None and isinstance(value, bool)) or value:
                    description += (f"\n|_ {key}: "
                                    f"{ResultUtils.format_data_field(value)}")
            if s_res.enqueued_payloads:
                description += (f"\n|_ Scanner {scanner} enqueued "
                                f"{s_res.enqueued_payloads} payloads")
        return description
