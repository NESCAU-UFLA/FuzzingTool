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

from typing import Dict
from ..objects.fuzz_word import FuzzWord
from ..utils.consts import FUZZING_MARK


def check_is_subdomain_fuzzing(url: str) -> bool:
    """Checks if the fuzzing tests will occur on subdomain

    @type url: str
    @param url: The target URL
    @returns bool: The subdomain fuzzing flag
    """
    return (('.' in url and FUZZING_MARK in url)
            and url.index(FUZZING_MARK) < url.index('.'))


def check_is_url_discovery(url: FuzzWord) -> bool:
    """Checks if the fuzzing type is url fuzzing for discovery

    @type url: FuzzWord
    @param url: The target URL object
    @returns bool: The url discovery fuzzing flag
    """
    return (url.has_fuzzing and '?' not in url.word)


def check_is_data_fuzzing(
    url_params: Dict[FuzzWord, FuzzWord],
    body: Dict[FuzzWord, FuzzWord],
    header: Dict[str, FuzzWord]
) -> bool:
    """Checks if the fuzzing type is DataFuzzing

    @type url_params: Dict[FuzzWord, FuzzWord]
    @param url_params: The target URL parameters
    @type body: Dict[FuzzWord, FuzzWord]
    @param body: The target body data
    @type header: Dict[str, FuzzWord]
    @param header: The target HTTP header
    @returns bool: The data fuzzing flag
    """
    for key, value in url_params.items():
        if key.has_fuzzing or value.has_fuzzing:
            return True
    for key, value in body.items():
        if key.has_fuzzing or value.has_fuzzing:
            return True
    for value in header.values():
        if value.has_fuzzing:
            return True
    return False


class RequestParser:
    """Class that handle with request arguments parsing

    Attributes:
        payload: The payload used in the request
    """
    def __init__(self):
        self.__payload = ''

    def get_method(self, method: FuzzWord) -> str:
        """The new method getter

        @type method: dict
        @param method: The method dictionary
        @returns str: The new target method
        """
        return method.get_payloaded_word(self.__payload)

    def get_url(self, url: FuzzWord) -> str:
        """The new url getter

        @type url: dict
        @param url: The URL dictionary
        @returns str: The new target URL
        """
        return url.get_payloaded_word(self.__payload)

    def get_header(self, header: dict) -> dict:
        """The new HTTP Header getter

        @type httpHeder: dict
        @param header: The HTTP Header
        @returns dict: The new HTTP Header
        """
        return {key: value.get_payloaded_word(self.__payload)
                for key, value in header.items()}

    def get_data(self, data: Dict[FuzzWord, FuzzWord]) -> dict:
        """The new data getter

        @type data: Dict[FuzzWord, FuzzWord]
        @param data: The request data dict
        @returns dict: The new request data dict
        """
        if not data:
            return {}
        return {
            key.get_payloaded_word(self.__payload): value.get_payloaded_word(self.__payload)
            for key, value in data.items()
        }

    def set_payload(self, payload: str) -> None:
        """The payload setter

        @type payload: str
        @param payload: The payload used in the request
        """
        self.__payload = payload


request_parser = RequestParser()
