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

from ..utils.consts import FUZZING_MARK, FUZZING_MARK_LEN


def check_is_subdomain_fuzzing(url: str) -> bool:
    """Checks if the fuzzing tests will occur on subdomain

    @type url: str
    @param url: The target URL
    @returns bool: The subdomain fuzzing flag
    """
    return (('.' in url and FUZZING_MARK in url)
            and url.index(FUZZING_MARK) < url.index('.'))


def check_is_method_fuzzing(method: dict) -> bool:
    """Checks if the fuzzing type is MethodFuzzing

    @type url: dict
    @param url: The target URL dict
    @returns bool: The method fuzzing flag
    """
    return False if not method['fuzzingIndexes'] else True


def check_is_url_fuzzing(url: dict) -> bool:
    """Checks if the fuzzing type is UrlFuzzing

    @type url: dict
    @param url: The target URL dict
    @returns bool: The url fuzzing flag
    """
    return False if not url['fuzzingIndexes'] else True


def check_is_url_discovery(url: dict) -> bool:
    """Checks if the fuzzing type is UrlFuzzing for discovery

    @type url: dict
    @param url: The target URL dict
    @returns bool: The url discovery fuzzing flag
    """
    return (check_is_url_fuzzing(url) and '?' not in url['content'])


def check_is_data_fuzzing(data: dict, header: dict) -> bool:
    """Checks if the fuzzing type is DataFuzzing

    @type data: dict
    @param data: The target data
    @type header: dict
    @param header: The target HTTP header
    @returns bool: The data fuzzing flag
    """
    for _, value in data['PARAM'].items():
        if not value:
            return True
    for _, value in data['BODY'].items():
        if not value:
            return True
    if header['payloadKeys']:
        return True
    return False


class RequestParser:
    """Class that handle with request arguments parsing

    Attributes:
        payload: The payload used in the request
    """
    def __init__(self):
        self.__payload = ''

    def get_method(self, method: dict) -> str:
        """The new method getter

        @type method: dict
        @param method: The method dictionary
        @returns str: The new target method
        """
        return method['content'] if not method['fuzzingIndexes'] else self.__get_ajusted_content_by_indexes(method)

    def get_url(self, url: dict) -> str:
        """The new url getter

        @type url: dict
        @param url: The URL dictionary
        @returns str: The new target URL
        """
        return url['content'] if not url['fuzzingIndexes'] else self.__get_ajusted_content_by_indexes(url)

    def get_header(self, headers: dict) -> dict:
        """The new HTTP Header getter

        @type httpHeder: dict
        @param headers: The HTTP Header
        @returns dict: The new HTTP Header
        """
        return headers['content'] if not headers['payloadKeys'] else self.__get_ajusted_header(headers)

    def get_data(self, data: dict) -> dict:
        """The new data getter

        @type data: dict
        @param data: The request parameters
        @returns dict: The new request parameters
        """
        return {
            'PARAM': {} if not data['PARAM'] else self.__get_ajusted_data(data['PARAM']),
            'BODY': {} if not data['BODY'] else self.__get_ajusted_data(data['BODY'])
        }

    def set_payload(self, payload: str) -> None:
        """The payload setter

        @type payload: str
        @param payload: The payload used in the request
        """
        self.__payload = payload

    def __get_ajusted_content_by_indexes(self, content: dict) -> str:
        """Put the payload into the given content

        @type content: dict
        @param content: The target content dictionary
        @returns str: The new content
        """
        ajusted_content = content['content']
        for i in content['fuzzingIndexes']:
            head = ajusted_content[:i]
            tail = ajusted_content[(i+FUZZING_MARK_LEN):]
            ajusted_content = head + self.__payload + tail
        return ajusted_content

    def __get_ajusted_header(self, header: dict) -> dict:
        """Put the payload in the header value that contains the fuzzing mark

        @type header: dict
        @param header: The HTTP Header dictionary
        @returns dict: The new HTTP Header
        """
        ajusted_header = {}
        for key, value in header['content'].items():
            ajusted_header[key] = value
        for key in header['payloadKeys']:
            result = ''
            value = ajusted_header[key]
            for i in range(len(value)-1):
                result += value[i] + self.__payload
            result += value[-1]
            ajusted_header[key] = result.encode('utf-8')
        return ajusted_header

    def __get_ajusted_data(self, data: dict) -> dict:
        """Put the payload into the Data requestParameters dictionary

        @type data: dict
        @param dara: The request parameters
        @returns dict: The new request parameters
        """
        ajusted_data = {}
        for key, value in data.items():
            if value:
                ajusted_data[key] = value
            else:
                ajusted_data[key] = self.__payload
        return ajusted_data


request_parser = RequestParser()
