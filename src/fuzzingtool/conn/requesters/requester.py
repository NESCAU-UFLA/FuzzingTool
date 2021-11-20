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

from threading import Lock
import random
import time
from typing import List, Dict, Tuple

import requests
import urllib3.exceptions

from ..request_parser import (check_is_method_fuzzing, check_is_url_discovery,
                              check_is_data_fuzzing, request_parser)
from ...utils.consts import (FUZZING_MARK, FUZZING_MARK_LEN,
                             UNKNOWN_FUZZING, HTTP_METHOD_FUZZING,
                             PATH_FUZZING, SUBDOMAIN_FUZZING, DATA_FUZZING)
from ...utils.http_utils import get_pure_url, get_host, get_url_without_scheme
from ...utils.utils import get_indexes_to_parse
from ...exceptions.request_exceptions import RequestException


class Requester:
    """Class that handle with the requests

    Attributes:
        url: The target URL
        method: The request method
        body: The body data of the request
        headers: The HTTP header
        proxy: The proxy used in the request
        proxies: The list with valid proxies gived by a file
        timeout: The request timeout before raise a TimeoutException
        follow_redirects: The follow redirections flag
        methods: The methods list to be used on fuzzing
        lock: The threads locker to set up the payload on the fuzzing entries
    """
    def __init__(self,
                 url: str,
                 method: str = 'GET',
                 methods: List[str] = None,
                 body: str = '',
                 headers: Dict[str, str] = None,
                 follow_redirects: bool = True,
                 proxy: str = '',
                 proxies: List[str] = None,
                 timeout: int = 0,
                 cookie: str = '',
                 is_session: bool = False):
        """Class constructor

        @type url: str
        @param url: The target URL
        @type method: str
        @param method: The request http verb (method)
        @type methods: list
        @param methods: The request methods list
        @type body: str
        @param body: The body data of the request
        @type headers: dict
        @param headers: The HTTP header of the request
        @type follow_redirects: bool
        @param follow_redirects: The follow redirects flag
        @type proxy: str
        @param proxy: The proxy used in the request
        @type proxies: list
        @param proxies: The list with the proxies used in the requests
        @type timeout: int
        @param timeout: The request timeout
        @type cookie: str
        @param cookie: The cookie HTTP header value
        @type is_session: bool
        @param is_session: The flag to say if the requests will be made as session request
        """
        self._url = self.__setup_url(url)
        self.__method = self.__setup_method(method)
        self.__data = self.__setup_data(body)
        self.__header = self.__setup_header(headers)
        self.__proxy = self.__setup_proxy(proxy) if proxy else {}
        self.__proxies = ([self.__setup_proxy(proxy) for proxy in proxies]
                          if proxies else [])
        self.__follow_redirects = follow_redirects
        self.__fuzzing_type = self._set_fuzzing_type()
        if not timeout:
            if self.is_url_discovery():
                timeout = 10
            else:
                timeout = None
        self.__timeout = timeout
        if is_session or self.is_path_fuzzing():
            self.__session = requests.Session()
            self.__request = self.__session_request
        else:
            self.__request = self.__common_request
        self.methods = methods if methods else []
        if cookie:
            self.set_header_content('Cookie', cookie)
        self._lock = Lock()

    def get_url(self) -> str:
        """The url content getter

        @returns str: The target URL
        """
        return self._url['content']

    def is_method_fuzzing(self) -> bool:
        """The method fuzzing flag getter

        @returns bool: The method fuzzing flag
        """
        return self.__fuzzing_type == HTTP_METHOD_FUZZING

    def is_data_fuzzing(self) -> bool:
        """The data fuzzing flag getter

        @returns bool: The data fuzzing flag
        """
        return self.__fuzzing_type == DATA_FUZZING

    def is_url_discovery(self) -> bool:
        """Checks if the fuzzing is for url discovery (path or subdomain)

        @returns bool: A flag to say if is url discovery fuzzing type
        """
        return self.__fuzzing_type == PATH_FUZZING or self.__fuzzing_type == SUBDOMAIN_FUZZING

    def is_path_fuzzing(self) -> bool:
        """Checks if the fuzzing will be path discovery

        @returns bool: A flag to say if is path fuzzing
        """
        return self.__fuzzing_type == PATH_FUZZING

    def get_fuzzing_type(self) -> int:
        """The fuzzing type getter

        @returns int: The fuzzing type
        """
        return self.__fuzzing_type

    def set_method(self, method: str) -> None:
        """The request method setter

        @type method: str
        @param method: The request method
        """
        self.__method = self.__setup_method(method)

    def set_body(self, body: str) -> None:
        """The body data setter

        @type body: str
        @param body: The body data of the request
        """
        self.__build_data_dict(self.__data, 'BODY', body)

    def set_header_content(self,
                           key: str,
                           value: str,
                           header: dict = {}) -> None:
        """The header content setter

        @type key: str
        @param key: The HTTP header key
        @type value: str
        @param value: The HTTP header value
        @type header: dict
        @param header: The header to set the content
        """
        if not header:
            header = self.__header
        if FUZZING_MARK in value:
            header['payloadKeys'].append(key)
            header['content'][key] = self.__parse_header_value(value)
        else:
            header['content'][key] = value

    def test_connection(self) -> None:
        """Test the connection with the target, and raise an exception if couldn't connect"""
        try:
            url = get_pure_url(self._url['content'])
            requests.get(
                url,
                proxies=self.__proxy,
                headers=request_parser.get_header(self.__header),
                timeout=(self.__timeout
                         if self.__timeout
                         else 10)  # Default 10 seconds to make a request
            )
        except requests.exceptions.ProxyError:
            raise RequestException("Can't connect to the proxy")
        except requests.exceptions.SSLError:
            raise RequestException(f"SSL couldn't be validated on {url}")
        except requests.exceptions.Timeout:
            raise RequestException(f"Connection to {url} timed out")
        except requests.exceptions.InvalidHeader as e:
            e = str(e)
            invalid_header = e[e.rindex(': ')+2:]
            raise RequestException(f"Invalid header {invalid_header}")
        except (
            requests.exceptions.ConnectionError,
            requests.exceptions.RequestException
        ):
            raise RequestException(f"Failed to establish a connection to {url}")

    def has_redirection(self) -> bool:
        """Test if the connection will have a redirection

        @returns bool: The flag to say if occur a redirection or not
        """
        response, *_ = self.request(' ')
        if '302' in str(response.history):
            return True
        return False

    def request(self, payload: str = '') -> Tuple[requests.Response, float]:
        """Make a request and get the response

        @type payload: str
        @param payload: The payload used in the request
        @returns Response: The response object of the request
        """
        if self.__proxies:
            self.__proxy = random.choice(self.__proxies)
        method, url, headers, data = self.__get_request_parameters(payload)
        try:
            before = time.time()
            response = self.__request(method, url, headers, data)
            rtt = (time.time() - before)
        except requests.exceptions.ProxyError:
            raise RequestException("Can't connect to the proxy")
        except requests.exceptions.TooManyRedirects:
            raise RequestException(f"Too many redirects on {url}")
        except requests.exceptions.SSLError:
            raise RequestException(f"SSL couldn't be validated on {url}")
        except requests.exceptions.Timeout:
            raise RequestException(f"Connection to {url} timed out")
        except requests.exceptions.InvalidHeader as e:
            e = str(e)
            invalid_header = e[e.rindex(': ')+2:]
            raise RequestException(f"Invalid header {invalid_header}: {headers[invalid_header].decode('utf-8')}")
        except (
            requests.exceptions.ConnectionError,
            requests.exceptions.RequestException
        ):
            raise RequestException(f"Failed to establish a connection to {url}")
        except (
            UnicodeError,
            urllib3.exceptions.LocationParseError
        ):
            raise RequestException(f"Invalid hostname {get_host(url)} for HTTP request")
        except ValueError as e:
            raise RequestException(str(e))
        else:
            return (response, rtt)

    def _set_fuzzing_type(self) -> int:
        """Sets the fuzzing type

        @returns int: The fuzzing type int value
        """
        if check_is_method_fuzzing(self.__method):
            return HTTP_METHOD_FUZZING
        if check_is_url_discovery(self._url):
            return PATH_FUZZING
        if check_is_data_fuzzing(self.__data, self.__header):
            return DATA_FUZZING
        return UNKNOWN_FUZZING

    def __setup_url(self, url: str) -> dict:
        """The URL setup

        @returns dict: The target URL dictionary
        """
        if '://' not in url:
            # No schema was defined, default protocol http
            url = f'http://{url}'
        if '/' not in get_url_without_scheme(url):
            # Insert a base path if wasn't specified
            url += '/'
        if '?' in url:
            url, self.__param = url.split('?', 1)
        else:
            self.__param = ''
        return {
            'content': url,
            'fuzzingIndexes': get_indexes_to_parse(url)
        }

    def __setup_method(self, method: str) -> dict:
        """The method setup

        @returns dict: The target method dictionary
        """
        return {
            'content': method,
            'fuzzingIndexes': get_indexes_to_parse(method)
        }

    def __setup_header(self, header: dict) -> dict:
        """Setup the HTTP Header

        @type header: dict
        @param header: The HTTP header dictionary
        @returns dict: The HTTP header dictionary
        """
        header = header if header else {}
        header = {
            'content': {**header},
            'payloadKeys': [],
        }
        for key, value in header['content'].items():
            self.set_header_content(key, value, header)
        if not header['content']:
            header['content']['User-Agent'] = 'FuzzingTool Requester Agent'
        else:
            if 'Content-Length' in header['content'].keys():
                del header['content']['Content-Length']
        header['content']['Accept-Encoding'] = 'gzip, deflate'
        return header

    def __parse_header_value(self, value: str) -> List[str]:
        """Parse the header value into a list

        @type value: str
        @param value: The HTTP Header value
        @returns List[str]: The list with the HTTP Header value content
        """
        header_value = []
        last_index = 0
        for i in get_indexes_to_parse(value):
            header_value.append(value[last_index:i])
            last_index = i+FUZZING_MARK_LEN
        if last_index == len(value):
            header_value.append('')
        else:
            header_value.append(value[last_index:len(value)])
        return header_value

    def __setup_data(self, body: str) -> dict:
        """Split all the request parameters into a list of arguments used in the request

        @type body: str
        @param body: The body data of the request
        @returns dict: The entries data of the request
        """
        data_dict = {
            'PARAM': {},
            'BODY': {},
        }
        if self.__param:
            self.__build_data_dict(data_dict, 'PARAM', self.__param)
        del self.__param
        if body:
            self.__build_data_dict(data_dict, 'BODY', body)
        return data_dict

    def __build_data_dict(self, data_dict: dict, where: str, content: str) -> None:
        """Build the content into the data dict

        @type data_dict: dict
        @param data_dict: The final data dict
        @type where: str
        @param where: Is on POST or GET?
        @type content: str
        @param content: The content of the data
        """
        def build_content(data_dict: dict, content: str) -> None:
            """Build the inner content (for each splited &) into the data dict

            @type data_dict: dict
            @param data_dict: The final data dict
            @type content: str
            @param content: The content of the data
            """
            if '=' in content:
                key, value = content.split('=')
                if FUZZING_MARK not in value:
                    data_dict[key] = value
                else:
                    data_dict[key] = ''
            else:
                data_dict[content] = ''

        for content in content.split('&'):
            build_content(data_dict[where], content)

    def __setup_proxy(self, proxy: str) -> Dict[str, str]:
        """Setup the proxy

        @type proxy: str
        @param proxy: The proxy used in the request
        @returns Dict[str, str]: The proxy dictionary
        """
        return {
            'http': f"http://{proxy}",
            'https': f"https://{proxy}",
        }

    def __get_request_parameters(self, payload: str) -> Tuple[
        str, str, dict, dict
    ]:
        """Get the request parameters using in the request fields

        @type payload: str
        @param payload: The payload used in the request
        @returns tuple(str, str, dict, dict): The parameters of the request
        """
        with self._lock:
            request_parser.set_payload(payload)
            return (
                request_parser.get_method(self.__method),
                request_parser.get_url(self._url),
                request_parser.get_header(self.__header),
                request_parser.get_data(self.__data),
            )

    def __session_request(self,
                          method: str,
                          url: str,
                          headers: dict,
                          data: dict) -> requests.Response:
        """Performs a request to the target using Session object

        @type method: str
        @param method: The request method
        @type url: str
        @param url: The target URL
        @type headers: dict
        @param headers: The http header of the request
        @type data: dict
        @param data: The data to be send with the request
        @returns Response: The response object of the request
        """
        return self.__session.send(
            self.__session.prepare_request(requests.Request(
                method,
                url,
                data=data['BODY'],
                params=data['PARAM'],
                headers=headers,
            )),
            proxies=self.__proxy,
            timeout=self.__timeout,
            allow_redirects=self.__follow_redirects,
        )

    def __common_request(self,
                         method: str,
                         url: str,
                         headers: dict,
                         data: dict) -> requests.Response:
        """Performs a request to the target

        @type method: str
        @param method: The request method
        @type url: str
        @param url: The target URL
        @type headers: dict
        @param headers: The http header of the request
        @type data: dict
        @param data: The data to be send with the request
        @returns Response: The response object of the request
        """
        return requests.request(
            method,
            url,
            data=data['BODY'],
            params=data['PARAM'],
            headers=headers,
            proxies=self.__proxy,
            timeout=self.__timeout,
            allow_redirects=self.__follow_redirects,
        )
