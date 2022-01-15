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

from ..request_parser import (check_is_url_discovery,
                              check_is_data_fuzzing, request_parser)
from ...utils.consts import (UNKNOWN_FUZZING, HTTP_METHOD_FUZZING,
                             PATH_FUZZING, SUBDOMAIN_FUZZING, DATA_FUZZING)
from ...utils.http_utils import get_pure_url, get_host, get_url_without_scheme
from ...objects.fuzz_word import FuzzWord
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
        self._url, url_params = self.__setup_url(url)
        self.__url_params = self.__build_data_dict(url_params)
        self.__method = FuzzWord(method)
        self.__body = self.__build_data_dict(body)
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
            self._request = self.__session_request
        self.methods = methods if methods else [self.__method.word]
        if cookie:
            self.__header['Cookie'] = FuzzWord(cookie)
        self._lock = Lock()

    def get_url(self) -> str:
        """The url content getter

        @returns str: The target URL
        """
        return self._url.word

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
        self.__method = FuzzWord(method)

    def set_body(self, body: str) -> None:
        """The body data setter

        @type body: str
        @param body: The body data of the request
        """
        self.__body = self.__build_data_dict(body)

    def test_connection(self) -> None:
        """Test the connection with the target, and raise an exception if couldn't connect"""
        try:
            url = get_pure_url(self._url.word)
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

    def request(self, payload: str = '') -> Tuple[requests.Response, float]:
        """Make a request and get the response

        @type payload: str
        @param payload: The payload used in the request
        @returns Tuple[Response, float]: The response object of the request
        """
        if self.__proxies:
            self.__proxy = random.choice(self.__proxies)
        method, url, body, url_params, headers = self.__get_request_parameters(payload)
        try:
            before = time.time()
            response = self._request(method, url, body, url_params, headers)
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
            raise RequestException(f"Invalid header {invalid_header}: {headers[invalid_header]}")
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

    def _request(self,
                 method: str,
                 url: str,
                 body: dict,
                 url_params: dict,
                 headers: dict) -> requests.Response:
        """Performs a request to the target

        @type method: str
        @param method: The request method
        @type url: str
        @param url: The target URL
        @type headers: dict
        @param headers: The http header of the request
        @type body: dict
        @param body: The body data to be send with the request
        @type url_params: dict
        @param url_params: The URL params to be send with the request
        @returns Response: The response object of the request
        """
        return requests.request(
            method,
            url,
            data=body,
            params=url_params,
            headers=headers,
            proxies=self.__proxy,
            timeout=self.__timeout,
            allow_redirects=self.__follow_redirects,
        )

    def _set_fuzzing_type(self) -> int:
        """Sets the fuzzing type

        @returns int: The fuzzing type int value
        """
        if self.__method.has_fuzzing:
            return HTTP_METHOD_FUZZING
        if check_is_url_discovery(self._url):
            return PATH_FUZZING
        if check_is_data_fuzzing(self.__url_params, self.__body, self.__header):
            return DATA_FUZZING
        return UNKNOWN_FUZZING

    def __setup_url(self, url: str) -> Tuple[FuzzWord, str]:
        """The URL setup

        @returns Tuple[FuzzWord, str]: The target URL dictionary and URL params
        """
        if '://' not in url:
            # No schema was defined, default protocol http
            url = f'http://{url}'
        if '/' not in get_url_without_scheme(url):
            # Insert a base path if wasn't specified
            url += '/'
        if '?' in url:
            url, params = url.split('?', 1)
        else:
            params = ''
        return (FuzzWord(url), params)

    def __build_data_dict(self, data: str) -> Dict[FuzzWord, FuzzWord]:
        """Build the data string into a data dict

        @type datat: str
        @param datat: The data to be used in the request
        @returns Dict[FuzzWord, FuzzWord]: The data dictionary
        """
        data_dict = {}
        if data:
            for variable in data.split('&'):
                if '=' in variable:
                    key, value = variable.split('=')
                    data_dict[FuzzWord(key)] = FuzzWord(value)
                else:
                    data_dict[FuzzWord(variable)] = FuzzWord()
        return data_dict

    def __setup_header(self, header: dict) -> dict:
        """Setup the HTTP Header

        @type header: dict
        @param header: The HTTP header dictionary
        @returns dict: The HTTP header dictionary
        """
        request_header = {}
        if not header:
            request_header['User-Agent'] = FuzzWord('FuzzingTool Requester Agent')
        else:
            for key, value in header.items():
                request_header[key] = FuzzWord(value)
            if 'Content-Length' in request_header.keys():
                del request_header['Content-Length']
        request_header['Accept-Encoding'] = FuzzWord('gzip, deflate')
        return request_header

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
        str, str, dict, dict, dict
    ]:
        """Get the request parameters using in the request fields

        @type payload: str
        @param payload: The payload used in the request
        @returns tuple(str, str, dict, dict, dict): The parameters of the request
        """
        with self._lock:
            request_parser.set_payload(payload)
            return (
                request_parser.get_method(self.__method),
                request_parser.get_url(self._url),
                request_parser.get_data(self.__body),
                request_parser.get_data(self.__url_params),
                request_parser.get_header(self.__header),
            )

    def __session_request(self,
                          method: str,
                          url: str,
                          body: dict,
                          url_params: dict,
                          headers: dict) -> requests.Response:
        """Performs a request to the target using Session object

        @type method: str
        @param method: The request method
        @type url: str
        @param url: The target URL
        @type headers: dict
        @param headers: The http header of the request
        @type body: dict
        @param body: The body data to be send with the request
        @type url_params: dict
        @param url_params: The URL params to be send with the request
        @returns Response: The response object of the request
        """
        return self.__session.send(
            self.__session.prepare_request(requests.Request(
                method,
                url,
                data=body,
                params=url_params,
                headers=headers,
            )),
            proxies=self.__proxy,
            timeout=self.__timeout,
            allow_redirects=self.__follow_redirects,
        )
