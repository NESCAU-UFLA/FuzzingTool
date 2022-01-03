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

from collections import deque
from typing import List, Tuple, Dict

from ..utils.consts import FUZZING_MARK
from ..utils.utils import split_str_to_list, parse_option_with_args
from ..utils.file_utils import read_file
from ..exceptions.main_exceptions import BadArgumentFormat


class ArgumentBuilder:
    @staticmethod
    def build_target_from_args(
        url: str,
        method: str,
        body: str
    ) -> dict:
        """Build the targets from arguments

        @type urls: List[str]
        @param urls: The target URLs
        @type method: str
        @param method: The request methods
        @type body: str
        @param body: The raw request body data
        @returns dict: The targets data builded into a dictionary
        """
        methods = split_str_to_list(method)
        if not methods:
            if body and not ('?' in url or FUZZING_MARK in url):
                methods = ['POST']
            else:
                methods = ['GET']
        return {
            'url': url,
            'methods': methods,
            'body': body,
            'header': {},
        }

    @staticmethod
    def build_target_from_raw_http(
        raw_http_filename: str,
        scheme: str
    ) -> dict:
        """Build the targets from raw http files

        @type raw_http_filenames: list
        @param raw_http_filenames: The list with the raw http filenames
        @type scheme: str
        @param scheme: The scheme used in the URL
        @returns dict: The target HTTP data builded into a dict
        """
        def build_header_from_raw_http(
            header_list: deque
        ) -> Dict[str, str]:
            """Get the HTTP header

            @tyoe header_list: deque
            @param header_list: The list with HTTP header
            @returns Dict[str, str]: The HTTP header parsed into a dict
            """
            headers = {}
            i = 0
            this_header = header_list.popleft()
            header_length = len(header_list)
            while i < header_length and this_header != '':
                key, value = this_header.split(': ', 1)
                headers[key] = value
                this_header = header_list.popleft()
                i += 1
            if this_header:
                key, value = this_header.split(': ', 1)
                headers[key] = value
            return headers

        try:
            header_list = deque(read_file(raw_http_filename))
        except ValueError:
            raise BadArgumentFormat("Invalid header format. E.g. Key: value")
        method, path, _ = header_list.popleft().split(' ')
        methods = split_str_to_list(method)
        headers = build_header_from_raw_http(header_list)
        url = f"{scheme}://{headers['Host']}{path}"
        if len(header_list) > 0:
            body = header_list.popleft()
        else:
            body = ''
        return {
            'url': url,
            'methods': methods,
            'body': body,
            'header': headers,
        }

    @staticmethod
    def build_wordlist(wordlists: str) -> List[Tuple[str, str]]:
        """Build the wordlists

        @type wordlists: str
        @param wordlists: The wordlists from command line
        @returns List[Tuple[str, str]]: The builded wordlists
        """
        return [
            parse_option_with_args(wordlist)
            for wordlist in split_str_to_list(wordlists, separator=';')
        ]

    @staticmethod
    def build_encoder(encoders: str) -> List[List[Tuple[str, str]]]:
        """Build the encoders

        @type encoders: str
        @param encoders: The encoders from command line
        @returns List[List[Tuple[str, str]]]: The builded encoders
        """
        return [[
            parse_option_with_args(e)
            for e in split_str_to_list(encoder, separator='@')]
            for encoder in split_str_to_list(encoders)
        ]

    @staticmethod
    def build_scanner(scanner: str) -> Tuple[str, str]:
        """Build the scanner

        @type scanner: str
        @param scanner: The scanner from command line
        @returns Tuple[str, str]: The builded scanner
        """
        return parse_option_with_args(scanner)

    @staticmethod
    def build_verbose_mode(is_common: bool, is_detailed: bool) -> List[bool]:
        """Build the verbose mode

        @type is_common: bool
        @param is_common: A flag to say if is common verbose mode
        @type is_detailed: bool
        @param is_detailed: A flag to say if is detailed verbose mode
        @returns List[bool]: The builded verbose mode
        """
        verbose = [False, False]
        if is_common:
            verbose = [True, False]
        elif is_detailed:
            verbose = [True, True]
        return verbose

    @staticmethod
    def build_blacklist_status(blacklist_status: str) -> Tuple[str, str, str]:
        """Build the blacklist_status

        @type blacklist_status: str
        @param blacklist_status: The blacklist status from command line
        @returns Tuple[str, str, str]: The builded blacklist status
        """
        blacklisted_status = blacklist_status
        blacklist_action = ''
        blacklist_action_param = ''
        if ':' in blacklisted_status:
            blacklisted_status, blacklist_action = blacklisted_status.split(':', 1)
            blacklist_action = blacklist_action.lower()
            if '=' in blacklist_action:
                blacklist_action, blacklist_action_param = blacklist_action.split('=')
        else:
            blacklist_action = 'stop'
        return (blacklisted_status, blacklist_action, blacklist_action_param)
