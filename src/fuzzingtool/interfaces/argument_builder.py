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
from typing import List, Union, Dict

from ..utils.consts import FUZZING_MARK
from ..utils.utils import split_str_to_list
from ..utils.file_utils import read_file
from ..exceptions.main_exceptions import BadArgumentFormat


class ArgumentBuilder:
    @staticmethod
    def build_targets_from_args(
        urls: List[str],
        method: Union[str, List[str]],
        body: str
    ) -> List[dict]:
        """Build the targets from arguments

        @type urls: List[str]
        @param urls: The target URLs
        @type method: str | List[str]
        @param method: The request methods
        @type body: str
        @param body: The raw request body data
        @returns dict: The targets data builded into a dictionary
        """
        if not type(method) is list:
            methods = split_str_to_list(method)
        else:
            methods = method
        targets = []
        for url in urls:
            if not methods:
                if body and not ('?' in url or FUZZING_MARK in url):
                    methods = ['POST']
                else:
                    methods = ['GET']
            targets.append({
                'url': url,
                'methods': methods,
                'body': body,
                'header': {},
            })
        return targets

    @staticmethod
    def build_targets_from_raw_http(
        raw_http_filenames: List[str],
        scheme: str
    ) -> List[dict]:
        """Build the targets from raw http files

        @type raw_http_filenames: list
        @param raw_http_filenames: The list with the raw http filenames
        @type scheme: str
        @param scheme: The scheme used in the URL
        @returns List[dict]: The targets data builded into a list of dictionary
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
            return headers

        targets = []
        for raw_http_filename in raw_http_filenames:
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
            targets.append({
                'url': url,
                'methods': methods,
                'body': body,
                'header': headers,
            })
        return targets
