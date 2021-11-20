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

from typing import Tuple

from .argument_parser import ArgumentParser
from ...utils.utils import split_str_to_list
from ...exceptions.main_exceptions import BadArgumentFormat


def parse_option_with_args(plugin: str) -> Tuple[str, str]:
    """Parse the plugin name into name and parameter

    @type plugin: str
    @param plugin: The plugin argument
    @returns tuple[str, str]: The plugin name and parameter
    """
    if '=' in plugin:
        plugin, param = plugin.split('=', 1)
    else:
        param = ''
    return (plugin, param)


class CliArguments:
    """Class that handle with the FuzzingTool arguments"""
    def __init__(self):
        try:
            parser = ArgumentParser()
            self.options = parser.get_options()
        except BadArgumentFormat as e:
            exit(f"FuzzingTool bad argument format - {str(e)}")
        self.set_request_arguments()
        self.set_dictionary_arguments()
        self.set_match_arguments()
        self.set_display_arguments()
        self.set_general_arguments()

    def set_request_arguments(self) -> None:
        """Set the request arguments"""
        self.set_targets_from_args()
        self.set_targets_from_raw_http()
        self.cookie = self.options.cookie
        self.proxy = self.options.proxy
        self.proxies = self.options.proxies
        self.timeout = self.options.timeout
        self.follow_redirects = self.options.follow_redirects

    def set_targets_from_args(self) -> None:
        """Set the targets from url"""
        self.targets_from_url = self.options.url
        self.method = self.options.method
        self.data = self.options.data

    def set_targets_from_raw_http(self) -> None:
        """Set the targets from raw http"""
        self.targets_from_raw_http = self.options.raw_http
        self.scheme = self.options.scheme

    def set_dictionary_arguments(self) -> None:
        """Set the dictionary arguments"""
        self.wordlists = [[
            parse_option_with_args(w)
            for w in split_str_to_list(wordlist, separator=';')]
            for wordlist in self.options.wordlist
        ]
        self.unique = self.options.unique
        self.prefix = split_str_to_list(self.options.prefix)
        self.suffix = split_str_to_list(self.options.suffix)
        self.uppercase = self.options.upper
        self.lowercase = self.options.lower
        self.capitalize = self.options.capitalize
        self.str_encoder = self.options.encoder
        self.encoder = [[
            parse_option_with_args(e)
            for e in split_str_to_list(encoder, separator='@')]
            for encoder in split_str_to_list(self.options.encoder)
        ]
        self.encode_only = self.options.encode_only

    def set_match_arguments(self) -> None:
        """Set the match arguments"""
        self.match_status = self.options.match_status
        self.match_length = self.options.match_length
        self.match_time = self.options.match_time
        self.str_scanner = self.options.scanner
        self.scanner = (None
                        if not self.options.scanner
                        else parse_option_with_args(self.options.scanner))

    def set_display_arguments(self) -> None:
        """Set the display arguments"""
        self.simple_output = self.options.simple_output
        if self.options.common_verbose:
            self.verbose = [True, False]
        elif self.options.detailed_verbose:
            self.verbose = [True, True]
        else:
            self.verbose = [False, False]
        self.disable_colors = self.options.disable_colors

    def set_general_arguments(self) -> None:
        """Set the general arguments"""
        self.delay = self.options.delay
        self.number_of_threads = self.options.number_of_threads
        self.set_blacklisted_status()
        self.report = self.options.report_name

    def set_blacklisted_status(self) -> None:
        """Sets blacklisted status codes, action and action param"""
        self.blacklisted_status = ''
        self.blacklist_action = ''
        self.blacklist_action_param = ''
        if self.options.blacklist_status:
            status = self.options.blacklist_status
            if ':' in status:
                status, blacklist_action = status.split(':', 1)
                blacklist_action = blacklist_action.lower()
                if '=' in blacklist_action:
                    self.blacklist_action, self.blacklist_action_param = blacklist_action.split('=')
                else:
                    self.blacklist_action = blacklist_action
            else:
                self.blacklist_action = 'skip'
            self.blacklisted_status = status
