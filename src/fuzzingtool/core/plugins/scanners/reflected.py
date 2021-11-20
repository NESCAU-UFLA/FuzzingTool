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

from ..plugin import Plugin
from ...bases.base_scanner import BaseScanner
from ...result import Result
from ....interfaces.cli.cli_output import Colors, get_formated_result
from ....decorators.plugin_meta import plugin_meta
from ....decorators.append_args import append_args


@plugin_meta
class Reflected(BaseScanner, Plugin):
    __author__ = ("Vitor Oriel",)
    __params__ = {}
    __desc__ = "Lookup if the payload was reflected in the response body"
    __type__ = ""
    __version__ = "0.1"

    @append_args
    def inspect_result(self, result: Result) -> None:
        result.custom['reflected'] = None

    def scan(self, result: Result) -> bool:
        reflected = result.payload in result.get_response().text
        result.custom['reflected'] = reflected
        return reflected

    def cli_callback(self, result: Result) -> str:
        reflected = f"{Colors.LIGHT_YELLOW}{Colors.BOLD}IDK"
        was_reflected = result.custom['reflected']
        if was_reflected is not None:
            if was_reflected:
                reflected = f"{Colors.GREEN}{Colors.BOLD}YES"
            else:
                reflected = f"{Colors.LIGHT_RED}{Colors.BOLD}NO "
        payload, rtt, length = get_formated_result(
            result.payload, result.rtt, result.length
        )
        return (
            f"{payload} {Colors.GRAY}["
            f"{Colors.LIGHT_GRAY}Reflected{Colors.RESET} {reflected}{Colors.RESET} | "
            f"{Colors.LIGHT_GRAY}Code{Colors.RESET} {result.status} | "
            f"{Colors.LIGHT_GRAY}RTT{Colors.RESET} {rtt} | "
            f"{Colors.LIGHT_GRAY}Size{Colors.RESET} {length}{Colors.GRAY}]{Colors.RESET}"
        )
