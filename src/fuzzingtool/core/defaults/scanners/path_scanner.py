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

from ...bases.base_scanner import BaseScanner
from ...result import Result
from ....utils.http_utils import get_path
from ....interfaces.cli.cli_output import Colors, get_formated_result


class PathScanner(BaseScanner):
    __author__ = ("Vitor Oriel",)

    def inspect_result(self, result: Result) -> None:
        result.custom['redirected'] = ''
        if result.status > 300 and result.status < 400:
            result.custom['redirected'] = (result.get_response()
                                                 .headers['Location'])

    def scan(self, result: Result) -> bool:
        return True

    def cli_callback(self, result: Result) -> str:
        status = result.status
        status_color = Colors.BOLD
        if status == 404:
            status_color = ''
        elif status >= 200 and status < 300:
            status_color += Colors.GREEN
        elif status >= 300 and status < 400:
            status_color += Colors.LIGHT_YELLOW
        elif status >= 400 and status < 500:
            if status == 401 or status == 403:
                status_color += Colors.CYAN
            else:
                status_color += Colors.BLUE
        elif status >= 500 and status < 600:
            status_color += Colors.RED
        else:
            status_color = ''
        redirected = result.custom['redirected']
        if redirected:
            redirected = f" {Colors.LIGHT_YELLOW}Redirected to {redirected}{Colors.RESET}"
        path, rtt, length = get_formated_result(
            get_path(result.url), result.rtt, result.length
        )
        return (
            f"{path} {Colors.GRAY}["
            f"{Colors.LIGHT_GRAY}Code{Colors.RESET} {status_color}{status}{Colors.RESET} | "
            f"{Colors.LIGHT_GRAY}RTT{Colors.RESET} {rtt} | "
            f"{Colors.LIGHT_GRAY}Size{Colors.RESET} {length}{Colors.GRAY}]{Colors.RESET}"
            f"{redirected}"
        )
