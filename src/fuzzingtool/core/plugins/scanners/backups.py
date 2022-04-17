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

from ...bases.base_plugin import Plugin
from ...bases.base_scanner import BaseScanner
from ....objects.result import Result
from ....decorators.plugin_meta import plugin_meta
from ....utils.consts import FuzzType

DEFAULT_EXTENSIONS = ".bak,.tgz,.zip,.tar.gz,~,.rar,.old,.swp"


@plugin_meta
class Backups(BaseScanner, Plugin):
    __author__ = ("Vitor Oriel",)
    __params__ = {
        'metavar': "EXTENSION",
        'type': list,
        'cli_list_separator': ',',
    }
    __desc__ = ("Look for backups extension on matched responses. "
                f"Default extensions: {DEFAULT_EXTENSIONS}")
    __type__ = FuzzType.PATH_FUZZING
    __version__ = "0.1"

    """
    Attributes:
        extensions: The extensions to look for
    """
    def __init__(self, extensions: list):
        self.extensions = extensions if extensions else DEFAULT_EXTENSIONS.split(',')
        BaseScanner.__init__(self)

    def scan(self, result: Result) -> bool:
        return True

    def _process(self, result: Result) -> None:
        if result.history.parsed_url.file_ext not in self.extensions:
            for ext in self.extensions:
                parsed_url = result.history.parsed_url
                self.enqueue_payload(result, f"{parsed_url.file_name}{ext}")
                self.enqueue_payload(result, f"{parsed_url.file}{ext}")
