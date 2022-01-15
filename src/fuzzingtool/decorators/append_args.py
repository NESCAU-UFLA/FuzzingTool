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

from typing import Callable

from ..core.bases.base_scanner import BaseScanner
from ..objects.result import Result


def append_args(function: Callable) -> Callable:
    """Decorator to append extra data from arguments to the result

    @type function: Callable
    @param function: The function to inspect the result
    """
    def wrapper(cls: BaseScanner,
                result: Result,
                *args) -> Callable[[BaseScanner, Result], None]:
        """Wrapper function to the decorator

        @type cls: BaseScanner
        @param cls: The scanner that are using this decorator function
        @type result: Result
        @param result: The result object
        """
        if args:
            result.custom.update(args[0])
        return function(cls, result)

    return wrapper
