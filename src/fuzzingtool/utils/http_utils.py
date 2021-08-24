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

from .consts import FUZZING_MARK

def getHost(url: str) -> str:
    """Get the target host from url

    @type url: str
    @param url: The target URL
    @returns str: The payloaded target
    """
    url = getUrlWithoutScheme(url)
    if '/' in url:
        return url[:url.index('/')]
    return url

def getPath(url: str) -> str:
    """Get the target path from url

    @type url: str
    @param url: The target URL
    @returns str: The payloaded path
    """
    url = getUrlWithoutScheme(url)
    return url[url.index('/'):]

def getPureUrl(url: str) -> str:
    """Gets the URL without the FUZZING_MARK variable

    @type url: str
    @param url: The target URL
    @returns str: The target URL without fuzzing marks
    """
    if FUZZING_MARK in url:
        if f'{FUZZING_MARK}.' in url:
            return url.replace(f'{FUZZING_MARK}.', '')
        return url.replace(FUZZING_MARK, '')
    return url

def getUrlWithoutScheme(url: str) -> str:
    """Get the target url without scheme

    @type url: str
    @param url: The target URL
    @returns str: The url without scheme
    """
    if '://' in url:
        return url[(url.index('://')+3):]
    return url