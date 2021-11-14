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

from .base_factories import BaseWordlistFactory
from .plugin_factory import PluginFactory
from ..core.bases.base_wordlist import BaseWordlist
from ..utils.http_utils import get_host, get_pure_url
from ..conn.requesters.requester import Requester
from ..core.defaults.wordlists import ListWordlist, FileWordlist
from ..exceptions.main_exceptions import WordlistCreationError
from ..exceptions.plugin_exceptions import InvalidPlugin, PluginCreationError


class WordlistFactory(BaseWordlistFactory):
    @staticmethod
    def creator(name: str, params: str, requester: Requester) -> BaseWordlist:
        try:
            wordlist_cls = PluginFactory.class_creator(name, 'wordlists')
        except InvalidPlugin:
            if name.startswith('[') and name.endswith(']'):
                wordlist_obj = ListWordlist(name)
            else:
                # For default, read the wordlist from a file
                wordlist_obj = FileWordlist(name)
        else:
            if (not params and requester and
                    wordlist_cls.__params__['metavar'] in
                    ["TARGET_HOST", "TARGET_URL"]):
                if "TARGET_HOST" in wordlist_cls.__params__['metavar']:
                    params = get_host(get_pure_url(requester.get_url()))
                elif "TARGET_URL" in wordlist_cls.__params__['metavar']:
                    params = get_pure_url(requester.get_url())
            try:
                wordlist_obj = PluginFactory.object_creator(name, 'wordlists', params)
            except PluginCreationError as e:
                raise WordlistCreationError(str(e))
        return wordlist_obj
