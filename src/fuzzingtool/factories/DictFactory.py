## FuzzingTool
# 
# Authors:
#    Vitor Oriel C N Borges <https://github.com/VitorOriel>
# License: MIT (LICENSE.md)
#    Copyright (c) 2021 Vitor Oriel
#    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
#    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
#    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
## https://github.com/NESCAU-UFLA/FuzzingTool

from .BaseFactories import BaseDictFactory
from .PluginFactory import PluginFactory
from ..conn.RequestParser import getHost, getPureUrl
from ..conn.requests.Request import Request
from ..core.dictionaries import *
from ..exceptions.MainExceptions import InvalidPluginName, MissingParameter

class DictFactory(BaseDictFactory):
    def creator(name: str, params: str, requester: Request):
        try:
            Dictionary = PluginFactory.classCreator(name, 'dictionaries')
            if (not params and
                Dictionary.__params__ in ["TARGET_HOST", "TARGET_URL"]):
                if "TARGET_HOST" in Dictionary.__params__:
                    params = getHost(getPureUrl(requester.getUrlDict()))
                if "TARGET_URL" in Dictionary.__params__:
                    params = getPureUrl(requester.getUrlDict())
            dictionary = PluginFactory.objectCreator(name, 'dictionaries', params)
        except InvalidPluginName:
            try:
                if name.startswith('[') and name.endswith(']'):
                    dictionary = ListDictionary(name)
                else:
                    # For default, read the wordlist from a file
                    dictionary = FileDictionary(name)
            except MissingParameter as e:
                raise Exception(f"Missing parameter: {str(e)}")
        dictionary.setWordlist()
        if len(dictionary) == 0:
            raise Exception("The dictionary generated an empty wordlist")
        return dictionary