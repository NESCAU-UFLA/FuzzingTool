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

from .BaseFactories import BasePluginFactory
from ..utils.utils import getPluginNamesFromCategory
from ..core.encoders import *
from ..core.scanners import *
from ..core.wordlists import *
from ..exceptions.MainExceptions import InvalidPluginName, MissingParameter, BadArgumentFormat

from importlib import import_module

class PluginFactory(BasePluginFactory):
    def classCreator(name: str, category: str):
        if not name in getPluginNamesFromCategory(category):
            raise InvalidPluginName(f"Plugin {name} does not exists")
        Plugin = import_module(
            f"fuzzingtool.core.{category}.custom.{name}",
            package=name
        )
        return getattr(Plugin, name)

    def objectCreator(name: str, category: str, params: str = ''):
        try:
            Plugin = PluginFactory.classCreator(name, category)
        except InvalidPluginName as e:
            raise Exception(str(e))
        if not Plugin.__params__:
            return Plugin()
        try:
            return Plugin(params)
        except MissingParameter as e:
            raise Exception(f"Plugin {name} missing parameter: {str(e)}")
        except BadArgumentFormat as e:
            raise Exception(f"Plugin {name} bad argument format: {str(e)}")