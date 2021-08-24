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

from .BaseFactories import BasePluginFactory
from ..utils.file_utils import getPluginNamesFromCategory
from ..utils.utils import splitStrToList
from ..core.plugins import *
from ..exceptions.MainExceptions import InvalidPluginName, MissingParameter, BadArgumentFormat

from importlib import import_module
from typing import Type

class PluginFactory(BasePluginFactory):
    convertCliPluginParameter = {
        str: lambda string, _: string,
        list: lambda string, Plugin: splitStrToList(string, separator=Plugin.__params__['cli_list_separator']),
    }

    def classCreator(name: str, category: str) -> Type[Plugin]:
        if not name in getPluginNamesFromCategory(category):
            raise InvalidPluginName(f"Plugin {name} does not exists")
        Plugin = import_module(
            f"fuzzingtool.core.plugins.{category}.{name}",
            package=name
        )
        return getattr(Plugin, name)

    def objectCreator(name: str, category: str, params) -> Plugin:
        try:
            Plugin = PluginFactory.classCreator(name, category)
        except InvalidPluginName as e:
            raise Exception(str(e))
        if not Plugin.__params__:
            return Plugin()
        try:
            if type(params) is str:
                params = PluginFactory.convertCliPluginParameter[Plugin.__params__['type']](params, Plugin)
            return Plugin(params)
        except MissingParameter as e:
            raise Exception(f"Plugin {name} missing parameter: {str(e)}")
        except BadArgumentFormat as e:
            raise Exception(f"Plugin {name} bad argument format: {str(e)}")