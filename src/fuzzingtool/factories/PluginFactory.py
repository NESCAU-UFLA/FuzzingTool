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
from ..core.dictionaries import *
from ..core.encoders import *
from ..core.scanners import *
from ..exceptions.MainExceptions import InvalidPluginName, MissingParameter

from importlib import import_module

class PluginFactory(BasePluginFactory):
    def classCreator(name, category):
        Plugin = import_module(
            f"fuzzingtool.core.{category}.custom.{name}",
            package=name
        )
        return getattr(Plugin, name)

    def objectCreator(name, category, params = ''):
        if name in getPluginNamesFromCategory(category):
            Plugin = PluginFactory.classCreator(name, category)
            if not Plugin.__params__:
                return Plugin()
            else:
                try:
                    return Plugin(params)
                except MissingParameter as e:
                    raise Exception(f"Plugin {name} missing parameter: {str(e)}")
                except Exception as e:
                    raise Exception(f"Bad plugin {name} argument format: {str(e)}")
        else:
            raise InvalidPluginName(f"Plugin {name} does not exists")