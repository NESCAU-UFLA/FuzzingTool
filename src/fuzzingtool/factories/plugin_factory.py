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

from importlib import import_module
from typing import Type, List

from .base_factories import BasePluginFactory
from ..utils.utils import split_str_to_list
from ..core.plugins import Plugin, encoders, scanners, wordlists
from ..exceptions.main_exceptions import (InvalidPluginName,
                                          MissingParameter, BadArgumentFormat)


class PluginFactory(BasePluginFactory):
    convert_cli_plugin_parameter = {
        str: lambda string, _: string,
        list: lambda string, Plugin: split_str_to_list(
            string, separator=Plugin.__params__['cli_list_separator']
        ),
    }

    def get_plugins_from_category(category: str) -> List[Type[Plugin]]:
        plugin_categories = {
            'encoders': encoders,
            'scanners': scanners,
            'wordlists': wordlists,
        }
        try:
            plugins = [cls for _, cls in plugin_categories[category].__dict__.items()
                       if isinstance(cls, type(Plugin))]
        except KeyError:
            raise Exception(f"Invalid plugin category {category}!")
        return plugins

    def class_creator(name: str, category: str) -> Type[Plugin]:
        plugin_module = import_module(
            f"fuzzingtool.core.plugins.{category}",
            package=name
        )
        try:
            Plugin = getattr(plugin_module, name)
        except AttributeError:
            raise InvalidPluginName(f"Plugin {name} does not exists")
        return Plugin

    def object_creator(name: str, category: str, params) -> Plugin:
        try:
            Plugin = PluginFactory.class_creator(name, category)
        except InvalidPluginName as e:
            raise Exception(str(e))
        if not Plugin.__params__:
            return Plugin()
        try:
            if type(params) is str:
                params = PluginFactory.convert_cli_plugin_parameter[
                    Plugin.__params__['type']
                ](params, Plugin)
            return Plugin(params)
        except MissingParameter as e:
            raise Exception(f"Plugin {name} missing parameter: {str(e)}")
        except BadArgumentFormat as e:
            raise Exception(f"Plugin {name} bad argument format: {str(e)}")
