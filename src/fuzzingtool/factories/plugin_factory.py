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
from ..core.bases.base_plugin import Plugin
from ..core.plugins import encoders, scanners, wordlists
from ..exceptions.main_exceptions import MissingParameter, BadArgumentFormat
from ..exceptions.plugin_exceptions import (InvalidPluginCategory, InvalidPlugin,
                                            PluginCreationError)


class PluginFactory(BasePluginFactory):
    convert_cli_plugin_parameter = {
        str: lambda string, _: string,
        list: lambda string, plugin_cls: split_str_to_list(
            string, separator=plugin_cls.__params__['cli_list_separator']
        ),
    }

    @staticmethod
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
            raise InvalidPluginCategory(f"Invalid plugin category {category}!")
        return plugins

    @staticmethod
    def class_creator(name: str, category: str) -> Type[Plugin]:
        plugin_module = import_module(
            f"fuzzingtool.core.plugins.{category}",
            package=name
        )
        try:
            plugin_cls = getattr(plugin_module, name)
        except AttributeError:
            raise InvalidPlugin(f"Plugin {name} does not exists")
        return plugin_cls

    @staticmethod
    def object_creator(name: str, category: str, params) -> Plugin:
        try:
            plugin_cls = PluginFactory.class_creator(name, category)
        except InvalidPlugin as e:
            raise PluginCreationError(str(e))
        if not plugin_cls.__params__:
            return plugin_cls()
        if isinstance(params, str):
            params = PluginFactory.convert_cli_plugin_parameter[
                plugin_cls.__params__['type']
            ](params, plugin_cls)
        try:
            return plugin_cls(params)
        except MissingParameter as e:
            raise PluginCreationError(f"Plugin {name} missing parameter: {str(e)}")
        except BadArgumentFormat as e:
            raise PluginCreationError(f"Plugin {name} bad argument format: {str(e)}")
