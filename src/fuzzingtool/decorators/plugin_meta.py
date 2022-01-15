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

from ..core.bases.base_plugin import Plugin
from ..exceptions.main_exceptions import MetadataException


def plugin_meta(cls: Plugin) -> Plugin:
    """Decorator to check for plugin metadata on a plugin class

    @type cls: Plugin
    @param cls: The class that call this decorator
    """
    _check_mandatory_meta(cls)
    if not cls.__author__:
        raise MetadataException(f"Author cannot be empty on plugin {cls.__name__}")
    if cls.__params__:
        _check_params_meta(cls)
    if not cls.__desc__:
        raise MetadataException(
            f"Description cannot be blank on plugin {cls.__name__}"
        )
    if not cls.__version__:
        raise MetadataException(f"Version cannot be blank on plugin {cls.__name__}")
    return cls


def _check_mandatory_meta(cls: Plugin) -> None:
    """Checks the mandatory metadata into the plugin decorator

    @type cls: Plugin
    @param cls: The class with the plugin metadata
    """
    metadata = ['__author__', '__params__',
                '__desc__', '__type__', '__version__']
    class_attr = vars(cls)
    for meta in metadata:
        if meta not in class_attr:
            raise MetadataException(
                f"Metadata {meta} not specified on plugin {cls.__name__}"
            )


def _check_params_meta(cls: Plugin) -> None:
    """Checks the parameter metadata into the plugin decorator

    @type cls: Plugin
    @param cls: The class with the plugin metadata
    """
    if not (type(cls.__params__) is dict):
        raise MetadataException("The parameters must be a "
                                f"dictionary on plugin {cls.__name__}")
    param_dict_keys = cls.__params__.keys()
    for key in ['metavar', 'type']:
        if key not in param_dict_keys:
            raise MetadataException(f"Key {key} must be in parameters "
                                    f"dict on plugin {cls.__name__}")
        if not cls.__params__[key]:
            raise MetadataException(f"Value of {key} cannot be empty in "
                                    f"parameters dict on plugin {cls.__name__}")
    if cls.__params__['type'] is list:
        if 'cli_list_separator' not in param_dict_keys:
            raise MetadataException("The key 'cli_list_separator' must be present "
                                    "when parameter type is list "
                                    f"on plugin {cls.__name__}")
        if not cls.__params__['cli_list_separator']:
            raise MetadataException("Value of 'cli_list_separator' "
                                    f"cannot be blank on {cls.__name__}")
