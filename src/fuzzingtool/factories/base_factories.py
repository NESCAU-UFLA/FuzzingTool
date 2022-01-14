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

from abc import ABC, abstractmethod


class BasePluginFactory(ABC):
    @staticmethod
    @abstractmethod
    def get_plugins_from_category(category: str):
        """Gets the plugin instanaces from a category

        @type category: str
        @param category: The category of the plugins
        @returns List[Type[Plugin]]: The list with the plugin instances from category
        """
        pass

    @staticmethod
    @abstractmethod
    def class_creator(name: str, category: str):
        """Get the import for the plugin

        @type name: str
        @param name: The plugin to be searched for
        @type category: str
        @param category: The category of the searched plugin
        @returns Type[Plugin]: The import of the searched plugin
        """
        pass

    @staticmethod
    @abstractmethod
    def object_creator(name: str, category: str, params):
        """Build the plugins based on their categories

        @type name: str
        @param name: The plugin name
        @type category: str
        @param category: The plugin category
        @type params: mixed
        @param params: The plugin parameters (if it has)
        @returns Plugin: The selected plugin object
        """
        pass


class BaseWordlistFactory(ABC):
    @staticmethod
    @abstractmethod
    def creator(name: str, params: str, requester):
        """Generates the wordlist

        @type name: str
        @param name: The wordlist name
        @type params: str
        @param params: The wordlist parameters
        @type requester: Requester
        @param requester: The requester for the given wordlist
        @returns BaseWordlist: The asked wordlist
        """
        pass
