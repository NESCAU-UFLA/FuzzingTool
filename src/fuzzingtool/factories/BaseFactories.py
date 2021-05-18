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

from abc import ABC, abstractmethod

class BaseHttpFactory(ABC):
    @staticmethod
    @abstractmethod
    def requestCreator(requestType, url, **kwargs):
        """Build the requests based on their types

        @type requestType: str
        @param requestType: The request type
        @type url: str
        @param url: The target URL
        @returns Request: A request object
        """
        pass

class BasePluginFactory(ABC):
    @staticmethod
    @abstractmethod
    def classCreator(name, category):
        """Get the import for the plugin

        @type name: str
        @param name: The plugin to be searched for
        @type category: str
        @param category: The category of the searched plugin
        @returns import: The import of the searched plugin
        """
        pass

    @staticmethod
    @abstractmethod
    def objectCreator(name, category, params = ''):
        """Build the plugins based on their categories

        @type name: str
        @param name: The plugin name
        @type category: str
        @param category: The plugin category
        @type params: str
        @param params: The plugin parameters (if it has)
        @returns Plugin: The selected plugin object
        """
        pass