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

def getIndexesToParse(content: str, searchFor: str = '$'):
    """Gets the indexes of the searched substring into a string content
    
    @type content: str
    @param content: The parameter content
    @type searchFor: str
    @param searchFor: The substring to be searched indexes on the given content
    @returns list: The positions indexes of the searched substring
    """
    return [i for i, char in enumerate(content) if char == searchFor]

def getCustomPackages(module: str):
    """Gets the custom packages

    @type module: str
    @param module: The module to search for the custom packages
    @returns list: The list with the custom packages filenames
    """
    from os import walk
    try:
        _, _, customPackages = next(walk(f"./modules/core/{module}/custom/"))
    except:
        from os.path import dirname, abspath
        modulesPath = dirname(dirname(abspath(__file__)))
        _, _, customPackages = next(walk(f"{modulesPath}/core/{module}/custom/"))
    if '__init__.py' in customPackages:
        customPackages.remove('__init__.py')
    return [packageFile.split('.')[0] for packageFile in customPackages]

def importCustomPackage(module: str, package: str):
    """Get the import for the custom package

    @type module: str
    @param module: The module of the custom package
    @type package: str
    @param package: The package to be searched for
    @returns import: The import of the searched package
    """
    from importlib import import_module
    try:
        customImported = import_module(
            f".modules.core.{module}.custom.{package}",
            package=f"{package}"
        )
    except:
        customImported = import_module(
            f"modules.core.{module}.custom.{package}",
            package=f"{package}"
        )
    return getattr(customImported, package)