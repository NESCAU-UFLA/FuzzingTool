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

def splitStrToList(string: str, separator: str = ','):
    """Split the given string into a list, using a separator

    @type string: str
    @param string: The string to be splited
    @type separator: str
    @param separator: A separator to split the string
    @returns list: The splited string
    """
    if string:
        if separator in string:
            return string.split(separator)
        return [string]
    return []

def getPluginNamesFromCategory(category: str):
    """Gets the custom package names (inside /core/category/custom/)

    @type category: str
    @param category: The category to search for the custom plugins
    @returns list: The list with the custom plugins filenames
    """
    from os import walk
    try:
        _, _, pluginFiles = next(walk(f"./fuzzingtool/core/{category}/custom/"))
    except:
        from os.path import dirname, abspath
        _, _, pluginFiles = next(walk(f"{dirname(dirname(abspath(__file__)))}/core/{category}/custom/"))
    if '__init__.py' in pluginFiles:
        pluginFiles.remove('__init__.py')
    return [pluginFile.split('.')[0] for pluginFile in pluginFiles]

def checkRangeList(content: str):
    """Checks if the given content has a range list,
       and make a list of the range specified
    
    @type content: str
    @param content: The string content to check for range
    @returns list: The list with the compiled content
    """
    def getNumberRange(left: str, right: str):
        """Get the number range list
        
        @type left: str
        @param left: The left string of the division mark
        @type right: str
        @param right: The right string of the division mark
        @returns list: The list with the range
        """
        isNumber = True
        i = len(left)
        while isNumber and i > 0:
            try:
                int(left[i-1])
            except:
                isNumber = False
            else:
                i -= 1
        leftDigit, leftStr = int(left[i:]), left[:i]
        isNumber = True
        i = 0
        while isNumber and i < (len(right)-1):
            try:
                int(right[i+1])
            except Exception as e:
                isNumber = False
            else:
                i += 1
        rightDigit, rightStr = int(right[:(i+1)]), right[(i+1):]
        compiledList = []
        if leftDigit < rightDigit:
            while leftDigit <= rightDigit:
                compiledList.append(
                    f"{leftStr}{str(leftDigit)}{rightStr}"
                )
                leftDigit += 1
        else:
            while rightDigit <= leftDigit:
                compiledList.append(
                    f"{leftStr}{str(leftDigit)}{rightStr}"
                )
                leftDigit -= 1
        return compiledList

    def getLetterRange(left: str, right: str):
        """Get the alphabet range list [a-z] [A-Z] [z-a] [Z-A]
        
        @type left: str
        @param left: The left string of the division mark
        @type right: str
        @param right: The right string of the division mark
        @returns list: The list with the range
        """
        leftDigit, leftStr = left[len(left)-1], left[:len(left)-1]
        rightDigit, rightStr = right[0], right[1:]
        compiledList = []
        if ord(leftDigit) <= ord(rightDigit):
            orderLeftDigit = ord(leftDigit)
            orderRightDigit = ord(rightDigit)
            while orderLeftDigit <= orderRightDigit:
                compiledList.append(
                    f"{leftStr}{chr(orderLeftDigit)}{rightStr}"
                )
                orderLeftDigit += 1
        else:
            orderLeftDigit = ord(leftDigit)
            orderRightDigit = ord(rightDigit)
            while orderLeftDigit >= orderRightDigit:
                compiledList.append(
                    f"{leftStr}{chr(orderLeftDigit)}{rightStr}"
                )
                orderLeftDigit -= 1
        return compiledList

    if '\-' in content:
        content = content.replace('\-', '-')
    elif '-' in content:
        left, right = content.split('-', 1)
        try:
            # Checks if the left and right digits from the mark are integers
            int(left[len(left)-1])
            int(right[0])
            return getNumberRange(left, right)
        except:
            return getLetterRange(left, right)
    return [content]