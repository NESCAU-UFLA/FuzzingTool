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

from ..utils.utils import splitStrToList

class BlacklistStatus:
    """Blacklist status handler object

    Attributes:
        codes: The list with the blacklisted status codes
        actionCallback: The callback function to trigger when detect a blacklisted status
    """
    def __init__(self,
        status: str,
        action: str,
        actionParam: str,
        actionCallbacks: dict
    ):
        """Class constructor
        
        @type status: str
        @param status: The blacklist status codes in string format
        @type action: str
        @param action: The action taken when detects a status in blacklist
        @type actionParam: str
        @param actionParam: The parameter for the action, if it requires
        @type actionCallbacks: dict
        @param actionCallbacks: The action callbacks
        """
        self.codes = self.buildStatusList(status)
        self.actionCallback = self.setActionCallback(action, actionParam, actionCallbacks)
    
    def buildStatusList(self, status: str):
        """Build the blacklisted status codes

        @type status: str
        @param status: The blacklisted status codes
        @returns list: The parsed blacklisted status codes
        """
        try:
            return [int(status) for status in splitStrToList(status)]
        except:
            raise Exception("Status code must be an integer")
    
    def setActionCallback(self,
        action: str,
        actionParam: str,
        actionCallbacks: str
    ):
        """Get the action callback if a blacklisted status code is set

        @type action: str
        @param action: The action taken when detects a status in blacklist
        @type actionParam: str
        @param actionParam: The parameter for the action, if it requires
        @type actionCallbacks: dict
        @param actionCallbacks: The action callbacks
        @returns Callable: A callback function for the blacklisted status code
        """
        if not action:
            return lambda status : None
        if action == 'skip':
            return actionCallbacks['skip']
        if action == 'wait':
            if not actionParam:
                raise Exception("Must set a time to wait")
            try:
                self.actionParam = float(actionParam)
            except ValueError:
                raise Exception("Time to wait must be a number")
            return actionCallbacks['wait']
        raise Exception(f"Invalid type of blacklist action: {action}")