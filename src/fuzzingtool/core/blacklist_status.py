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

from typing import List, Dict, Callable

from ..utils.utils import split_str_to_list
from ..exceptions.main_exceptions import (BadArgumentType, MissingParameter,
                                          InvalidArgument)


class BlacklistStatus:
    """Blacklist status handler object

    Attributes:
        codes: The list with the blacklisted status codes
        action_callback: The callback function to trigger when detect a blacklisted status
    """
    def __init__(self,
                 status: str,
                 action: str,
                 action_param: str,
                 action_callbacks: Dict[str, Callable[[int], None]]):
        """Class constructor

        @type status: str
        @param status: The blacklist status codes in string format
        @type action: str
        @param action: The action taken when detects a status in blacklist
        @type action_param: str
        @param action_param: The parameter for the action, if it requires
        @type action_callbacks: Dict[str, Callable[[int], None]]
        @param action_callbacks: The action callbacks
        """
        self.codes = self.build_status_list(status)
        if action:
            self.do_action, self.action_param = self.set_action_callback(
                action, action_param, action_callbacks
            )

    def do_action(self, status: int) -> None:
        """Do an ction when a status code is detected

        @type status: int
        @param status: The status code of the response
        """
        pass

    def build_status_list(self, status: str) -> List[int]:
        """Build the blacklisted status codes

        @type status: str
        @param status: The blacklisted status codes
        @returns List[int]: The parsed blacklisted status codes
        """
        try:
            return [int(status) for status in split_str_to_list(status)]
        except ValueError:
            raise BadArgumentType("Status code must be an integer")

    def set_action_callback(self,
                            action: str,
                            action_param: str,
                            action_callbacks: str) -> Callable[[int], None]:
        """Get the action callback if a blacklisted status code is set

        @type action: str
        @param action: The action taken when detects a status in blacklist
        @type action_param: str
        @param action_param: The parameter for the action, if it requires
        @type action_callbacks: dict
        @param action_callbacks: The action callbacks
        @returns Callable[[int], None]: A callback function for the blacklisted status code
        """
        if action == 'stop':
            return (action_callbacks['stop'], None)
        if action == 'wait':
            if not action_param:
                raise MissingParameter("Must set a time to wait, in seconds")
            try:
                action_param = float(action_param)
            except ValueError:
                raise BadArgumentType("Time to wait must be a number")
            return (action_callbacks['wait'], action_param)
        raise InvalidArgument(f"Invalid type of blacklist action: {action}")
