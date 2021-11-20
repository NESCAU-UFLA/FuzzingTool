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

from typing import List, Dict, Tuple, Callable

from .result import Result
from ..utils.utils import split_str_to_list
from ..exceptions.main_exceptions import BadArgumentType


def get_allowed_status(status: str,
                       allowed_list: List[int],
                       allowed_range: List[int]) -> None:
    """Get the allowed status code list and range

    @type status: str
    @param status: The status cod given in the terminal
    @type allowed_list: List[int]
    @param allowed_list: The allowed status codes list
    @type allowed_range: List[int]
    @param allowed_range: The range of allowed status codes
    """
    try:
        if '-' not in status:
            allowed_list.append(int(status))
        else:
            code_left, code_right = (int(code) for code in status.split('-', 1))
            if code_right < code_left:
                code_left, code_right = code_right, code_left
            allowed_range[:] = [code_left, code_right]
    except ValueError:
        raise BadArgumentType(
            f"The match status argument ({status}) must be integer"
        )


class Matcher:
    """Class to handle with the match validations

    Attributes:
        comparator: The dictionary with the default
                    entries to be compared with the current request
        allowed_status: The dictionary with the
                        allowed status codes (and range)
    """
    @staticmethod
    def build_allowed_status(allowed_status: str) -> dict:
        """Build the matcher attribute for allowed status

        @type allowed_status: str
        @param allowed_status: The allowed status codes to match results
        @returns dict: The allowed status code,
                       list and range, parsed into a dict
        """
        if not allowed_status:
            is_default = True
            allowed_list = [200]
        else:
            is_default = False
            allowed_list = []
        allowed_range = []
        for status in split_str_to_list(allowed_status):
            get_allowed_status(status, allowed_list, allowed_range)
        return {
            'is_default': is_default,
            'List': allowed_list,
            'Range': allowed_range,
        }

    @staticmethod
    def build_comparator(length: str, time: str) -> dict:
        """Build the matcher attribute for data comparator

        @type length: str
        @param length: The length attribute for match results
        @type time: str
        @param time: The time attribute for match results
        @returns dict: The data comparators parsed into a dict
        """
        return {
            'Length': None if not length else length,
            'Time': None if not time else time,
        }

    def __init__(self,
                 allowed_status: dict = None,
                 comparator: dict = None,
                 match_functions: Tuple[Callable, Callable] = None):
        """Class constructor

        @type allowed_status: dict
        @param allowed_status: The allowed status dictionary
        @type comparator: dict
        @param comparator: The dict with comparator data
        @type match_functions: Tuple[Callable, Callable]
        @param match_functions: The callback functions for the match comparator
        """
        if not allowed_status:
            allowed_status = {
                'is_default': True,
                'List': [200],
                'Range': [],
            }
        if not comparator:
            comparator = {
                'Length': None,
                'Time': None,
            }
        self._allowed_status = allowed_status
        if match_functions:
            self._comparator = comparator
            self._match_length, self._match_time = match_functions
        else:
            self.set_comparator(comparator)

    @classmethod
    def from_string(cls,
                    allowed_status: str,
                    length: str,
                    time: str) -> object:
        """Creates a Matcher object com strings

        @type allowed_status: str
        @param allowed_status: The allowed status codes
        @type length: str
        @param length: The length to be compared with the response body
        @type time: str
        @param time: The time to be compared with the rtt
        @returns Matcher: A Matcher object
        """
        return cls(
            Matcher.build_allowed_status(allowed_status),
            Matcher.build_comparator(length, time)
        )

    def get_allowed_status(self) -> dict:
        """The allowed status getter

        @returns dict: The allowed status dict
        """
        return self._allowed_status

    def get_comparator(self) -> dict:
        """The data comparator getter

        @returns dict: The data comparator dict
        """
        return self._comparator

    def get_match_functions(self) -> Tuple[Callable, Callable]:
        """Gets the match functions

        @returns Tuple[Callable, Callable]: The match functions
        """
        return (self._match_length, self._match_time)

    def allowed_status_is_default(self) -> bool:
        """Check if the allowed status is set as default config

        @returns bool: If the allowed status is the default or not
        """
        return self._allowed_status['is_default']

    def comparator_is_set(self) -> bool:
        """Check if any of the comparators are seted

        @returns bool: if any of the comparators are seted
                       returns True, else False
        """
        return self._comparator['Length'] or self._comparator['Time']

    def set_allowed_status(self, allowed_status: dict) -> None:
        """The allowed status setter

        @type allowed_status: dict
        @param allowed_status: The allowed status dictionary
        """
        self._allowed_status = allowed_status

    def set_comparator(self, comparator: dict) -> None:
        """The comparator setter

        @type comparator: dict
        @param comparator: The comparator dictionary
        """
        if comparator['Length']:
            length_comparator, self._match_length = self.__get_comparator_and_callback(
                comparator['Length'], 'Length'
            )
            try:
                length_comparator = int(length_comparator)
            except ValueError:
                raise BadArgumentType(
                    f"The length comparator must be an integer, not '{length_comparator}'!"
                )
            comparator['Length'] = length_comparator
        if comparator['Time']:
            time_comparator, self._match_time = self.__get_comparator_and_callback(
                comparator['Time'], 'Time'
            )
            try:
                time_comparator = float(time_comparator)
            except ValueError:
                raise BadArgumentType(f"The time comparator must be a number, not '{time_comparator}'!")
            comparator['Time'] = time_comparator
        self._comparator = comparator

    def match(self, result: Result) -> bool:
        """Check if the request content has some predefined characteristics 
           based on a payload, it'll be considered as vulnerable

        @type result: Result
        @param result: The actual result object
        @returns bool: A match flag
        """
        if self._match_status(result.status):
            if not self._comparator['Length'] is None:
                return self._match_length(int(result.length))
            if not self._comparator['Time'] is None:
                return self._match_time(result.rtt)
            return True
        return False

    def _match_status(self, status: int) -> bool:
        """Check if the result status match with the allowed status dict

        @type status: int
        @param status: The result status code
        @returns bool: if match returns True else False
        """
        return (status in self._allowed_status['List']
                or (self._allowed_status['Range']
                    and (self._allowed_status['Range'][0] <= status
                         and status <= self._allowed_status['Range'][1])))

    def _match_length(self, length: int) -> bool:
        """Check if the result length match with the comparator dict

        @type length: int
        @param length: The result length
        @returns bool: if match returns True else False
        """
        pass

    def _match_time(self, time: float) -> bool:
        """Check if the result time match with the comparator dict

        @type time: int
        @param time: The result time
        @returns bool: if match returns True else False
        """
        pass

    def __get_comparator_and_callback(self,
                                      comparator: str,
                                      key: str) -> Tuple[str, Callable]:
        """Gets the comparator and callback

        @type comparator: str
        @param comparator: The value to be compared
        @type key: str
        @param key: Where it'll be compared (Length or Time)
        @returns Tuple[str, Callable]: The comparator and match callback
        """
        def set_match(
            match: Dict[str, Callable], comparator: str
        ) -> Tuple[Callable, str]:
            """Set the match function and new comparator value

            @type match: Dict[str, Callable]
            @param match: The dictionary with available comparations
            @type comparator: str
            @param comparator: The value to be compared
            @returns Tuple[Callable, str]: The callback match function,
                                            and the new comparator value
            """
            comparator = str(comparator)
            for key, value in match.items():
                if key in comparator:
                    return (value, comparator.split(key, 1)[1])
            raise IndexError

        match_dict = {
            '>=': lambda to_compare: to_compare >= self._comparator[key],
            '<=': lambda to_compare: to_compare <= self._comparator[key],
            '>': lambda to_compare: to_compare > self._comparator[key],
            '<': lambda to_compare: to_compare < self._comparator[key],
            '==': lambda to_compare: to_compare == self._comparator[key],
            '!=': lambda to_compare: to_compare != self._comparator[key],
        }
        try:
            match_callback, comparator = set_match(match_dict, comparator)
        except IndexError:
            match_callback = lambda to_compare: self._comparator[key] < to_compare
        return (comparator, match_callback)
