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

from typing import List, Dict, Tuple, Callable, Union, Type
import operator

from ..objects.result import Result
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
    def __init__(self,
                 allowed_status: str = None,
                 time: str = None,
                 size: str = None,
                 words: str = None,
                 lines: str = None):
        """Class constructor

        @type allowed_status: dict
        @param allowed_status: The allowed status dictionary
        @type comparator: dict
        @param comparator: The dict with comparator data
        @type match_functions: Tuple[Callable, Callable]
        @param match_functions: The callback functions for the match comparator
        """
        self._allowed_status = self.__build_allowed_status(allowed_status)
        self._comparator = self.__build_comparator(time, size, words, lines)

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
        for value in self._comparator.values():
            if value is not None:
                return True
        return False

    def set_allowed_status(self, allowed_status: str) -> None:
        """The allowed status setter

        @type allowed_status: str
        @param allowed_status: The allowed status
        """
        self._allowed_status = self.__build_allowed_status(allowed_status)

    def set_comparator(self,
                       time: str,
                       size: str,
                       words: str,
                       lines: str) -> None:
        """The comparator setter

        @type size: str
        @param size: The size to be compared with response body
        @type time: str
        @param time: The time to be compared with the RTT
        """
        self._comparator = self.__build_comparator(time, size, words, lines)

    def match(self, result: Result) -> bool:
        """Check if the request content has some predefined characteristics
           based on a payload, it'll be considered as vulnerable

        @type result: Result
        @param result: The actual result object
        @returns bool: A match flag
        """
        if self._match_status(result.status):
            if self._comparator['time'] is not None:
                return self._match_time(result.rtt, self._comparator['time'])
            if self._comparator['size'] is not None:
                return self._match_size(int(result.body_size), self._comparator['size'])
            if self._comparator['words'] is not None:
                return self._match_words(result.words, self._comparator['words'])
            if self._comparator['lines'] is not None:
                return self._match_lines(result.lines, self._comparator['lines'])
            return True
        return False

    def _match_status(self, status: int) -> bool:
        """Check if the result status match with the allowed status dict

        @type status: int
        @param status: The result status code
        @returns bool: if match returns True else False
        """
        return (status in self._allowed_status['list']
                or (self._allowed_status['range']
                    and (self._allowed_status['range'][0] <= status
                         and status <= self._allowed_status['range'][1])))

    def _match_time(self, time: float, comparator_time: float) -> bool:
        """Check if the result time match with the comparator dict

        @type time: int
        @param time: The result time
        @type comparator_time: int
        @param comparator_time: The time comparator
        @returns bool: if match returns True else False
        """
        pass

    def _match_size(self, size: int, comparator_size: int) -> bool:
        """Check if the result size match with the comparator dict

        @type size: int
        @param size: The result size
        @type comparator_size: int
        @param comparator_size: The size comparator
        @returns bool: if match returns True else False
        """
        pass

    def _match_words(self, words: float, comparator_words: float) -> bool:
        """Check if the result words match with the comparator dict

        @type words: int
        @param words: The result words
        @type comparator_words: int
        @param comparator_words: The words comparator
        @returns bool: if match returns True else False
        """
        pass

    def _match_lines(self, lines: float, comparator_lines: float) -> bool:
        """Check if the result lines match with the comparator dict

        @type lines: int
        @param lines: The result lines
        @type comparator_lines: int
        @param comparator_lines: The lines comparator
        @returns bool: if match returns True else False
        """
        pass

    def __build_allowed_status(self, allowed_status: str) -> dict:
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
            'list': allowed_list,
            'range': allowed_range,
        }

    def __get_comparator_and_callback(self,
                                      comparator: str) -> Tuple[str, Callable]:
        """Gets the comparator and callback

        @type comparator: str
        @param comparator: The value to be compared
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
            '>=': operator.ge,
            '<=': operator.le,
            '>': operator.gt,
            '<': operator.lt,
            '==': operator.eq,
            '!=': operator.ne,
        }
        try:
            match_callback, comparator = set_match(match_dict, comparator)
        except IndexError:
            match_callback = operator.gt
        return (comparator, match_callback)

    def __instance_comparator(
        self,
        cast_type: Union[Type[int], Type[float]],
        key: str,
        value: str
    ) -> Tuple[Union[int, float], Callable[[Union[int, float]], bool]]:
        """Instance the comparator value and callback

        @type cast_type: Union[Type[int], Type[float]]
        @param cast_type: The expected type of the value
        @type key: str
        @param key: The name of the comparator
        @type value: str
        @param value: The value of the comparator
        @returns tuple: The tuple with comparator value and callback
        """
        value_to_compare, comparator_callback = self.__get_comparator_and_callback(value)
        try:
            value_to_compare = cast_type(value_to_compare)
        except ValueError:
            if cast_type is int:
                raise BadArgumentType(
                    f"The {key} comparator must be an integer, not '{value_to_compare}'!"
                )
            raise BadArgumentType(
                f"The {key} comparator must be a number, not '{value_to_compare}'!"
            )
        return (value_to_compare, comparator_callback)

    def __build_comparator(self,
                           time: str,
                           size: str,
                           words: str,
                           lines: str) -> dict:
        """The comparator setter

        @type size: str
        @param size: The size to be compared with response body
        @type time: str
        @param time: The time to be compared with the RTT
        @returns dict: The data comparator
        """
        comparator = {
            'time': None,
            'size': None,
            'words': None,
            'lines': None,
        }
        if time:
            comparator['time'], self._match_time = self.__instance_comparator(
                float, 'time', time
            )
        if size:
            comparator['size'], self._match_size = self.__instance_comparator(
                int, 'size', size
            )
        if words:
            comparator['words'], self._match_words = self.__instance_comparator(
                int, 'words', words
            )
        if lines:
            comparator['lines'], self._match_lines = self.__instance_comparator(
                int, 'lines', lines
            )
        return comparator
