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

from typing import List, Tuple, Union

from .consts import FUZZING_MARK, MAX_PAYLOAD_LENGTH_TO_OUTPUT


def get_indexes_to_parse(content: str,
                         search_for: str = FUZZING_MARK) -> List[int]:
    """Gets the indexes of the searched substring into a string content

    @type content: str
    @param content: The parameter content
    @type search_for: str
    @param search_for: The substring to be searched indexes
                       on the given content
    @returns List[int]: The positions indexes of the searched substring
    """
    return [i for i in range(len(content)) if content.startswith(search_for, i)]


def split_str_to_list(string: str,
                      separator: str = ',',
                      ignores: str = '\\') -> List[str]:
    """Split the given string into a list, using a separator

    @type string: str
    @param string: The string to be splited
    @type separator: str
    @param separator: A separator to split the string
    @type ignores: str
    @param ignores: A string to ignores the separator
    @returns List[str]: The splited string
    """
    if string:
        if f'{ignores}{separator}' in string:
            final = []
            buffer = ''
            for substr in string.split(separator):
                if substr[-1] == ignores:
                    buffer += substr[:-1]+separator
                else:
                    final.extend([buffer+substr])
                    buffer = ''
            return final
        return string.split(separator)
    return []


def stringfy_list(one_list: list) -> str:
    """Stringfies a list

    @type one_list: list
    @param one_list: A list to be stringed
    @returns str: The stringed list
    """
    if not one_list:
        return ''
    output = ''
    for i in range(len(one_list)-1):
        output += f"{one_list[i]},"
    output += one_list[-1]
    return output


def parse_option_with_args(option: str) -> Tuple[str, str]:
    """Parse the option name into name and parameter

    @type option: str
    @param option: The option argument
    @returns tuple[str, str]: The option name and parameter
    """
    if '=' in option:
        option, param = option.split('=', 1)
    else:
        param = ''
    return (option, param)


def get_human_length(length: int) -> Tuple[Union[int, float], str]:
    """Get the human readable length from the result

    @type length: int
    @param length: The length of the response body
    @returns Tuple[int|float, str]: The tuple with new length
                                    and the readable order
    """
    for order in ["B ", "KB", "MB", "GB"]:
        if length < 1024:
            return (length, order)
        length /= 1024
    return (length, "TB")


def get_formatted_rtt(rtt: float) -> Tuple[Union[int, float], str]:
    """Formats the rtt from the result to output

    @type rtt: float
    @param rtt: The elapsed time of a request
    @returns Tuple[int|float, str]: The tuple with the formatted rtt
    """
    if rtt < 1:
        return (int(rtt*1000), "ms")
    for order in ["s ", "m "]:
        if rtt < 60:
            return (rtt, order)
        rtt /= 60
    return (rtt, 'h ')


def fix_payload_to_output(payload: str) -> str:
    """Fix the payload's size

    @type payload: str
    @param payload: The payload used in the request
    @returns str: The fixed payload to output
    """
    if '	' in payload:
        payload = payload.replace('	', ' ')
    if len(payload) > MAX_PAYLOAD_LENGTH_TO_OUTPUT:
        return f'{payload[:(MAX_PAYLOAD_LENGTH_TO_OUTPUT-3)]}...'
    return payload


def check_range_list(content: str) -> List[Union[int, str]]:
    """Checks if the given content has a range list,
       and make a list of the range specified

    @type content: str
    @param content: The string content to check for range
    @returns List[int|str]: The list with the compiled content
    """
    if '\\-' in content:
        content = content.replace('\\-', '-')
    elif '-' in content:
        left, right = content.split('-', 1)
        if not left or not right:
            return [content]
        try:
            # Checks if the left and right digits from the mark are integers
            int(left[-1])
            int(right[0])
        except ValueError:
            content = _get_letter_range(left, right)
        else:
            content = _get_number_range(left, right)
        return content
    return [content]


def _get_letter_range(left: str, right: str) -> List[str]:
    """Get the alphabet range list [a-z] [A-Z] [z-a] [Z-A]

    @type left: str
    @param left: The left string of the division mark
    @type right: str
    @param right: The right string of the division mark
    @returns List[str]: The list with the range
    """
    left_digit, left_str = left[-1], left[:-1]
    right_digit, right_str = right[0], right[1:]
    compiled_list = []
    order_left_digit = ord(left_digit)
    order_right_digit = ord(right_digit)
    if order_left_digit <= order_right_digit:
        range_list = range(order_left_digit, order_right_digit+1)
    else:
        range_list = range(order_left_digit, order_right_digit-1, -1)
    for c in range_list:
        compiled_list.append(
            f"{left_str}{chr(c)}{right_str}"
        )
    return compiled_list


def _get_number_range(left: str, right: str) -> List[int]:
    """Get the number range list

    @type left: str
    @param left: The left string of the division mark
    @type right: str
    @param right: The right string of the division mark
    @returns List[int]: The list with the range
    """
    is_number = True
    i = len(left)
    while is_number and i > 0:
        try:
            int(left[i-1])
        except ValueError:
            is_number = False
        else:
            i -= 1
    left_digit, left_str = int(left[i:]), left[:i]
    is_number = True
    i = 0
    while is_number and i < (len(right)-1):
        try:
            int(right[i+1])
        except ValueError:
            is_number = False
        else:
            i += 1
    right_digit, right_str = int(right[:(i+1)]), right[(i+1):]
    compiled_list = []
    if left_digit < right_digit:
        range_list = range(left_digit, right_digit+1)
    else:
        range_list = range(left_digit, right_digit-1, -1)
    for d in range_list:
        compiled_list.append(
            f"{left_str}{str(d)}{right_str}"
        )
    return compiled_list
