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

from datetime import datetime
import threading
import sys
from typing import Tuple
from math import floor, ceil, log10
from shutil import get_terminal_size

from ...objects.result import Result
from ...utils.consts import MAX_PAYLOAD_LENGTH_TO_OUTPUT, FuzzType
from ...utils.utils import fix_payload_to_output
from ...utils.http_utils import get_parsed_url, get_pure_url
from ...utils.result_utils import ResultUtils


class Colors:
    """Class that handle with the colors"""
    RESET = '\033[0m'
    GRAY = '\033[90m'
    YELLOW = '\033[33m'
    RED = '\u001b[31;1m'
    GREEN = '\u001b[32;1m'
    BLUE = '\u001b[34m'
    BLUE_GRAY = '\033[36m'
    CYAN = '\u001b[36m'
    LIGHT_GRAY = '\u001b[38;5;250m'
    LIGHT_YELLOW = '\u001b[33;1m'
    LIGHT_RED = '\033[91m'
    LIGHT_GREEN = '\u001b[38;5;48m'
    BOLD = '\033[1m'

    @staticmethod
    def disable() -> None:
        """Disable the colors of the program"""
        Colors.RESET = ''
        Colors.GRAY = ''
        Colors.YELLOW = ''
        Colors.RED = ''
        Colors.GREEN = ''
        Colors.BLUE = ''
        Colors.BLUE_GRAY = ''
        Colors.CYAN = ''
        Colors.LIGHT_GRAY = ''
        Colors.LIGHT_YELLOW = ''
        Colors.LIGHT_RED = ''
        Colors.LIGHT_GREEN = ''
        Colors.BOLD = ''


class CliOutput:
    """Class that handle with the outputs

    Attributes:
        lock: The threads locker for screen output
        break_line: A string to break line
        last_inline: A flag to say if the last output was inline or not
        info: The info label
        warning: The warning label
        error: The error label
        abort: The abort label
        worked: The worked label
        not_worked: The not worked label
    """
    @staticmethod
    def print(msg: str) -> None:
        """Print the message

        @type msg: str
        @param msg: The message
        """
        print(msg)

    @staticmethod
    def help_title(num_spaces: int, title: str) -> None:
        """Output the help title

        @type num_spaces: int
        @param num_spaces: The number of spaces before the title
        @type title: str
        @param title: The title or subtitle
        """
        print("\n"+' '*num_spaces+title)

    @staticmethod
    def help_content(num_spaces: int, command: str, desc: str) -> None:
        """Output the help content

        @type num_spaces: int
        @param num_spaces: The number of spaces before the content
        @type command: str
        @param command: The command to be used in the execution argument
        @type desc: str
        @param desc: The description of the command
        """
        max_command_size_with_space = 27
        if (len(command)+num_spaces) <= max_command_size_with_space:
            print(' '
                  * num_spaces
                  + ("{:<" + str(max_command_size_with_space-num_spaces) + "}")
                  .format(command)
                  + ' ' + desc)
        else:
            print(' '
                  * num_spaces
                  + ("{:<" + str(max_command_size_with_space-num_spaces) + "}")
                  .format(command))
            print(' '*(max_command_size_with_space)+' '+desc)

    def __init__(self):
        self.__lock = threading.Lock()
        self.__last_inline = False
        self.__info = f'{Colors.GRAY}[{Colors.BLUE_GRAY}INFO{Colors.GRAY}]{Colors.RESET} '
        self.__warning = f'{Colors.GRAY}[{Colors.YELLOW}WARNING{Colors.GRAY}]{Colors.RESET} '
        self.__error = f'{Colors.GRAY}[{Colors.RED}ERROR{Colors.GRAY}]{Colors.RESET} '
        self.__abort = f'{Colors.GRAY}[{Colors.RED}ABORT{Colors.GRAY}]{Colors.RESET} '
        self.__worked = f'{Colors.GRAY}[{Colors.GREEN}+{Colors.GRAY}]{Colors.RESET} '
        self.__not_worked = f'{Colors.GRAY}[{Colors.RED}-{Colors.GRAY}]{Colors.RESET} '

    def set_simple_output_mode(self) -> None:
        """Set the display to simple output mode, change labels"""
        def get_blank_time() -> str:
            return ''

        self.__get_time = get_blank_time
        self.__info = f'{Colors.GRAY}[{Colors.BLUE_GRAY}*{Colors.GRAY}]{Colors.RESET} '
        self.__warning = f'{Colors.GRAY}[{Colors.YELLOW}!{Colors.GRAY}]{Colors.RESET} '
        self.__error = f'{Colors.GRAY}[{Colors.RED}!!{Colors.GRAY}]{Colors.RESET} '
        self.__abort = f'{Colors.GRAY}[{Colors.RED}AB{Colors.GRAY}]{Colors.RESET} '
        self.__worked = f'{Colors.GRAY}[{Colors.GREEN}+{Colors.GRAY}]{Colors.RESET} '
        self.__not_worked = f'{Colors.GRAY}[{Colors.RED}-{Colors.GRAY}]{Colors.RESET} '

    def set_new_job(self, total_requests: int) -> None:
        """Set the variables from job manager

        @type total_requests: int
        @param total_requests: The number of requests that'll be made
        """
        self.__total_requests = total_requests
        self.__request_indent = ceil(log10(total_requests))
        self.__progress_length = (38  # Progress bar, spaces, square brackets and slashes
                                  + MAX_PAYLOAD_LENGTH_TO_OUTPUT
                                  + self.__request_indent * 2)

    def info_box(self, msg: str) -> None:
        """Print the message with a info label

        @type msg: str
        @param msg: The message
        """
        print(f'{self._get_break()}{self.__get_time()}{self.__get_info(msg)}')

    def error_box(self, msg: str) -> None:
        """End the application with error label and a message

        @type msg: str
        @param msg: The message
        """
        exit(f'{self._get_break()}{self.__get_time()}{self.__get_error(msg)}')

    def warning_box(self, msg: str) -> None:
        """Print the message with a warning label

        @type msg: str
        @param msg: The message
        """
        with self.__lock:
            sys.stdout.flush()
            print(f'{self._get_break()}{self.__get_time()}{self.__get_warning(msg)}')

    def abort_box(self, msg: str) -> None:
        """Print the message with abort label and a message

        @type msg: str
        @param msg: The message
        """
        with self.__lock:
            sys.stdout.flush()
            print(f'{self._get_break()}{self.__get_time()}{self.__get_abort(msg)}')

    def worked_box(self, msg: str) -> None:
        """Print the message with worked label and a message

        @type msg: str
        @param msg: The message
        """
        print(f'{self.__get_time()}{self.__get_worked(msg)}')

    def not_worked_box(self, msg: str) -> None:
        """Print the message with not worked label and a message

        @type msg: str
        @param msg: The message
        """
        with self.__lock:
            print(f"{self.__get_time()}{self.__get_not_worked(msg)}")

    def ask_yes_no(self, ask_type: str, msg: str) -> bool:
        """Ask a question for the user

        @type ask_type: str
        @param ask_type: The type of the asker
        @type msg: str
        @param msg: The message
        @returns bool: The answer based on the user's input
        """
        if ask_type == 'warning':
            get_type = self.__get_warning
        else:
            get_type = self.__get_info
        print(f"{self._get_break()}{self.__get_time()}{get_type(msg)} (y/N) ", end='')
        action = input()
        if action == 'y' or action == 'Y':
            return True
        return False

    def ask_data(self, msg: str) -> str:
        """Ask data for the user

        @type msg: str
        @param msg: The message
        @returns mixed: The data asked
        """
        print(f"{self._get_break()}{self.__get_time()}{self.__get_info(msg)}", end=': ')
        return input()

    def print_config(self, key: str, value: str = '', spaces: int = 0) -> None:
        """The config's printer function

        @type key: str
        @param key: The name of the config
        @type value: str
        @param value: The value of that config
        @type spaces: int
        @param spaces: The number of spaces to indent the config output
        """
        print(f"{' '*(spaces+3)}{Colors.BLUE}{key}: "
              f"{Colors.LIGHT_YELLOW}{value}{Colors.RESET}")

    def print_configs(self,
                      target: dict,
                      dictionary: dict) -> None:
        """Prints the program configuration

        @type target: dict
        @param taget: The target
        @type dictionary: dict
        @param dictionary: The dictionary used in the tests
        """
        print("")
        spaces = 3
        self.print_config("Target", get_parsed_url(get_pure_url(target['url'])).hostname)
        self.print_config("Method", target['method'], spaces)
        self.print_config("HTTP headers", target['header'], spaces)
        if target['body']:
            self.print_config("Body data", target['body'], spaces)
        self.print_config("Fuzzing type", target['type_fuzzing'], spaces)
        dict_size = dictionary['len']
        if 'removed' in dictionary.keys() and dictionary['removed']:
            dict_size = (f"{dictionary['len']} "
                         f"(removed {dictionary['removed']} "
                         f"duplicated payloads)")
        self.print_config("Dictionary size", dict_size)
        print("")

    def get_percentage(self, item_index: int) -> str:
        """Get the percentage string from item_index per total_requests

        @type item_index: int
        @param item_index: The actual request index
        @returns str: The percentage str
        """
        return f"{self._get_percentage_value(item_index, self.__total_requests)}%"

    def progress_status(self,
                        item_index: int,
                        payload: str,
                        current_job: int,
                        total_jobs: int) -> None:
        """Output the progress status of the fuzzing

        @type item_index: int
        @param item_index: The actual request index
        @type payload: str
        @param payload: The payload used in the request
        """
        jobs_indent = ceil(log10(total_jobs))
        progress_length = self.__progress_length + (2 * jobs_indent)
        if progress_length <= get_terminal_size()[0]:
            percentage_value = self._get_percentage_value(item_index, self.__total_requests)
            status = self._get_progress_bar(percentage_value)
            payload = fix_payload_to_output(payload)
            status += (f" {Colors.LIGHT_YELLOW}{percentage_value:>3}% {Colors.RESET}"
                       + f"{Colors.GRAY}[{Colors.LIGHT_GRAY}{item_index:>{self.__request_indent}}"
                       + f"{Colors.GRAY}/{Colors.LIGHT_GRAY}{self.__total_requests}"
                       + f"{Colors.GRAY}]{Colors.RESET} "
                       + f"{Colors.GRAY}[{Colors.LIGHT_GRAY}{current_job:>{jobs_indent}}"
                       + f"{Colors.GRAY}/{Colors.LIGHT_GRAY}{total_jobs}"
                       + f"{Colors.GRAY}]{Colors.RESET}")
            status += f"{Colors.GRAY} :: {Colors.LIGHT_GRAY}{payload:<{MAX_PAYLOAD_LENGTH_TO_OUTPUT}}"
            with self.__lock:
                if not self.__last_inline:
                    self.__last_inline = True
                    self.__erase_line()
                print(f"\r{status}", end='')

    def print_result(self, result: Result, vuln_validator: bool) -> None:
        """Custom output print for box mode

        @type result: Result
        @param result: The result object
        @type vuln_validator: bool
        @param vuln_validator: Case the output is marked as vulnerable
        """
        formatted_result_str = self.__get_formatted_result(result)
        if not vuln_validator:
            self.not_worked_box(formatted_result_str)
        else:
            with self.__lock:
                if self.__last_inline:
                    self.__last_inline = False
                    self.__erase_line()
                self.worked_box(formatted_result_str)

    def _get_break(self) -> str:
        """Get a break line if the last message was inline

        @returns str: The break line
        """
        if self.__last_inline:
            self.__last_inline = False
            return '\n'
        return ''

    def _get_percentage_value(self, item_index: int, total_requests: int) -> int:
        """Get the percentage from item_index per total_requests

        @type item_index: int
        @param item_index: The actual request index
        @type total_requests: int
        @param total_requests: The total of requests quantity
        @returns int: The percentage value
        """
        return int((item_index/total_requests)*100)

    def _get_progress_bar(self, percentage_value: int) -> str:
        """Get a formated progress bar

        @type percentage_value: int
        @param percentage_value: The percentage value of progress status
        @returns str: The formated progress bar
        """
        bar_size = floor(percentage_value/5)
        spaces = 20-bar_size
        return (f"{Colors.GRAY}["
                f"{Colors.LIGHT_GREEN}{Colors.BOLD}{'#'*bar_size}{Colors.RESET}{' '*spaces}"
                f"{Colors.GRAY}]{Colors.RESET}")

    def __get_time(self) -> str:
        """Get a time label

        @returns str: The time label with format HH:MM:SS
        """
        time = datetime.now().strftime("%H:%M:%S")
        return (f'{Colors.GRAY}[{Colors.LIGHT_GREEN}{time}'
                f'{Colors.GRAY}]{Colors.RESET} ')

    def __get_info(self, msg: str) -> str:
        """The info getter, with a custom message

        @type msg: str
        @param msg: The custom message
        @returns str: The message with info label
        """
        return f'{self.__info}{msg}'

    def __get_warning(self, msg: str) -> str:
        """The warning getter, with a custom message

        @type msg: str
        @param msg: The custom message
        @returns str: The message with warning label
        """
        return f'{self.__warning}{msg}'

    def __get_error(self, msg: str) -> str:
        """The error getter, with a custom message

        @type msg: str
        @param msg: The custom message
        @returns str: The message with error label
        """
        return f'{self.__error}{msg}'

    def __get_abort(self, msg: str) -> str:
        """The abort getter, with a custom message

        @type msg: str
        @param msg: The custom message
        @returns str: The message with abort label
        """
        return f'{self.__abort}{msg}'

    def __get_worked(self, msg: str) -> str:
        """The worked getter, with a custom message

        @type msg: str
        @param msg: The custom message
        @returns str: The message with worked label
        """
        return f'{self.__worked}{msg}'

    def __get_not_worked(self, msg: str) -> str:
        """The not worked getter, with a custom message

        @type msg: str
        @param msg: The custom message
        @returns str: The message with not worked label
        """
        return f'{self.__not_worked}{Colors.LIGHT_GRAY}{msg}{Colors.RESET}'

    def __erase_line(self) -> None:
        """Erases the current line"""
        sys.stdout.flush()
        sys.stdout.write("\033[1K")
        sys.stdout.write("\033[0G")
        sys.stdout.flush()

    def __get_formatted_payload(self, result: Result) -> str:
        """Formats the payload to output

        @type result: Result
        @param result: The result of the request
        @returns str: The formatted payload to output
        """
        if result.fuzz_type == FuzzType.PATH_FUZZING:
            formatted_payload = result.history.parsed_url.path
            if not formatted_payload:
                return result.history.url
            return formatted_payload
        if result.fuzz_type == FuzzType.SUBDOMAIN_FUZZING:
            return result.history.parsed_url.hostname
        return result.payload

    def __get_formatted_status(self, status: int) -> str:
        """Formats the status code to output

        @type status: int
        @param status: The status code of the response
        @returns str: The formatted status code to output
        """
        status_color = Colors.BOLD
        if status == 404:
            status_color = ''
        elif status >= 200 and status < 300:
            status_color += Colors.GREEN
        elif status >= 300 and status < 400:
            status_color += Colors.LIGHT_YELLOW
        elif status >= 400 and status < 500:
            if status == 401 or status == 403:
                status_color += Colors.CYAN
            else:
                status_color += Colors.BLUE
        elif status >= 500 and status < 600:
            status_color += Colors.RED
        return f"{status_color}{status}{Colors.RESET}"

    def __get_formatted_result_items(self, result: Result) -> Tuple[
        str, str, str, str, str, str
    ]:
        """Format the result items to the output

        @type result: Result
        @param result: The result of the request
        @returns Tuple[str, str, str, str, str, str]: The tuple with the formatted result items
        """
        payload, rtt, length, words, lines = ResultUtils.get_formatted_result(
            self.__get_formatted_payload(result), result.history.rtt,
            result.history.body_size, result.words, result.lines
        )
        return (payload, self.__get_formatted_status(result.history.status), rtt, length, words, lines)

    def __get_formatted_result(self, result: Result) -> str:
        """Format the entire result message

        @type result: Result
        @param result: The result of the request
        @returns str: The formatted result message to output
        """
        formatted_items = self.__get_formatted_result_items(result)
        payload, status_code, rtt, length, words, lines = formatted_items
        formatted_result_str = (
            f"{payload} {Colors.GRAY}["
            f"{Colors.LIGHT_GRAY}Code{Colors.RESET} {status_code} | "
            f"{Colors.LIGHT_GRAY}RTT{Colors.RESET} {rtt} | "
            f"{Colors.LIGHT_GRAY}Size{Colors.RESET} {length} | "
            f"{Colors.LIGHT_GRAY}Words{Colors.RESET} {words} | "
            f"{Colors.LIGHT_GRAY}Lines{Colors.RESET} {lines}{Colors.GRAY}]{Colors.RESET}"
        )
        formatted_result_str += f"{Colors.LIGHT_YELLOW}{result.get_description()}{Colors.RESET}"
        return formatted_result_str
