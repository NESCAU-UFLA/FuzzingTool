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

from ...objects.result import Result
from ...utils.consts import MAX_PAYLOAD_LENGTH_TO_OUTPUT, PATH_FUZZING, SUBDOMAIN_FUZZING
from ...utils.utils import stringfy_list, fix_payload_to_output
from ...utils.http_utils import get_path, get_host, get_pure_url
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
    def disable():
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
        self.__break_line = ''
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

    def set_verbosity_mode(self, verbose_mode: bool) -> None:
        """Set the verbosity mode

        @type verbose_mode: bool
        @param verbose_mode: The verbose mode flag
        """
        if verbose_mode:
            self.__break_line = ''
        else:
            self.__break_line = '\n'

    def info_box(self, msg: str) -> None:
        """Print the message with a info label

        @type msg: str
        @param msg: The message
        """
        print(f'{self.__get_time()}{self.__get_info(msg)}')

    def error_box(self, msg: str) -> None:
        """End the application with error label and a message

        @type msg: str
        @param msg: The message
        """
        exit(f'{self.__get_time()}{self.__get_error(msg)}')

    def warning_box(self, msg: str) -> None:
        """Print the message with a warning label

        @type msg: str
        @param msg: The message
        """
        with self.__lock:
            sys.stdout.flush()
            print(f'{self.__break_line}'
                  f'{self.__get_time()}{self.__get_warning(msg)}')

    def abort_box(self, msg: str) -> None:
        """Print the message with abort label and a message

        @type msg: str
        @param msg: The message
        """
        with self.__lock:
            sys.stdout.flush()
            print(f'{self.__break_line}'
                  f'{self.__get_time()}{self.__get_abort(msg)}')

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
        print(f"{self.__get_time()}{get_type(msg)} (y/N) ", end='')
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
        print(self.__get_time()+self.__get_info(msg), end=': ')
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
        self.print_config("Target", get_host(get_pure_url(target['url'])))
        self.print_config("Methods",
                          stringfy_list(target['methods']),
                          spaces)
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

    def get_percentage(self, item_index: int, total_requests: int) -> str:
        """Get the percentage from item_index / total_requests

        @type item_index: int
        @param item_index: The actual request index
        @type total_requests: int
        @param total_requests: The total of requests quantity
        @returns str: The percentage str
        """
        return f"{str(int((int(item_index)/total_requests)*100))}%"

    def progress_status(self,
                        item_index: int,
                        total_requests: int,
                        payload: str) -> None:
        """Output the progress status of the fuzzing

        @type item_index: int
        @param item_index: The actual request index
        @type total_requests: int
        @param total_requests: The total of requests quantity
        @type payload: str
        @param payload: The payload used in the request
        """
        status = (f"{Colors.GRAY}[{Colors.LIGHT_GRAY}{item_index}"
                  + f"{Colors.GRAY}/{Colors.LIGHT_GRAY}{total_requests}"
                  + f"{Colors.GRAY}]{Colors.RESET} {Colors.LIGHT_YELLOW}"
                  + self.get_percentage(item_index, total_requests)
                  + f"{Colors.RESET}")
        payload = fix_payload_to_output(payload)
        while len(payload) < MAX_PAYLOAD_LENGTH_TO_OUTPUT:
            payload += ' '
        with self.__lock:
            if not self.__last_inline:
                self.__last_inline = True
                self.__erase_line()
            print(f"\r{self.__get_time()}{status}"
                  f"{Colors.GRAY} :: {Colors.LIGHT_GRAY}{payload}", end='')

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
        if result.fuzz_type == PATH_FUZZING:
            try:
                formatted_payload = get_path(result.url)
            except ValueError:
                formatted_payload = result.url
            return formatted_payload
        if result.fuzz_type == SUBDOMAIN_FUZZING:
            return get_host(result.url)
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
            self.__get_formatted_payload(result), result.rtt,
            result.body_size, result.words, result.lines
        )
        return (payload, self.__get_formatted_status(result.status), rtt, length, words, lines)

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
        if result.custom:
            custom_str = ''
            for key, value in result.custom.items():
                if (value is not None and isinstance(value, bool)) or value:
                    custom_str += (f"\n{Colors.LIGHT_YELLOW}|_ {key}: "
                                   f"{ResultUtils.format_custom_field(value)}{Colors.RESET}")
            formatted_result_str += custom_str
        return formatted_result_str
