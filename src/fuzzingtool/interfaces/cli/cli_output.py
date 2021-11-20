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
from typing import Callable, Tuple

from ...utils.utils import stringfy_list, get_human_length
from ...utils.http_utils import get_host, get_pure_url


def fix_payload_to_output(payload: str,
                          max_length: int = 30,
                          is_progress_status: bool = False) -> str:
    """Fix the payload's size

    @type payload: str
    @param payload: The payload used in the request
    @type max_length: int
    @param max_length: The maximum length of the payload on output
    @type is_progress_status: bool
    @param is_progress_status: A flag to say if the function
                               was called by the progress_status or not
    @returns str: The fixed payload to output
    """
    if '	' in payload:
        payload = payload.replace('	', ' ')
    if len(payload) > max_length:
        output = ""
        for i in range(27):
            output += payload[i]
        output += '...'
        return output
    if is_progress_status:
        while len(payload) < max_length:
            payload += ' '
    return payload


def get_formated_result(payload: str,
                        rtt: float,
                        length: int) -> Tuple[str, str, str]:
    """Format the result into a dict of strings

    @type payload: str
    @param payload: The payload used in the request
    @type rtt: float
    @param rtt: The request and response elapsed time
    @type length: int
    @param length: The response body length in bytes
    @returns tuple[str, str, str]: The result formated with strings
    """
    length, order = get_human_length(int(length))
    if type(length) is float:
        length = "%.2f" % length
    length = '{:>7}'.format(length)
    return (
        '{:<30}'.format(fix_payload_to_output(payload)),
        '{:>10}'.format(rtt),
        f"{length} {order}",
    )


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
        self.__abord = f'{Colors.GRAY}[{Colors.RED}ABORT{Colors.GRAY}]{Colors.RESET} '
        self.__worked = f'{Colors.GRAY}[{Colors.GREEN}+{Colors.GRAY}]{Colors.RESET} '
        self.__not_worked = f'{Colors.GRAY}[{Colors.RED}-{Colors.GRAY}]{Colors.RESET} '

    def set_simple_output_mode(self) -> None:
        """Set the display to simple output mode, change labels"""
        self.__get_time = lambda: ''
        self.__info = f'{Colors.GRAY}[{Colors.BLUE_GRAY}*{Colors.GRAY}]{Colors.RESET} '
        self.__warning = f'{Colors.GRAY}[{Colors.YELLOW}!{Colors.GRAY}]{Colors.RESET} '
        self.__error = f'{Colors.GRAY}[{Colors.RED}!!{Colors.GRAY}]{Colors.RESET} '
        self.__abord = f'{Colors.GRAY}[{Colors.RED}AB{Colors.GRAY}]{Colors.RESET} '
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

    def set_message_callback(self, get_message_callback: Callable) -> None:
        """Set the print content mode for the results

        @type get_message_callback: Callable
        @param get_message_callback: The get message callback for the results
        """
        self.__get_message = get_message_callback

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
        else:
            return False

    def ask_data(self, msg: str) -> str:
        """Ask data for the user

        @type msg: str
        @param msg: The message
        @returns mixed: The data asked
        """
        print(self.__get_time()+self.__get_info(msg)+': ', end='')
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
                      output: str,
                      verbose: str,
                      targets: list,
                      dictionaries: list,
                      prefix: list,
                      suffix: list,
                      case: str,
                      encoder: str,
                      encode_only: str,
                      match: dict,
                      scanner: str,
                      blacklist_status: dict,
                      delay: float,
                      threads: int,
                      report: str) -> None:
        """Prints the program configuration

        @type output: str
        @param output: The display output mode
        @type verbose: str
        @param verbose: The verbosity mode
        @type targets: list
        @param tagets: The targets list
        @type dictionaries: list
        @param dictionaries: The dictionaries used in the tests
        @type prefix: list
        @param prefix: The prefixes used with the payload
        @type suffix: list
        @param suffix: The suffixes used with the payload
        @type case: str
        @param case: The payload case
        @type encoder: str
        @param encoder: The encoders string that caontains
                        the encoder name and parameters
        @type encode_only: str
        @param encode_only: The encode only regex
        @type match: dict
        @param match: The matcher options on a dictionary
        @type scanner: str
        @param scanner: The scanner string that caontains
                        the scanner name and parameters
        @type blacklist_status: dict
        @param blacklist_status: The blacklist status arguments
                                 (codes and action taken)
        @type delay: float
        @param delay: The delay between each request
        @type threads: int
        @param threads: The number of threads used in the tests
        @type report: str
        @param report: The report name and/or format
        """
        print("")
        global_dict = False
        if len(dictionaries) != len(targets):
            global_dict = True
            this_dict = dictionaries[0]
        spaces = 3
        self.print_config("Output mode", output)
        self.print_config("Verbosity mode", verbose)
        for i, target in enumerate(targets):
            self.print_config("Target", get_host(get_pure_url(target['url'])))
            self.print_config("Methods",
                              stringfy_list(target['methods']),
                              spaces)
            self.print_config("HTTP headers",
                              'custom' if target['header'] else 'default',
                              spaces)
            if target['body']:
                self.print_config("Body data", target['body'], spaces)
            self.print_config("Fuzzing type", target['type_fuzzing'], spaces)
            if not global_dict:
                this_dict = dictionaries[i]
                dict_size = this_dict['len']
                if 'removed' in this_dict.keys() and this_dict['removed']:
                    dict_size = (f"{this_dict['len']} "
                                 f"(removed {this_dict['removed']} "
                                 f"duplicated payloads)")
                self.print_config("Dictionary size", dict_size, spaces)
                self.print_config("Wordlists",
                                  stringfy_list(this_dict['wordlists']),
                                  spaces)
        if global_dict:
            dict_size = this_dict['len']
            if 'removed' in this_dict.keys() and this_dict['removed']:
                dict_size = (f"{this_dict['len']} "
                             f"(removed {this_dict['removed']} "
                             f"duplicated payloads)")
            self.print_config("Dictionary size", dict_size)
            self.print_config("Wordlists",
                              stringfy_list(this_dict['wordlists']))
        if prefix:
            self.print_config("Prefix", stringfy_list(prefix))
        if suffix:
            self.print_config("Suffix", stringfy_list(suffix))
        if case:
            self.print_config("Payload case", case)
        if encoder:
            encode_msg = encoder
            if encode_only:
                encode_msg = f"{encoder} (encode with regex {encode_only})"
            self.print_config("Encoder", encode_msg)
        for key, value in match.items():
            if value:
                self.print_config(f"Match {key}", value)
        if scanner:
            self.print_config("Scanner", scanner)
        if blacklist_status:
            self.print_config("Blacklisted status",
                              (f"{blacklist_status['status']} "
                               f"with action {blacklist_status['action']}"))
        if delay:
            self.print_config("Delay", f"{delay} seconds")
        self.print_config("Threads", threads)
        if report:
            self.print_config("Report", report)
        print("")

    def progress_status(self,
                        request_index: int,
                        total_requests: int,
                        payload: str) -> None:
        """Output the progress status of the fuzzing

        @type request_index: int
        @param request_index: The actual request index
        @type total_requests: int
        @param total_requests: The total of requests quantity
        @type payload: str
        @param payload: The payload used in the request
        """
        status = (f"{Colors.GRAY}[{Colors.LIGHT_GRAY}{request_index}"
                  f"{Colors.GRAY}/{Colors.LIGHT_GRAY}{total_requests}"
                  f"{Colors.GRAY}]{Colors.RESET} {Colors.LIGHT_YELLOW}"
                  f"{str(int((int(request_index)/total_requests)*100))}%"
                  f"{Colors.RESET}")
        payload = Colors.LIGHT_GRAY + fix_payload_to_output(
            payload=payload,
            is_progress_status=True
        )
        with self.__lock:
            if not self.__last_inline:
                self.__last_inline = True
                self.__erase_line()
            print(f"\r{self.__get_time()}{status}"
                  f"{Colors.GRAY} :: {payload}", end='')

    def print_result(self, result: dict, vuln_validator: bool) -> None:
        """Custom output print for box mode

        @type result: dict
        @param result: The result dictionary
        @type vuln_validator: bool
        @param vuln_validator: Case the output is marked as vulnerable
        """
        msg = self.__get_message(result)
        if not vuln_validator:
            self.not_worked_box(msg)
        else:
            with self.__lock:
                if self.__last_inline:
                    self.__last_inline = False
                    self.__erase_line()
                self.worked_box(msg)

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
        return f'{self.__abord}{msg}'

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
