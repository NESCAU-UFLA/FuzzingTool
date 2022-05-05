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

import time
import threading
from argparse import Namespace

from .cli_output import CliOutput, Colors
from ... import __version__
from ...fuzz_lib import FuzzLib
from ...utils.argument_utils import build_verbose_mode
from ...utils.consts import FUZZ_TYPE_NAME
from ...utils.http_utils import get_parsed_url, get_pure_url
from ...persistence import Logger, Report
from ...objects import BaseItem, Error, Payload, Result, HttpHistory
from ...exceptions import FuzzLibException, StopActionInterrupt, RequestException
from ...exceptions.base_exceptions import FuzzingToolException


def banner() -> str:
    """Gets the program banner

    @returns str: The program banner
    """
    banner = (f"{Colors.BLUE_GRAY}   ____                        _____       _\n" +
              f"{Colors.BLUE_GRAY}  |  __|_ _ ___ ___ _ ___ ___ |_   _|_ ___| |{Colors.RESET} Version {__version__}\n" +
              f"{Colors.BLUE_GRAY}  |  __| | |- _|- _|'|   | . |  | | . | . | |\n" +
              f"{Colors.BLUE_GRAY}  |_|  |___|___|___|_|_|_|_  |  |_|___|___|_|\n" +
              f"{Colors.BLUE_GRAY}                         |___|{Colors.RESET}\n\n" +
              "  [!] Disclaimer: We're not responsible for the misuse of this tool.\n" +
              "      This project was created for educational purposes\n" +
              "      and should not be used in environments without legal authorization.\n")
    return banner


class CliController(FuzzLib):
    """Class that handle with the CLI application

    Attributes:
        lock: A thread locker to prevent overwrites on logfiles
        logger: The object to handle with the program log
        cli_output: The object that handles the terminal output
    """
    def __init__(self, arguments: Namespace):
        super().__init__(**vars(arguments))
        self.lock = threading.Lock()
        self.logger = Logger()
        self.cli_output = CliOutput()

    def is_verbose_mode(self) -> bool:
        """The verboseMode getter

        @returns bool: The verbose mode flag
        """
        return self.verbose[0]

    def main(self) -> None:
        if self.args["simple_output"]:
            self.cli_output.set_simple_output_mode()
        else:
            CliOutput.print(banner())
        self.cli_output.info_box("Setting up arguments ...")
        try:
            self.init()
        except FuzzingToolException as e:
            self.cli_output.error_box(str(e))
        if not self.args["simple_output"]:
            self.print_configs()
        try:
            self.check_connection()
            self.prepare()
        except KeyboardInterrupt:
            self.cli_output.abort_box("Test aborted by the user")
        except FuzzingToolException as e:
            self.cli_output.error_box(str(e))
        else:
            self.start()
            self.show_footer()
            self.cli_output.info_box("Test completed")

    def init(self) -> None:
        """The initialization function.
           Set the application variables including plugins requires
        """
        self.verbose = build_verbose_mode(
            self.args["common_verbose"],
            self.args["detailed_verbose"]
        )
        self.__init_report()
        super().init()

    def print_configs(self) -> None:
        """Print the program configuration"""
        self.cli_output.print_configs(
            target={
                'url': self.requester.get_url(),
                'method': self.requester.get_method(),
                'header': 'custom' if self.args["raw_http"] else 'default',
                'body': self.args["data"],
                'type_fuzzing': FUZZ_TYPE_NAME[self.requester.get_fuzzing_type()],
                },
            dictionary=self.dict_metadata
        )

    def check_connection(self) -> None:
        """Test the connection to target.
           If data fuzzing is detected, check for redirections
        """
        self.cli_output.info_box(f"Validating {self.requester.get_url()} ...")
        if self.is_verbose_mode():
            self.cli_output.info_box("Testing connection ...")
        try:
            self.requester.test_connection()
        except RequestException as e:
            if not self.cli_output.ask_yes_no('warning',
                                              f"{str(e)}. Continue anyway?"):
                raise FuzzLibException("No target left for fuzzing")
        else:
            if self.is_verbose_mode():
                self.cli_output.info_box("Connection status: OK")

    def start(self) -> None:
        """Starts the fuzzing application.
           Each target is fuzzed based on their own methods list
        """
        self.cli_output.info_box("Start fuzzing on "
                                 + get_parsed_url(get_pure_url(self.requester.get_url())).hostname)
        try:
            super().start()
        except StopActionInterrupt as e:
            self.cli_output.abort_box(f"{str(e)}. Program stopped.")

    def prepare(self) -> None:
        """Prepare the application before the fuzzing"""
        self.target_host = get_parsed_url(get_pure_url(self.requester.get_url())).hostname
        if self.is_verbose_mode():
            self.cli_output.info_box(f"Preparing target {self.target_host} ...")
        self.check_ignore_errors()
        if (len(self.scanners) == 1 and
                (self.requester.is_data_fuzzing() and
                 not self.matcher.comparator_is_set())):
            self.cli_output.info_box("DataFuzzing detected, checking for a data comparator ...")
            self.matcher.set_comparator(*self.__get_data_comparator())

    def check_ignore_errors(self) -> None:
        """Check if the user wants to ignore the errors during the tests.
           By default, URL fuzzing (path and subdomain) ignore errors
        """
        if (self.requester.is_url_discovery() or
                self.cli_output.ask_yes_no('info',
                                           ("Do you want to ignore errors on this "
                                            "target, and save them into a log file?"))):
            self.ignore_errors = True
            log_path = self.logger.setup(self.target_host)
            self.cli_output.info_box(f'The logs will be saved on \'{log_path}\'')
        else:
            self.ignore_errors = False

    def show_footer(self) -> None:
        """Show the footer content of the software, after maked the fuzzing.
           The results are shown for each target
        """
        if self.fuzzer:
            if self.summary.elapsed_time:
                self.cli_output.info_box(
                    f"Time taken: {float('%.2f'%(self.summary.elapsed_time))} seconds"
                )
            if self.summary.results:
                self.__handle_valid_results(self.target_host, self.summary.results)
            else:
                self.cli_output.info_box(
                    f"No matched results was found for {self.target_host}"
                )

    def _wait_callback(self, status: int) -> None:
        if not self.fuzzer.is_paused():
            self.fuzzer.pause()
            self.cli_output.warning_box(
                f"Status code {str(status)} detected. Pausing threads ..."
            )
            self.fuzzer.wait_until_pause()
            self.cli_output.info_box(
                f"Waiting for {self.blacklist_status.action_param} seconds ..."
            )
            time.sleep(self.blacklist_status.action_param)
            self.cli_output.info_box("Resuming job ...")
            self.fuzzer.resume()

    def _result_callback(self, result: Result, valid: bool) -> None:
        if self.verbose[0]:
            if valid:
                self.summary.results.append(result)
            self.cli_output.print_result(result, valid)
        else:
            if valid:
                self.summary.results.append(result)
                self.cli_output.print_result(result, valid)
            self.__print_progress(
                result.index, result.payload
            )

    def _request_exception_callback(self, error: Error) -> None:
        if self.ignore_errors:
            if not self.verbose[0]:
                self.__print_progress(
                    error.index, error.payload
                )
            else:
                if self.verbose[1]:
                    self.cli_output.not_worked_box(str(error))
            with self.lock:
                self.logger.write(str(error), error.payload)
        else:
            self.stop_action = str(error)

    def _invalid_hostname_callback(self, error: Error) -> None:
        if self.verbose[0]:
            if self.verbose[1]:
                self.cli_output.not_worked_box(str(error))
        else:
            self.__print_progress(
                error.index, error.payload
            )

    def _init_dictionary(self) -> None:
        try:
            super()._init_dictionary()
        finally:
            if self.is_verbose_mode():
                for e in self.wordlist_errors:
                    self.cli_output.warning_box(str(e))

    def _get_job(self) -> None:
        super()._get_job()
        self.cli_output.set_new_job(self.job_manager.total_requests)

    def _join(self) -> None:
        """Blocks until the fuzzer is running"""
        while self.fuzzer.is_running():
            try:
                super()._join()
            except KeyboardInterrupt:
                self.cli_output.warning_box("Ctrl+C detected, pausing threads ...")
                self._handle_pause()

    def _handle_pause(self) -> None:
        """Handle with the Ctrl+C pause"""
        self.fuzzer.pause()
        self.fuzzer.wait_until_pause()
        self.summary.pause_timer()
        options = "[c]ontinue | [p]rogress | [q]uit"
        if (self.job_manager.has_pending_jobs()
                or self.job_manager.has_pending_jobs_from_providers()
                or self.recursion_manager.has_recursive_job()):
            options += " | [s]kip"
        answer = ''
        while answer not in ['q', 'c', 's']:
            try:
                answer = self.cli_output.ask_data(options)
            except KeyboardInterrupt:
                answer = 'q'
            if answer == 'q':
                self._handle_quit()
            elif answer == 'p':
                self._handle_progress()
            elif answer == "c":
                self._handle_continue()
            elif answer == 's':
                self._handle_skip()

    def _handle_quit(self) -> None:
        """Handle with the quit option when pause"""
        raise StopActionInterrupt("Test aborted")

    def _handle_progress(self) -> None:
        """Handle with the progress option when pause"""
        str_percentage = self.cli_output.get_percentage(BaseItem.index)
        self.cli_output.info_box(
            f"Progress: {Colors.LIGHT_YELLOW}{str_percentage}{Colors.RESET} completed"
        )

    def _handle_continue(self) -> None:
        """Handle with the continue option when pause"""
        self.summary.resume_timer()
        self.fuzzer.resume()

    def _handle_skip(self) -> None:
        """Handle with the skip option when pause"""
        self.fuzzer.stop()
        self.cli_output.abort_box(f"Current job ({self.job_manager.current_job}) skipped")

    def __init_report(self) -> None:
        """Initialize the report"""
        self.report = Report.build(self.args["report_name"])
        Result.save_payload_configs = self.args["save_payload_conf"]
        Result.save_headers = self.args["save_headers"]
        Result.save_body = self.args["save_body"]

    def __get_comparator_value(self,
                               name_value: str,
                               ask_message: str) -> str:
        """Instance the value of a comparator

        @type name_value: str
        @param name_value: The name of the comparator
        @type ask_message: str
        @param ask_message: The message to ask the comparator value
        @returns str: The comparator value
        """
        value = None
        if self.cli_output.ask_yes_no('info',
                                      ("Do you want to match results "
                                       f"based on custom {name_value}?")):
            value = self.cli_output.ask_data(ask_message)
            if not value:
                value = None
        return value

    def __get_data_comparator(self) -> tuple:
        """Check if the user wants to insert
           custom data comparator to validate the responses

        @returns tuple: The data comparator tuple for the Matcher object
        """
        payload = self.cli_output.ask_data("Define an arbitraty payload")
        self.cli_output.info_box(
            f"Making first request with '{payload}' as payload ..."
        )
        try:
            # Make the first request to get some info about the target
            response, rtt = self.requester.request(payload)
        except RequestException as e:
            raise StopActionInterrupt(str(e))
        result_to_comparator = Result(HttpHistory(response, rtt), Payload(payload))
        self.cli_output.print_result(result_to_comparator, False)
        time = self.__get_comparator_value(
            name_value="RTT",
            ask_message="Insert the time (in seconds)"
        )
        length = self.__get_comparator_value(
            name_value="body size",
            ask_message="Insert the body size (in bytes)"
        )
        words = self.__get_comparator_value(
            name_value="quantity of words on body",
            ask_message="Insert the quantity of words"
        )
        lines = self.__get_comparator_value(
            name_value="quantity of lines on body",
            ask_message="Insert the quantity of lines"
        )
        return (time, length, words, lines)

    def __print_progress(self, index: int, payload: str) -> None:
        """Print the progress status

        @type index: int
        @param index: The actual item index
        @type payload: str
        @param payload: The payload used in the previous request
        """
        self.cli_output.progress_status(
            item_index=index,
            payload=payload,
            current_job=self.job_manager.current_job,
            total_jobs=self.job_manager.total_jobs,
        )

    def __handle_valid_results(self,
                               host: str,
                               results: list) -> None:
        """Handle the valid results from footer

        @type host: str
        @param host: The target host
        @type results: list
        @param results: The target results from the fuzzing
        """
        if self.is_verbose_mode():
            self.cli_output.info_box(
                f"Found {len(results)} matched results on target {host}"
            )
            for result in results:
                self.cli_output.print_result(result, True)
            self.cli_output.info_box(f'Saving results for {host} ...')
        report_path = self.report.open(host)
        self.report.write(results)
        self.cli_output.info_box(f"Results saved on {report_path}")
