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
from ..argument_builder import ArgumentBuilder as AB
from ... import version
from ...api.fuzz_controller import FuzzController
from ...core.bases.base_plugin import Plugin
from ...utils.http_utils import get_host, get_pure_url
from ...utils.logger import Logger
from ...reports.report import Report
from ...objects import Error, Result
from ...exceptions.base_exceptions import FuzzingToolException
from ...exceptions.main_exceptions import FuzzControllerException, StopActionInterrupt
from ...exceptions.request_exceptions import RequestException


def banner() -> str:
    """Gets the program banner

    @returns str: The program banner
    """
    banner = (f"{Colors.BLUE_GRAY}   ____                        _____       _\n" +
              f"{Colors.BLUE_GRAY}  |  __|_ _ ___ ___ _ ___ ___ |_   _|_ ___| |{Colors.RESET} Version {version()}\n" +
              f"{Colors.BLUE_GRAY}  |  __| | |- _|- _|'|   | . |  | | . | . | |\n" +
              f"{Colors.BLUE_GRAY}  |_|  |___|___|___|_|_|_|_  |  |_|___|___|_|\n" +
              f"{Colors.BLUE_GRAY}                         |___|{Colors.RESET}\n\n" +
              "  [!] Disclaimer: We're not responsible for the misuse of this tool.\n" +
              "      This project was created for educational purposes\n" +
              "      and should not be used in environments without legal authorization.\n")
    return banner


class CliController(FuzzController):
    """Class that handle with the entire application

    Attributes:
        requesters: The requesters list
        started_time: The time when start the fuzzing test
        fuzzer: The fuzzer object to handle with the fuzzing test
        lock: A thread locker to prevent overwrites on logfiles
        blacklist_status: The blacklist status object
        logger: The object to handle with the program log
    """
    def __init__(self, arguments: Namespace):
        super().__init__(**vars(arguments))
        self.lock = threading.Lock()
        self.logger = Logger()
        self.cli_output = CliOutput()
        self.verbose = AB.build_verbose_mode(self.args["common_verbose"],
                                             self.args["detailed_verbose"])

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
        try:
            self.cli_output.info_box("Setting up arguments ...")
            self.init()
            if not self.args["simple_output"]:
                self.print_configs()
        except FuzzingToolException as e:
            self.cli_output.error_box(str(e))
        self.cli_output.set_verbosity_mode(self.is_verbose_mode())
        try:
            self.check_connection()
            self.start()
        except KeyboardInterrupt:
            if self.fuzzer and self.fuzzer.is_running():
                self.cli_output.abort_box("Test aborted, stopping threads ...")
                self.fuzzer.stop()
            self.cli_output.abort_box("Test aborted by the user")
        except FuzzingToolException as e:
            self.cli_output.error_box(str(e))
        finally:
            self.show_footer()
            self.cli_output.info_box("Test completed")

    def init(self) -> None:
        """The initialization function.
           Set the application variables including plugins requires
        """
        self.__init_report()
        super().init()

    def print_configs(self) -> None:
        """Print the program configuration"""
        if self.verbose[1]:
            verbose = 'detailed'
        elif self.verbose[0]:
            verbose = 'common'
        else:
            verbose = 'quiet'
        if self.args["lower"]:
            case = 'lowercase'
        elif self.args["upper"]:
            case = 'uppercase'
        elif self.args["capitalize"]:
            case = 'capitalize'
        else:
            case = None
        self.cli_output.print_configs(
            output='normal'
                   if not self.args["simple_output"]
                   else 'simple',
            verbose=verbose,
            target=self.target,
            dictionary=self.dict_metadata,
            prefix=self.args["prefix"],
            suffix=self.args["suffix"],
            case=case,
            encoder=self.args["encoder"],
            encode_only=self.args["encode_only"],
            match={
                'status': self.args["match_status"],
                'length': self.args["match_length"],
                'time': self.args["match_time"],
                },
            blacklist_status=self.args["blacklist_status"],
            scanner=self.args["scanner"],
            delay=self.delay,
            threads=self.number_of_threads,
            report=self.args["report_name"],
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
                raise FuzzControllerException("No target left for fuzzing")
        else:
            if self.is_verbose_mode():
                self.cli_output.info_box("Connection status: OK")

    def start(self) -> None:
        """Starts the fuzzing application.
           Each target is fuzzed based on their own methods list
        """
        self.cli_output.info_box("Start fuzzing on "
                                 + get_host(get_pure_url(self.requester.get_url())))
        try:
            super().start()
        except StopActionInterrupt as e:
            self.cli_output.abort_box(f"{str(e)}. Program stopped.")
        else:
            if not self.is_verbose_mode():
                CliOutput.print("")

    def prepare(self) -> None:
        self.target_host = get_host(get_pure_url(self.requester.get_url()))
        if self.is_verbose_mode():
            self.cli_output.info_box(f"Preparing target {self.target_host} ...")
        self.check_ignore_errors()
        super().prepare()

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
            if self.started_time:
                self.cli_output.info_box(
                    f"Time taken: {float('%.2f'%(time.time() - self.started_time))} seconds"
                )
            if self.results:
                self.__handle_valid_results(self.target_host, self.results)
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
            if not self.is_verbose_mode():
                CliOutput.print("")
            self.cli_output.info_box(
                f"Waiting for {self.blacklist_status.action_param} seconds ..."
            )
            time.sleep(self.blacklist_status.action_param)
            self.cli_output.info_box("Resuming target ...")
            self.fuzzer.resume()

    def _result_callback(self, result: Result, validate: bool) -> None:
        if self.verbose[0]:
            if validate:
                self.results.append(result)
            self.cli_output.print_result(result, validate)
        else:
            if validate:
                self.results.append(result)
                self.cli_output.print_result(result, validate)
            self.cli_output.progress_status(
                result.index, self.total_requests, result.payload
            )

    def _request_exception_callback(self, error: Error) -> None:
        """Callback that handle with the request exceptions

        @type error: Error
        @param error: The error gived by the exception
        """
        if self.ignore_errors:
            if not self.verbose[0]:
                self.cli_output.progress_status(
                    error.index, self.total_requests, error.payload
                )
            else:
                if self.verbose[1]:
                    self.cli_output.not_worked_box(str(error))
            with self.lock:
                self.logger.write(str(error), error.payload)
        else:
            self.stop_action = str(error)

    def _invalid_hostname_callback(self, error: Error) -> None:
        """Callback that handle with the subdomain hostname resolver exceptions

        @type error: Error
        @param error: The error gived by the exception
        """
        if self.verbose[0]:
            if self.verbose[1]:
                self.cli_output.not_worked_box(str(error))
        else:
            self.cli_output.progress_status(
                error.index, self.total_requests, error.payload
            )

    def _prepare_scanner(self) -> None:
        """Prepares the scanner"""
        super()._prepare_scanner()
        self.cli_output.set_message_callback(self.scanner.cli_callback)
        if not isinstance(self.scanner, Plugin):
            if (self.requester.is_data_fuzzing() and
                    not self.matcher.comparator_is_set()):
                self.cli_output.info_box("DataFuzzing detected, checking for a data comparator ...")
                self.matcher.set_comparator(*self.__get_data_comparator())

    def __init_report(self) -> None:
        """Initialize the report"""
        self.report = Report.build(self.args["report_name"])
        Result.save_payload_configs = self.args["save_payload_conf"]
        Result.save_headers = self.args["save_headers"]
        Result.save_body = self.args["save_body"]

    def _init_dictionary(self) -> None:
        super()._init_dictionary()
        if self.is_verbose_mode():
            for e in self.wordlist_errors:
                self.cli_output.warning_box(str(e))
        if not len(self.dictionary):
            self.cli_output.error_box("The wordlist is empty")

    def __get_data_comparator(self) -> tuple:
        """Check if the user wants to insert
           custom data comparator to validate the responses

        @returns tuple: The data comparator tuple for the Matcher object
        """
        payload = ' '  # Set an arbitraty payload
        self.cli_output.info_box(
            f"Making first request with '{payload}' as payload ..."
        )
        try:
            # Make the first request to get some info about the target
            response, rtt = self.requester.request(payload)
        except RequestException as e:
            raise StopActionInterrupt(str(e))
        result_to_comparator = Result(response, rtt)
        self.cli_output.print_result(result_to_comparator, False)
        length = None
        default_length = int(result_to_comparator.body_length)+300
        if self.cli_output.ask_yes_no('info',
                              ("Do you want to exclude responses "
                               "based on custom length?")):
            length = self.cli_output.ask_data(
                f"Insert the length (in bytes, default >{default_length})"
            )
            if not length:
                length = default_length
        time = None
        default_time = result_to_comparator.rtt+5.0
        if self.cli_output.ask_yes_no('info',
                              ("Do you want to exclude responses "
                               "based on custom time?")):
            time = self.cli_output.ask_data(
                f"Insert the time (in seconds, default >{default_time} seconds)"
            )
            if not time:
                time = default_time
        return (length, time)

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
