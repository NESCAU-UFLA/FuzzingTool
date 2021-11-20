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

from queue import Queue
import time
import threading
from typing import Tuple, List, Union

from .cli_arguments import CliArguments
from .cli_output import CliOutput, Colors
from ..argument_builder import ArgumentBuilder as AB
from ... import version
from ...utils.http_utils import get_host, get_pure_url
from ...utils.file_utils import read_file
from ...utils.logger import Logger
from ...core import (BlacklistStatus, Dictionary, Fuzzer,
                     Matcher, Payloader, Result)
from ...core.defaults.scanners import (DataScanner,
                                       PathScanner, SubdomainScanner)
from ...core.bases import BaseScanner, BaseEncoder
from ...conn.request_parser import check_is_subdomain_fuzzing
from ...conn.requesters import Requester
from ...factories import PluginFactory, RequesterFactory, WordlistFactory
from ...reports.report import Report
from ...exceptions.base_exceptions import FuzzingToolException
from ...exceptions.main_exceptions import (ControllerException, SkipTargetException,
                                           WordlistCreationError, BuildWordlistFails)
from ...exceptions.request_exceptions import RequestException, InvalidHostname


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


class CliController:
    """Class that handle with the entire application

    Attributes:
        requesters: The requesters list
        started_time: The time when start the fuzzing test
        fuzzer: The fuzzer object to handle with the fuzzing test
        all_results: The results dictionary for each host
        lock: A thread locker to prevent overwrites on logfiles
        blacklist_status: The blacklist status object
        logger: The object to handle with the program log
    """
    def __init__(self):
        self.requesters = []
        self.started_time = 0
        self.fuzzer = None
        self.all_results = {}
        self.lock = threading.Lock()
        self.blacklist_status = None
        self.logger = Logger()

    def is_verbose_mode(self) -> bool:
        """The verboseMode getter

        @returns bool: The verbose mode flag
        """
        return self.verbose[0]

    def main(self, arguments: CliArguments) -> None:
        """The main function.
           Prepares the application environment and starts the fuzzing

        @type arguments: CliArguments
        @param arguments: The command line interface arguments object
        """
        self.co = CliOutput()  # Abbreviation to cli output
        self.verbose = arguments.verbose
        if arguments.simple_output:
            self.co.set_simple_output_mode()
        else:
            CliOutput.print(banner())
        try:
            self.co.info_box("Setting up arguments ...")
            self.init(arguments)
            if not arguments.simple_output:
                self.print_configs(arguments)
        except FuzzingToolException as e:
            self.co.error_box(str(e))
        self.co.set_verbosity_mode(self.is_verbose_mode())
        try:
            self.check_connection_and_redirections()
            self.start()
        except KeyboardInterrupt:
            if self.fuzzer and self.fuzzer.is_running():
                self.co.abort_box("Test aborted, stopping threads ...")
                self.fuzzer.stop()
            self.co.abort_box("Test aborted by the user")
        except FuzzingToolException as e:
            self.co.error_box(str(e))
        finally:
            self.show_footer()
            self.co.info_box("Test completed")

    def init(self, arguments: CliArguments) -> None:
        """The initialization function.
           Set the application variables including plugins requires

        @type arguments: CliArguments
        @param arguments: The command line interface arguments object
        """
        self.__init_requesters(arguments)
        scanner = None
        if arguments.scanner:
            scanner, param = arguments.scanner
            scanner = PluginFactory.object_creator(
                scanner, 'scanners', param
            )
        self.global_scanner = scanner
        self.__check_for_duplicated_targets()
        match_status = arguments.match_status
        if (match_status and
                '200' not in match_status and
                self.co.ask_yes_no('warning',
                                   ("Status code 200 (OK) wasn't included. "
                                    "Do you want to include it to "
                                    "the allowed status codes?"))):
            match_status += ",200"
        self.global_matcher = Matcher.from_string(
            match_status,
            arguments.match_length,
            arguments.match_time
        )
        if arguments.blacklisted_status:
            blacklisted_status = arguments.blacklisted_status
            action = arguments.blacklist_action
            self.blacklist_status = BlacklistStatus(
                status=blacklisted_status,
                action=action,
                action_param=arguments.blacklist_action_param,
                action_callbacks={
                    'skip': self._skip_callback,
                    'wait': self._wait_callback,
                },
            )
        self.delay = arguments.delay
        self.number_of_threads = arguments.number_of_threads
        if self.global_scanner:
            self.local_scanner = self.global_scanner
            self.co.set_message_callback(self.local_scanner.cli_callback)
        self.report = Report.build(arguments.report)
        self.__init_dictionary(arguments)

    def print_configs(self, arguments: CliArguments) -> None:
        """Print the program configuration

        @type arguments: CliArguments
        @param arguments: The command line interface arguments object
        """
        if self.verbose[1]:
            verbose = 'detailed'
        elif self.verbose[0]:
            verbose = 'common'
        else:
            verbose = 'quiet'
        if arguments.lowercase:
            case = 'lowercase'
        elif arguments.uppercase:
            case = 'uppercase'
        elif arguments.capitalize:
            case = 'capitalize'
        else:
            case = None
        self.co.print_configs(
            output='normal'
                   if not arguments.simple_output
                   else 'simple',
            verbose=verbose,
            targets=self.targets_list,
            dictionaries=self.dictionaries_metadata,
            prefix=arguments.prefix,
            suffix=arguments.suffix,
            case=case,
            encoder=arguments.str_encoder,
            encode_only=arguments.encode_only,
            match={
                'status': arguments.match_status,
                'length': arguments.match_length,
                'time': arguments.match_time,
                },
            scanner=arguments.str_scanner,
            blacklist_status={
                'status': arguments.blacklisted_status,
                'action': arguments.blacklist_action,
                } if arguments.blacklisted_status else {},
            delay=self.delay,
            threads=self.number_of_threads,
            report=arguments.report,
        )

    def check_connection_and_redirections(self) -> None:
        """Test the connection to target.
           If data fuzzing is detected, check for redirections
        """
        for requester in self.requesters:
            self.co.info_box(f"Validating {requester.get_url()} ...")
            if self.is_verbose_mode():
                self.co.info_box("Testing connection ...")
            try:
                requester.test_connection()
            except RequestException as e:
                if not self.co.ask_yes_no('warning',
                                          f"{str(e)}. Continue anyway?"):
                    self.co.info_box("Target removed from list.")
                    self.requesters.remove(requester)
            else:
                if self.is_verbose_mode():
                    self.co.info_box("Connection status: OK")
                if requester.is_data_fuzzing():
                    self.check_redirections(requester)
        if len(self.requesters) == 0:
            raise ControllerException("No targets left for fuzzing")

    def check_redirections(self, requester: Requester) -> None:
        """Check the redirections for a target.
           Perform a redirection check for each method
           in requester methods list

        @type requester: Requester
        @param requester: The requester for the target
        """
        if self.is_verbose_mode():
            self.co.info_box("Testing redirections ...")
        for method in requester.methods:
            requester.set_method(method)
            if self.is_verbose_mode():
                self.co.info_box(f"Testing with {method} method ...")
            try:
                if (requester.has_redirection() and
                        self.co.ask_yes_no('warning',
                                           ("You was redirected to another page. "
                                            "Remove this method?"))):
                    requester.methods.remove(method)
                    self.co.info_box(f"Method {method} removed from list")
                else:
                    if self.is_verbose_mode():
                        self.co.info_box("No redirections")
            except RequestException as e:
                self.co.warning_box(f"{str(e)}. Removing method {method}")
        if len(requester.methods) == 0:
            self.requesters.remove(requester)
            self.co.warning_box("No methods left on this target, "
                                "removed from targets list")

    def start(self) -> None:
        """Starts the fuzzing application.
           Each target is fuzzed based on their own methods list
        """
        self.started_time = time.time()
        for requester in self.requesters:
            self.co.info_box("Start fuzzing on "
                             + get_host(get_pure_url(requester.get_url())))
            start_index = 1
            try:
                self.prepare_target(requester)
                for method in self.requester.methods:
                    self.requester.set_method(method)
                    self.prepare_fuzzer(start_index)
                    start_index = self.fuzzer.index
                if not self.is_verbose_mode():
                    CliOutput.print("")
            except SkipTargetException as e:
                if self.fuzzer and self.fuzzer.is_running():
                    self.co.warning_box("Skip target detected, stopping threads ...")
                    self.fuzzer.stop()
                self.co.abort_box(f"{str(e)}. Target skipped")

    def prepare_target(self, requester: Requester) -> None:
        """Prepare the target variables for the fuzzing tests.
           Both error logger and default scanners are setted

        @type requester: Requester
        @param requester: The requester for the target
        """
        self.requester = requester
        self.target_host = get_host(get_pure_url(requester.get_url()))
        if self.is_verbose_mode():
            self.co.info_box(f"Preparing target {self.target_host} ...")
        before = time.time()
        self.check_ignore_errors(self.target_host)
        self.started_time += (time.time() - before)
        self.results = []
        self.all_results[self.target_host] = self.results
        self.skip_target = None
        self.__prepare_local_matcher()
        self.__prepare_local_scanner()
        if not self.global_dictionary:
            self.local_dictionary = self.dictionaries.get()
        self.total_requests = (len(self.local_dictionary)
                               * len(self.requester.methods))

    def prepare_fuzzer(self, start_index: int = 1) -> None:
        """Prepare the fuzzer for the fuzzing tests.
           Refill the dictionary with the wordlist
           content if a global dictionary was given

        @type start_index: int
        @param start_index: The index value to start the Fuzzer index
        """
        self.local_dictionary.reload()
        self.fuzzer = Fuzzer(
            requester=self.requester,
            dictionary=self.local_dictionary,
            matcher=self.local_matcher,
            scanner=self.local_scanner,
            delay=self.delay,
            number_of_threads=self.number_of_threads,
            blacklist_status=self.blacklist_status,
            start_index=start_index,
            result_callback=self._result_callback,
            exception_callbacks=[
                self._invalid_hostname_callback,
                self._request_exception_callback
            ],
        )
        self.fuzzer.start()
        while self.fuzzer.join():
            if self.skip_target:
                raise SkipTargetException(self.skip_target)

    def check_ignore_errors(self, host: str) -> None:
        """Check if the user wants to ignore the errors during the tests.
           By default, URL fuzzing (path and subdomain) ignore errors

        @type host: str
        @param host: The target hostname
        """
        if (self.requester.is_url_discovery() or
                self.co.ask_yes_no('info',
                                   ("Do you want to ignore errors on this "
                                    "target, and save them into a log file?"))):
            self.ignore_errors = True
            log_path = self.logger.setup(host)
            self.co.info_box(f'The logs will be saved on \'{log_path}\'')
        else:
            self.ignore_errors = False

    def show_footer(self) -> None:
        """Show the footer content of the software, after maked the fuzzing.
           The results are shown for each target
        """
        if self.fuzzer:
            if self.started_time:
                self.co.info_box(
                    f"Time taken: {float('%.2f'%(time.time() - self.started_time))} seconds"
                )
            requester_index = 0
            for key, value in self.all_results.items():
                if value:
                    self.__handle_valid_results(key, value, requester_index)
                else:
                    self.co.info_box(
                        f"No matched results was found on target {key}"
                    )
                requester_index += 1

    def _skip_callback(self, status: int) -> None:
        """The skip target callback for the blacklist_action

        @type status: int
        @param status: The identified status code into the blacklist
        """
        self.skip_target = f"Status code {str(status)} detected"

    def _wait_callback(self, status: int) -> None:
        """The wait (pause) callback for the blacklist_action

        @type status: int
        @param status: The identified status code into the blacklist
        """
        if not self.fuzzer.is_paused():
            self.fuzzer.pause()
            self.co.warning_box(
                f"Status code {str(status)} detected. Pausing threads ..."
            )
            self.fuzzer.wait_until_pause()
            if not self.is_verbose_mode():
                CliOutput.print("")
            self.co.info_box(
                f"Waiting for {self.blacklist_status.action_param} seconds ..."
            )
            time.sleep(self.blacklist_status.action_param)
            self.co.info_box("Resuming target ...")
            self.fuzzer.resume()

    def _result_callback(self, result: dict, validate: bool) -> None:
        """Callback function for the results output

        @type result: dict
        @param result: The FuzzingTool result
        @type validate: bool
        @param validate: A validator flag for the result, gived by the scanner
        """
        if self.verbose[0]:
            if validate:
                self.results.append(result)
            self.co.print_result(result, validate)
        else:
            if validate:
                self.results.append(result)
                self.co.print_result(result, validate)
            self.co.progress_status(
                result.index, self.total_requests, result.payload
            )

    def _request_exception_callback(self,
                                    e: RequestException,
                                    payload: str) -> None:
        """Callback that handle with the request exceptions

        @type e: RequestException
        @param e: The request exception
        @type payload: str
        @param payload: The payload used in the request
        """
        if self.ignore_errors:
            if not self.verbose[0]:
                self.co.progress_status(
                    self.fuzzer.index, self.total_requests, payload
                )
            else:
                if self.verbose[1]:
                    self.co.not_worked_box(str(e))
            with self.lock:
                self.logger.write(str(e), payload)
        else:
            self.skip_target = str(e)

    def _invalid_hostname_callback(self,
                                   e: InvalidHostname,
                                   payload: str) -> None:
        """Callback that handle with the subdomain hostname resolver exceptions

        @type e: InvalidHostname
        @param e: The invalid hostname exception
        @type payload: str
        @param payload: The payload used in the request
        """
        if self.verbose[0]:
            if self.verbose[1]:
                self.co.not_worked_box(str(e))
        else:
            self.co.progress_status(
                self.fuzzer.index, self.total_requests, payload
            )

    def __get_target_fuzzing_type(self, requester: Requester) -> str:
        """Get the target fuzzing type, as a string format

        @type requester: Requester
        @param requester: The actual iterated requester
        @return str: The fuzzing type, as a string
        """
        if requester.is_method_fuzzing():
            return "MethodFuzzing"
        elif requester.is_data_fuzzing():
            return "DataFuzzing"
        elif requester.is_url_discovery():
            if requester.is_path_fuzzing():
                return "PathFuzzing"
            else:
                return "SubdomainFuzzing"
        else:
            return "Couldn't determine the fuzzing type"

    def __init_requesters(self, arguments: CliArguments) -> None:
        """Initialize the requesters

        @type arguments: CliArguments
        @param arguments: The command line interface arguments object
        """
        self.targets_list = []
        if arguments.targets_from_url:
            self.targets_list.extend(AB.build_targets_from_args(
                arguments.targets_from_url, arguments.method, arguments.data
            ))
        if arguments.targets_from_raw_http:
            self.targets_list.extend(AB.build_targets_from_raw_http(
                arguments.targets_from_raw_http, arguments.scheme
            ))
        if not self.targets_list:
            raise ControllerException("A target is needed to make the fuzzing")
        for target in self.targets_list:
            if check_is_subdomain_fuzzing(target['url']):
                requester_type = 'SubdomainRequester'
            else:
                requester_type = 'Requester'
            requester = RequesterFactory.creator(
                requester_type,
                url=target['url'],
                methods=target['methods'],
                body=target['body'],
                headers=target['header'],
                follow_redirects=arguments.follow_redirects,
                proxy=arguments.proxy,
                proxies=(read_file(arguments.proxies)
                         if arguments.proxies else []),
                timeout=arguments.timeout,
                cookie=arguments.cookie,
            )
            self.requesters.append(requester)
            target['type_fuzzing'] = self.__get_target_fuzzing_type(requester)

    def __check_for_duplicated_targets(self) -> None:
        """Checks for duplicated targets,
           if they'll use the same scanner (based on fuzzing type)
           Also, checks if a global scanner was
           already specified before make the check
        """
        if not self.global_scanner:
            targets_checker = [{
                'host': get_host(get_pure_url(target['url'])),
                'type_fuzzing': target['type_fuzzing'],
            } for target in self.targets_list]
            if len(set([
                target['host'] for target in targets_checker
            ])) != len(self.targets_list):
                targets_checker.sort(key=lambda e: e['host'])
                for i in range(len(targets_checker)-1):
                    this_target = targets_checker[i]
                    next_target = targets_checker[i+1]
                    if (this_target['host'] == next_target['host'] and
                        (this_target['type_fuzzing'] !=
                         next_target['type_fuzzing'])):
                        raise ControllerException(
                            "Duplicated target detected with "
                            "different type of fuzzing scan, exiting."
                        )

    def __build_encoders(self, arguments: CliArguments) -> Union[
        Tuple[List[BaseEncoder], List[List[BaseEncoder]]], None
    ]:
        """Build the encoders

        @type arguments: CliArguments
        @param arguments: The command line interface arguments object
        @returns Tuple | None: The encoders used in the program
        """
        if not arguments.encoder:
            return None
        if arguments.encode_only:
            Payloader.encoder.set_regex(arguments.encode_only)
        encoders_default = []
        encoders_chain = []
        for encoders in arguments.encoder:
            if len(encoders) > 1:
                append_to = []
                is_chain = True
            else:
                append_to = encoders_default
                is_chain = False
            for encoder in encoders:
                name, param = encoder
                encoder = PluginFactory.object_creator(
                    name, 'encoders', param
                )
                append_to.append(encoder)
            if is_chain:
                encoders_chain.append(append_to)
        return (encoders_default, encoders_chain)

    def __configure_payloader(self, arguments: CliArguments) -> None:
        """Configure the Payloader options

        @type arguments: CliArguments
        @param arguments: The command line interface arguments object
        """
        Payloader.set_prefix(arguments.prefix)
        Payloader.set_suffix(arguments.suffix)
        if arguments.lowercase:
            Payloader.set_lowercase()
        elif arguments.uppercase:
            Payloader.set_uppercase()
        elif arguments.capitalize:
            Payloader.set_capitalize()
        encoders = self.__build_encoders(arguments)
        if encoders:
            Payloader.encoder.set_encoders(encoders)

    def __build_wordlist(
        self,
        wordlists: List[Tuple[str, str]],
        requester: Requester = None
    ):
        """Build the wordlist

        @type wordlists: List[Tuple[str, str]]
        @param wordlists: The wordlists used in the dictionary
        @type requester: Requester
        @param requester: The requester for the given dictionary
        @returns List: The builded wordlist list
        """
        builded_wordlist = []
        for wordlist in wordlists:
            name, params = wordlist
            if self.verbose[1]:
                self.co.info_box(f"Building wordlist from {name} ...")
            self.dictionaries_metadata[-1]['wordlists'].append(
                f"{name}={params}" if params else name
            )
            try:
                wordlist_obj = WordlistFactory.creator(name, params, requester)
                wordlist_obj.build()
            except (WordlistCreationError, BuildWordlistFails) as e:
                if self.is_verbose_mode():
                    self.co.warning_box(str(e))
            else:
                builded_wordlist.extend(wordlist_obj.get())
                if self.verbose[1]:
                    self.co.info_box(f"Wordlist {name} builded")
        if not builded_wordlist:
            raise ControllerException("The wordlist is empty")
        return builded_wordlist

    def __build_dictionary(
        self,
        wordlists: List[Tuple[str, str]],
        is_unique: bool,
        requester: Requester = None
    ) -> None:
        """Build the dictionary

        @type wordlists: List[Tuple[str, str]]
        @param wordlists: The wordlists used in the dictionary
        @type is_unique: bool
        @param is_unique: A flag to say if the dictionary will contains only unique payloads
        @type requester: Requester
        @param requester: The requester for the given dictionary
        @returns Dictionary: The dictionary object
        """
        self.dictionaries_metadata.append({
            'wordlists': [],
            'len': 0
        })
        builded_wordlist = self.__build_wordlist(wordlists, requester)
        atual_length = len(builded_wordlist)
        if is_unique:
            previous_length = atual_length
            builded_wordlist = set(builded_wordlist)
            atual_length = len(builded_wordlist)
            self.dictionaries_metadata[-1]['removed'] = previous_length-atual_length
        dictionary = Dictionary(builded_wordlist)
        self.dictionaries_metadata[-1]['len'] = atual_length
        return dictionary

    def __init_dictionary(self, arguments: CliArguments) -> None:
        """Initialize the dictionary

        @type arguments: CliArguments
        @param arguments: The command line interface arguments object
        """
        self.__configure_payloader(arguments)
        self.global_dictionary = None
        self.dictionaries = []
        self.dictionaries_metadata = []
        len_wordlists = len(arguments.wordlists)
        len_requesters = len(self.requesters)
        if len_wordlists > len_requesters:
            raise ControllerException(
                "The quantity of wordlists is greater than the requesters"
            )
        elif len_wordlists != len_requesters:
            wordlist = arguments.wordlists[0]
            self.global_dictionary = self.__build_dictionary(wordlist,
                                                             arguments.unique)
            self.local_dictionary = self.global_dictionary
        else:
            self.dictionaries = Queue()
            for i, wordlist in enumerate(arguments.wordlists):
                self.dictionaries.put(self.__build_dictionary(
                    wordlist, arguments.unique, self.requesters[i]
                ))

    def __prepare_local_matcher(self) -> None:
        """Prepares the local matcher"""
        self.local_matcher = Matcher(
            allowed_status=self.global_matcher.get_allowed_status(),
            comparator=self.global_matcher.get_comparator(),
            match_functions=self.global_matcher.get_match_functions()
        )
        if (self.requester.is_url_discovery() and
                self.global_matcher.allowed_status_is_default()):
            self.local_matcher.set_allowed_status(
                Matcher.build_allowed_status("200-399,401,403")
            )

    def __get_default_scanner(self) -> BaseScanner:
        """Check what's the scanners that will be used

        @returns BaseScanner: The scanner used in the fuzzing tests
        """
        if self.requester.is_url_discovery():
            if self.requester.is_path_fuzzing():
                scanner = PathScanner()
            else:
                scanner = SubdomainScanner()
        else:
            scanner = DataScanner()
        self.co.set_message_callback(scanner.cli_callback)
        return scanner

    def __get_data_comparator(self) -> dict:
        """Check if the user wants to insert
           custom data comparator to validate the responses

        @returns dict: The data comparator dictionary for the Matcher object
        """
        payload = ' '  # Set an arbitraty payload
        self.co.info_box(
            f"Making first request with '{payload}' as payload ..."
        )
        try:
            # Make the first request to get some info about the target
            response, rtt = self.requester.request(payload)
        except RequestException as e:
            raise SkipTargetException(str(e))
        result_to_comparator = Result(response, rtt)
        self.co.print_result(result_to_comparator, False)
        length = None
        default_length = int(result_to_comparator.length)+300
        if self.co.ask_yes_no('info',
                              ("Do you want to exclude responses "
                               "based on custom length?")):
            length = self.co.ask_data(
                f"Insert the length (in bytes, default >{default_length})"
            )
            if not length:
                length = default_length
        time = None
        default_time = result_to_comparator.rtt+5.0
        if self.co.ask_yes_no('info',
                              ("Do you want to exclude responses "
                               "based on custom time?")):
            time = self.co.ask_data(
                f"Insert the time (in seconds, default >{default_time} seconds)"
            )
            if not time:
                time = default_time
        return Matcher.build_comparator(length, time)

    def __prepare_local_scanner(self) -> None:
        """Prepares the local scanner"""
        if not self.global_scanner:
            self.local_scanner = self.__get_default_scanner()
            if (self.requester.is_data_fuzzing() and
                    not self.global_matcher.comparator_is_set()):
                self.co.info_box("DataFuzzing detected, checking for a data comparator ...")
                before = time.time()
                self.local_matcher.set_comparator(
                    self.__get_data_comparator()
                )
                self.started_time += (time.time() - before)

    def __handle_valid_results(self,
                               host: str,
                               results: list,
                               requester_index: int) -> None:
        """Handle the valid results from footer

        @type host: str
        @param host: The target host
        @type results: list
        @param results: The target results from the fuzzing
        @type requester_index: int
        @param requester_index: The requester of the target
        """
        if self.is_verbose_mode():
            self.co.info_box(
                f"Found {len(results)} matched results on target {host}"
            )
            if not self.global_scanner:
                self.requester = self.requesters[requester_index]
                self.__get_default_scanner()
            for result in results:
                self.co.print_result(result, True)
            self.co.info_box(f'Saving results for {host} ...')
        report_path = self.report.open(host)
        self.report.write(results)
        self.co.info_box(f"Results saved on {report_path}")
