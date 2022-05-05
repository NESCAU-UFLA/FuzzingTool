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

from typing import Tuple, List, Union
import time
from threading import Thread

from requests.models import Response

from .utils.argument_utils import (build_target_from_args, build_target_from_raw_http,
                                   build_wordlist, build_encoder, build_scanner,
                                   build_blacklist_status)
from .utils.consts import PluginCategory
from .utils.utils import split_str_to_list
from .utils.file_utils import read_file
from .utils.result_utils import ResultUtils
from .core import (BlacklistStatus, Dictionary, Fuzzer, Filter,
                   JobManager, Matcher, Payloader, RecursionManager, Summary)
from .core.bases import BaseScanner, BaseEncoder
from .core.defaults.scanners import (DataScanner,
                                     PathScanner, SubdomainScanner)
from .conn.requesters import Requester, SubdomainRequester
from .conn.request_parser import check_is_subdomain_fuzzing
from .factories import PluginFactory, WordlistFactory
from .objects import BaseItem, Error, Result, HttpHistory, Payload
from .exceptions import (FuzzLibException, StopActionInterrupt,
                         WordlistCreationError, BuildWordlistFails)


class FuzzLib:
    def __init__(self, **kwargs):
        self.args = self.__get_default_args()
        self.args.update(kwargs)
        self.requester = None
        self.fuzzer = None
        self.blacklist_status = None
        self.summary = Summary()
        self.stop_action = None
        if self.args["res_callback"]:
            self._result_callback = self.args["res_callback"]
        if self.args["req_ex_callback"]:
            self._request_exception_callback = self.args["req_ex_callback"]
        if self.args["invalid_host_calalback"]:
            self._invalid_hostname_callback = self.args["invalid_host_calalback"]
        ResultUtils.detailed_results = not self.args["simple_output"]

    def main(self) -> None:
        """The main function.
           Prepares the application environment and starts the fuzzing
        """
        self.init()
        self.start()

    def init(self) -> None:
        """The initialization function.
           Set the application variables including plugins requires
        """
        self._init_requester()
        self._init_filter()
        self._init_matcher()
        self._init_scanners()
        self._init_other_arguments()
        self._init_dictionary()
        self._init_managers()
        self._set_observer()

    def start(self) -> None:
        """Starts the fuzzing application"""
        self.summary.start_timer()
        try:
            while self.job_manager.has_pending_jobs():
                self._get_job()
                self.__fuzz()
                self._check_for_new_jobs()
        except StopActionInterrupt as e:
            if self.fuzzer and self.fuzzer.is_running():
                self.fuzzer.stop()
            raise e
        finally:
            self.summary.stop_timer()

    def _stop_callback(self, status: int) -> None:
        """The skip target callback for the blacklist_action

        @type status: int
        @param status: The identified status code into the blacklist
        """
        self.stop_action = f"Status code {str(status)} detected"

    def _wait_callback(self, status: int) -> None:
        """The wait (pause) callback for the blacklist_action

        @type status: int
        @param status: The identified status code into the blacklist
        """
        if not self.fuzzer.is_paused():
            self.fuzzer.pause()
            self.fuzzer.wait_until_pause()
            time.sleep(self.blacklist_status.action_param)
            self.fuzzer.resume()

    def _result_callback(self, result: Result, valid: bool) -> None:
        """Callback function for the FuzzingTool results

        @type result: Result
        @param result: The FuzzingTool result object
        @type valid: bool
        @param valid: A validator flag for the result
        """
        pass

    def _request_exception_callback(self, error: Error) -> None:
        """Callback that handle with the request exceptions

        @type error: Error
        @param error: The error gived by the exception
        """
        pass

    def _invalid_hostname_callback(self, error: Error) -> None:
        """Callback that handle with the subdomain hostname resolver exceptions

        @type error: Error
        @param error: The error gived by the exception
        """
        pass

    def _init_requester(self) -> None:
        """Initialize the requester"""
        target = None
        if self.args["url"]:
            target = build_target_from_args(
                self.args["url"], self.args["method"], self.args["data"]
            )
        if self.args["raw_http"]:
            target = build_target_from_raw_http(
                self.args["raw_http"], self.args["scheme"]
            )
        if not target:
            raise FuzzLibException("A target is needed to make the fuzzing")
        if check_is_subdomain_fuzzing(target['url']):
            requester_cls = SubdomainRequester
        else:
            requester_cls = Requester
        self.requester = requester_cls(
            url=target['url'],
            method=target['method'],
            body=target['body'],
            headers=target['header'],
            follow_redirects=self.args["follow_redirects"],
            proxy=self.args["proxy"],
            proxies=(read_file(self.args["proxies"])
                     if self.args["proxies"] else []),
            timeout=self.args["timeout"],
            cookie=self.args["cookie"],
            replay_proxy=self.args["replay_proxy"],
        )

    def _init_filter(self) -> None:
        """Initialize the filter"""
        self.filter = Filter(
            self.args['filter_status'],
            self.args['filter_regex']
        )

    def _init_matcher(self) -> None:
        """Initialize the matcher"""
        self.matcher = Matcher(
            self.args['match_status'],
            self.args['match_time'],
            self.args['match_size'],
            self.args['match_words'],
            self.args['match_lines'],
            self.args['match_regex'],
        )
        if (self.requester.is_url_discovery() and
                self.matcher.status_code_is_default()):
            self.matcher.set_status_code("200-399,401,403")

    def _init_scanners(self) -> None:
        """Initialize the scanners"""
        self.scanners: List[BaseScanner] = [self.__get_default_scanner()]
        if self.args["scanner"]:
            scanners = (self.args["scanner"]
                        if isinstance(self.args["scanner"], list)
                        else [self.args["scanner"]])
            for scanner in scanners:
                scanner, param = build_scanner(scanner)
                plugin_scanner: BaseScanner = PluginFactory.object_creator(
                    PluginCategory.scanner, scanner, param
                )
                self.scanners.append(plugin_scanner)

    def _init_other_arguments(self) -> None:
        """Initialize the uncategorized arguments"""
        if self.args["blacklist_status"]:
            blacklisted_status, action, action_param = build_blacklist_status(
                self.args["blacklist_status"]
            )
            self.blacklist_status = BlacklistStatus(
                status=blacklisted_status,
                action=action,
                action_param=action_param,
                action_callbacks={
                    'stop': self._stop_callback,
                    'wait': self._wait_callback,
                },
            )
        self.delay = self.args["delay"]
        self.number_of_threads = self.args["threads"]
        self.has_recursion = self.args["recursive"]
        self.replay_proxy = self.args["replay_proxy"]

    def _init_dictionary(self) -> None:
        """Initialize the dictionary"""
        self.__configure_payloader()
        final_wordlist = self.__build_wordlist(
            build_wordlist(self.args["wordlist"])
        )
        atual_length = len(final_wordlist)
        self.dict_metadata = {}
        if self.args["unique"]:
            previous_length = atual_length
            final_wordlist = set(final_wordlist)
            atual_length = len(final_wordlist)
            self.dict_metadata['removed'] = previous_length-atual_length
        self.dict_metadata['len'] = atual_length
        self.dictionary = Dictionary(final_wordlist)

    def _init_managers(self) -> None:
        """Initialize the recursion manager and job manager"""
        self.recursion_manager = RecursionManager(
            max_rlevel=self.args["max_rlevel"],
            wordlist=self.dictionary.wordlist
        )
        self.job_manager = JobManager(
            dictionary=self.dictionary,
            job_providers={
                **{str(scanner): scanner.payloads_queue for scanner in self.scanners[1:]},
                "recursion": self.recursion_manager.payloads_queue,
            },
            max_rlevel=self.args["max_rlevel"]
        )

    def _set_observer(self) -> None:
        """Set the job manager as observer for the job providers"""
        self.recursion_manager.set_observer(self.job_manager)
        for scanner in self.scanners[1:]:
            scanner.set_observer(self.job_manager)

    def _get_job(self) -> None:
        """Get a job from the job queue"""
        BaseItem.reset_index()
        self.job_manager.get_job()

    def _join(self) -> None:
        """Blocks until the fuzzer ends"""
        while self.fuzzer.join():
            if self.stop_action:
                raise StopActionInterrupt(self.stop_action)
        self.fuzzer.stop()

    def _check_for_new_jobs(self) -> None:
        """Check for new jobs"""
        if self.recursion_manager.has_recursive_job():
            self.recursion_manager.fill_payloads_queue()
        self.job_manager.check_for_new_jobs()

    def __get_default_args(self) -> dict:
        """Gets the default arguments for the program

        @returns dict: The arguments dictionary
        """
        return dict(
            # Target options
            url=None,
            raw_http=None,
            # Request options
            scheme=None,
            method=None,
            data=None,
            proxy=None,
            proxies=None,
            cookie=None,
            timeout=None,
            follow_redirects=False,
            # Dictionary options
            wordlist=None,
            unique=False,
            encoder=None,
            encode_only=None,
            prefix=None,
            suffix=None,
            upper=False,
            lower=False,
            capitalize=False,
            # Matcher, Filter and Scanner options
            match_status=None,
            match_time=None,
            match_size=None,
            match_words=None,
            match_lines=None,
            match_regex=None,
            filter_status=None,
            filter_regex=None,
            scanner=None,
            # Display options
            simple_output=False,
            # Other options
            threads=1,
            delay=0,
            blacklist_status=None,
            recursive=False,
            max_rlevel=1,
            replay_proxy=None,
            # Callbacks
            res_callback=None,
            req_ex_callback=None,
            invalid_host_calalback=None,
        )

    def __build_encoders(self) -> Tuple[List[BaseEncoder], List[List[BaseEncoder]]]:
        """Build the encoders

        @returns tuple: The encoders used in the program
        """
        encoders_list = build_encoder(self.args["encoder"])
        if self.args["encode_only"]:
            Payloader.encoder.set_regex(self.args["encode_only"])
        encoders_default = []
        encoders_chain = []
        for encoders in encoders_list:
            if len(encoders) > 1:
                append_to = []
                is_chain = True
            else:
                append_to = encoders_default
                is_chain = False
            for encoder in encoders:
                name, param = encoder
                encoder = PluginFactory.object_creator(
                    PluginCategory.encoder, name, param
                )
                append_to.append(encoder)
            if is_chain:
                encoders_chain.append(append_to)
        return (encoders_default, encoders_chain)

    def __configure_payloader(self) -> None:
        """Configure the Payloader options"""
        if self.args["prefix"]:
            Payloader.set_prefix(split_str_to_list(self.args["prefix"]))
        if self.args["suffix"]:
            Payloader.set_suffix(split_str_to_list(self.args["suffix"]))
        if self.args["lower"]:
            Payloader.set_lowercase()
        elif self.args["upper"]:
            Payloader.set_uppercase()
        elif self.args["capitalize"]:
            Payloader.set_capitalize()
        if self.args["encoder"]:
            Payloader.encoder.set_encoders(self.__build_encoders())

    def __build_wordlist(self,
                         wordlists: List[Tuple[str, str]]) -> List[str]:
        """Build the dictionary

        @type wordlists: List[Tuple[str, str]]
        @param wordlists: The wordlists used in the dictionary
        @returns List[str]: The builded payload wordlist
        """
        def run(wordlist: Tuple[str, str]) -> None:
            """Run the wordlist thread function

            @type wordlist: Tuple[str, str]
            @param wordlist: The wordlist name and parameter
            """
            nonlocal final_wordlist
            try:
                wordlist_obj = WordlistFactory.creator(*wordlist, self.requester)
                wordlist_obj.build()
            except (WordlistCreationError, BuildWordlistFails) as e:
                self.wordlist_errors.append(e)
            else:
                final_wordlist.extend(wordlist_obj.get())

        final_wordlist = []
        wordlist_threads = [Thread(target=run, args=(wordlist,)) for wordlist in wordlists]
        self.wordlist_errors: List[Union[WordlistCreationError, BuildWordlistFails]] = []
        for thread in wordlist_threads:
            thread.start()
        for thread in wordlist_threads:
            thread.join()
        if not final_wordlist:
            raise FuzzLibException("The wordlist is empty")
        return final_wordlist

    def __get_default_scanner(self) -> BaseScanner:
        """Check what's the scanners that will be used

        @returns BaseScanner: The scanner used in the fuzzing tests
        """
        if self.requester.is_url_discovery():
            if self.requester.is_path_fuzzing():
                return PathScanner()
            return SubdomainScanner()
        return DataScanner()

    def __fuzz(self) -> None:
        """Prepare the fuzzer for the fuzzing tests"""
        self.fuzzer = Fuzzer(
            requester=self.requester,
            dictionary=self.dictionary,
            delay=self.delay,
            number_of_threads=self.number_of_threads,
            response_callback=self.__handle_response,
            exception_callbacks=[
                self._invalid_hostname_callback,
                self._request_exception_callback
            ],
        )
        self.fuzzer.start()
        self._join()

    def __handle_response(self,
                          response: Response,
                          rtt: float,
                          payload: Payload,
                          *ip) -> None:
        """Handle the response from the request

        @type response: Response
        @param response: The response object from the request
        @type rtt: float
        @param rtt: The elapsed time between request and response
        @type payload: Payload
        @param payload: The payload used in the request
        """
        if (self.blacklist_status and
                response.status_code in self.blacklist_status.codes):
            self.blacklist_status.do_action(response.status_code)
        result = Result(HttpHistory(response, rtt, *ip),
                        payload,
                        self.requester.get_fuzzing_type())
        self.__handle_result(result)

    def __is_valid(self, result: Result) -> bool:
        """Checks if the result is valid or not

        @type result: Result
        @param result: The FuzzingTool result object
        @returns bool: A flag to say if the result is valid or not
        """
        if self.filter.check(result) and self.matcher.match(result):
            for scanner in self.scanners:
                if not scanner.scan(result):
                    return False
            return True
        return False

    def __handle_result(self, result: Result) -> bool:
        """Process the result

        @type result: Result
        @param result: The FuzzingTool result object
        """
        if self.__is_valid(result):
            for scanner in self.scanners:
                scanner.process(result)
            if self.has_recursion:
                self.recursion_manager.check_for_recursion(result)
            self._result_callback(result, True)
            if self.replay_proxy:
                self.requester.request(result.payload, replay_proxy=True)
        else:
            self._result_callback(result, False)
