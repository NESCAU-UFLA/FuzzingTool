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

from requests.models import Response

from ..interfaces.argument_builder import ArgumentBuilder as AB
from ..utils.utils import split_str_to_list
from ..utils.file_utils import read_file
from ..utils.result_utils import ResultUtils
from ..core import (BlacklistStatus, Dictionary, Fuzzer,
                    JobManager, Matcher, Payloader, Summary)
from ..core.bases import BaseScanner, BaseEncoder
from ..core.defaults.scanners import (DataScanner,
                                      PathScanner, SubdomainScanner)
from ..conn.requesters import Requester, SubdomainRequester
from ..conn.request_parser import check_is_subdomain_fuzzing
from ..factories import PluginFactory, WordlistFactory
from ..objects import BaseItem, Error, Result, HttpHistory, Payload
from ..exceptions.main_exceptions import (FuzzControllerException, StopActionInterrupt,
                                          WordlistCreationError, BuildWordlistFails)


class FuzzController:
    def __init__(self, **kwargs):
        self.args = self.__get_default_args()
        self.args.update(kwargs)
        self.requester = None
        self.elapsed_time = None
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
        self._init_matcher()
        self._init_scanner()
        if self.args["blacklist_status"]:
            blacklisted_status, action, action_param = AB.build_blacklist_status(
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
        self._init_dictionary()
        self.job_manager = JobManager(
            dictionary=self.dictionary,
            job_providers={
                str(scanner): scanner.payloads_queue for scanner in self.scanners[1:]
            }
        )

    def start(self) -> None:
        """Starts the fuzzing application.
           The target is fuzzed based on his own method list
        """
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
            target = AB.build_target_from_args(
                self.args["url"], self.args["method"], self.args["data"]
            )
        if self.args["raw_http"]:
            target = AB.build_target_from_raw_http(
                self.args["raw_http"], self.args["scheme"]
            )
        if not target:
            raise FuzzControllerException("A target is needed to make the fuzzing")
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
        )

    def _init_matcher(self) -> None:
        """Initialize the matcher"""
        self.matcher = Matcher(
            self.args['match_status'],
            self.args['match_time'],
            self.args['match_size'],
            self.args['match_words'],
            self.args['match_lines'],
        )
        if (self.requester.is_url_discovery() and
                self.matcher.allowed_status_is_default()):
            self.matcher.set_allowed_status("200-399,401,403")

    def _init_scanner(self) -> None:
        """Initialize the scanner"""
        self.scanners: List[BaseScanner] = [self.__get_default_scanner()]
        if self.args["scanner"]:
            scanner, param = AB.build_scanner(self.args["scanner"])
            plugin_scanner: BaseScanner = PluginFactory.object_creator(
                scanner, 'scanners', param
            )
            self.scanners.append(plugin_scanner)

    def _init_dictionary(self) -> None:
        """Initialize the dictionary"""
        self.__configure_payloader()
        final_wordlist = self.__build_wordlist(
            AB.build_wordlist(self.args["wordlist"])
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

    def _check_for_new_jobs(self):
        """Check for new jobs on job manager"""
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
            # Match and Scanner options
            match_status=None,
            match_time=None,
            match_size=None,
            match_words=None,
            match_lines=None,
            scanner=None,
            # Display options
            simple_output=False,
            # Other options
            threads=1,
            delay=0,
            blacklist_status=None,
            # Callbacks
            res_callback=None,
            req_ex_callback=None,
            invalid_host_calalback=None,
        )

    def __build_encoders(self) -> Union[
        Tuple[List[BaseEncoder], List[List[BaseEncoder]]], None
    ]:
        """Build the encoders

        @returns Tuple | None: The encoders used in the program
        """
        if not self.args["encoder"]:
            return None
        encoders_list = AB.build_encoder(self.args["encoder"])
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
                    name, 'encoders', param
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
        encoders = self.__build_encoders()
        if encoders:
            Payloader.encoder.set_encoders(encoders)

    def __build_wordlist(self,
                         wordlists: List[Tuple[str, str]]) -> List[str]:
        """Build the dictionary

        @type wordlists: List[Tuple[str, str]]
        @param wordlists: The wordlists used in the dictionary
        @returns List[str]: The builded payload wordlist
        """
        final_wordlist = []
        self.wordlist_errors: List[Union[WordlistCreationError, BuildWordlistFails]] = []
        for wordlist in wordlists:
            try:
                wordlist_obj = WordlistFactory.creator(*wordlist, self.requester)
                wordlist_obj.build()
            except (WordlistCreationError, BuildWordlistFails) as e:
                self.wordlist_errors.append(e)
            else:
                final_wordlist.extend(wordlist_obj.get())
        if not final_wordlist:
            raise FuzzControllerException("The wordlist is empty")
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
        self._result_callback(result, self.__result_is_valid(result))

    def __result_is_valid(self, result: Result):
        """Checks if the result is valid or not

        @type result: Result
        @param result: The FuzzingTool result object
        """
        if self.matcher.match(result):
            for scanner in self.scanners:
                if not scanner.scan(result):
                    return False
                scanner.process(result)
            return True
        return False
