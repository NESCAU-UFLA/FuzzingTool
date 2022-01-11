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

from threading import Thread, Event
import time
from typing import Callable, List

from requests.models import Response

from .blacklist_status import BlacklistStatus
from .dictionary import Dictionary
from .matcher import Matcher
from .bases.base_scanner import BaseScanner
from ..conn.requesters import Requester
from ..objects import Error, Payload, Result
from ..exceptions.request_exceptions import RequestException, InvalidHostname


class Fuzzer:
    """Fuzzer class, the core of the software

    Attributes:
        requester: The requester object to deal with the requests
        dict: The dictionary object to handle with the payloads
        matcher: A matcher object, used to match the results
        scanner: A scanner object, used to validate the results
        delay: The delay between each test
        running: A flag to say if the application is running or not
        blacklist_status: The blacklist status object to handle
                          with the blacklisted status
    """
    def __init__(self,
                 requester: Requester,
                 dictionary: Dictionary,
                 matcher: Matcher,
                 scanner: BaseScanner,
                 delay: float,
                 number_of_threads: int,
                 blacklist_status: BlacklistStatus,
                 result_callback: Callable[[dict, bool], None],
                 exception_callbacks: List[Callable[[str, str], None]]):
        """Class constructor

        @type requester: Requester
        @param requester: The requester object to deal with the requests
        @type dict: Dictionary
        @param dict: The dicttionary object to deal with the payload dictionary
        @type matcher: Matcher
        @param matcher: The matcher for the results
        @type scanner: BaseScanner
        @param scanner: The fuzzing results scanner
        @type delay: float
        @param delay: The delay between each request
        @type number_of_threads: int
        @param number_of_threads: The number of threads
                                  used in the fuzzing tests
        @type blacklist_status: blacklist_status
        @param blacklist_status: The blacklist status object
                                 to handle with the blacklisted status
        @type result_callback: Callable
        @param result_callback: The callback function for the results
        @type exception_callbacks: List[Callable]
        @param exception_callbacks: The list that handles
                                    with exception callbacks
        """
        self.__requester = requester
        self.__dict = dictionary
        self.__matcher = matcher
        self.__scanner = scanner
        self.__delay = delay
        self.__running = True
        self.__blacklist_status = blacklist_status
        self.result_callback = result_callback
        self.exception_callbacks = exception_callbacks
        self.setup_threads(number_of_threads)

    def setup_threads(self, number_of_threads: int) -> None:
        """Handle with threads setup

        @type number_of_threads: int
        @param number_of_threads: The number of threads
                                  used in the fuzzing tests

        Attributes:
            threads: The list with the threads used in the application
            running_threads: The running threads count
            paused_threads: The paused threads count
            join_timeout: The join timeout for the threads
            player: The player event object handler
        """
        self.__threads = [Thread(target=self.run, daemon=True) for _ in range(number_of_threads)]
        self.__running_threads = number_of_threads
        self.__paused_threads = 0
        self.__join_timeout = 0.001*float(number_of_threads)
        self.__player = Event()
        self.__player.clear()  # Not necessary, but force the blocking of the threads

    def is_running(self) -> bool:
        """The running flag getter

        @returns bool: The running flag
        """
        return self.__running

    def is_paused(self) -> bool:
        """The paused flag getter

        @returns bool: The paused flag
        """
        return not self.__player.isSet()

    def run(self) -> None:
        """Run the threads"""
        while not self.__dict.is_empty():
            for payload in next(self.__dict):
                try:
                    response, rtt, *args = self.__requester.request(str(payload))
                except InvalidHostname as e:
                    self.exception_callbacks[0](Error(e, payload))
                except RequestException as e:
                    self.exception_callbacks[1](Error(e, payload))
                else:
                    self.__threat_result(response, rtt, payload, *args)
                finally:
                    time.sleep(self.__delay)
            if self.is_paused():
                self.__paused_threads += 1
                self.__player.wait()
        self.__running_threads -= 1

    def join(self) -> bool:
        """Join the threads

        @returns bool: A flag to say if the threads are running or not
        """
        for thread in self.__threads:
            thread.join(self.__join_timeout)
            if thread.is_alive():
                return True
        return False

    def start(self) -> None:
        """Starts the fuzzer application"""
        self.__player.set()  # Awake threads
        for thread in self.__threads:
            thread.start()

    def pause(self) -> None:
        """Pause the fuzzer application"""
        self.__player.clear()

    def stop(self) -> None:
        """Stop the fuzzer application"""
        self.__running = False
        self.pause()
        self.wait_until_pause()

    def resume(self) -> None:
        """Resume the fuzzer application"""
        self.__paused_threads = 0
        self.__player.set()

    def wait_until_pause(self) -> None:
        while self.__paused_threads < (self.__running_threads-1):
            """Do nothing until all threads are paused"""
            pass
        time.sleep(0.1)

    def __threat_result(self,
                        response: Response,
                        rtt: float,
                        payload: Payload,
                        *args):
        """Threats the result

        @type response: Response
        @param response: The response object from the request
        @type rtt: float
        @param rtt: The elapsed time between request and response
        @type payload: Payload
        @param payload: The payload used in the request
        """
        if (self.__blacklist_status and
                response.status_code in self.__blacklist_status.codes):
            self.__blacklist_status.do_action(response.status_code)
        result = Result(response, rtt, payload, self.__requester.get_fuzzing_type())
        self.__scanner.inspect_result(result, *args)
        self.result_callback(
            result,
            (self.__scanner.scan(result)
             if self.__matcher.match(result)
             else False)
        )
