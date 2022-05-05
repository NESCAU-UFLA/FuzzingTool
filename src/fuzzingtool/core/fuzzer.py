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
from typing import Callable, Union, Any

from requests.models import Response

from .dictionary import Dictionary
from ..conn.requesters import Requester
from ..objects import Error, Payload
from ..exceptions import RequestException, InvalidHostname


class Fuzzer:
    """Fuzzer class, the core of the software

    Attributes:
        requester: The requester object to deal with the requests
        dict: The dictionary object to handle with the payloads
        delay: The delay between each test
        running: A flag to say if the application is running or not
    """
    def __init__(self,
                 requester: Requester,
                 dictionary: Dictionary,
                 delay: float,
                 number_of_threads: int,
                 response_callback: Callable[[dict, bool], None],
                 exception_callbacks: Callable[[Response, float, Payload, Union[Any, None]], None]):
        """Class constructor

        @type requester: Requester
        @param requester: The requester object to deal with the requests
        @type dict: Dictionary
        @param dict: The dicttionary object to deal with the payload dictionary
        @type delay: float
        @param delay: The delay between each request
        @type number_of_threads: int
        @param number_of_threads: The number of threads
                                  used in the fuzzing tests
        @type response_callback: Callable
        @param response_callback: The callback function for the results
        @type exception_callbacks: List[Callable]
        @param exception_callbacks: The list that handles
                                    with exception callbacks
        """
        self.__requester = requester
        self.__dict = dictionary
        self.__delay = delay
        self.__running = True
        self.response_callback = response_callback
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
                    response, rtt, *ip = self.__requester.request(str(payload))
                    self.response_callback(response, rtt, payload, *ip)
                except InvalidHostname as e:
                    self.exception_callbacks[0](Error(e, payload))
                except RequestException as e:
                    self.exception_callbacks[1](Error(e, payload))
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
        self.__player.set()
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
        """Blocks until all threads are paused"""
        while self.__paused_threads < self.__running_threads:
            """Wait until all threads are paused"""
            pass
        time.sleep(0.1)
