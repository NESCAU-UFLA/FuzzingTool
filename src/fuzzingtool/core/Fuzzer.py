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

from .BlacklistStatus import BlacklistStatus
from .Dictionary import Dictionary
from .Matcher import Matcher
from .Result import Result
from .bases.BaseScanner import BaseScanner
from ..conn.requests import *
from ..exceptions.MainExceptions import SkipTargetException
from ..exceptions.RequestExceptions import RequestException, InvalidHostname

from threading import Thread, Event
import time
from typing import Callable, List

class Fuzzer:
    """Fuzzer class, the core of the software
    
    Attributes:
        requester: The requester object to deal with the requests
        dict: The dictionary object to handle with the payloads
        matcher: A matcher object, used to match the results
        scanner: A scanner object, used to validate the results
        delay: The delay between each test
        running: A flag to say if the application is running or not
        blacklistStatus: The blacklist status object to handle with the blacklisted status
        startIndex: The actual request index
    """
    def __init__(self,
        requester: Request,
        dictionary: Dictionary,
        matcher: Matcher,
        scanner: BaseScanner,
        delay: float,
        numberOfThreads: int,
        blacklistStatus: BlacklistStatus,
        startIndex: int,
        resultCallback: Callable[[dict, bool], None],
        exceptionCallbacks: List[Callable[[str, str], None]],
    ):
        """Class constructor

        @type requester: requester
        @param requester: The requester object to deal with the requests
        @type dict: Dictionary
        @param dict: The dicttionary object to deal with the payload dictionary
        @type matcher: Matcher
        @param matcher: The matcher for the results
        @type scanner: BaseScanner
        @param scanner: The fuzzing results scanner
        @type delay: float
        @param delay: The delay between each request
        @type numberOfThreads: int
        @param numberOfThreads: The number of threads used in the fuzzing tests
        @type blacklistStatus: BlacklistStatus
        @param blacklistStatus: The blacklist status object to handle with the blacklisted status
        @type startIndex: int
        @param startIndex: The index value to start
        @type resultCallback: Callable
        @param resultCallback: The callback function for the results
        @type exceptionCallbacks: List[Callable]
        @param exceptionCallbacks: The list that handles with exception callbacks
        """
        self.__requester = requester
        self.__dict = dictionary
        self.__matcher = matcher
        self.__scanner = scanner
        self.__delay = delay
        self.__running = True
        self.__blacklistStatus = blacklistStatus
        self.index = startIndex
        self.resultsCallback = resultCallback
        self.exceptionCallbacks = exceptionCallbacks
        self.setupThreads(numberOfThreads)

    def setupThreads(self, numberOfThreads: int) -> None:
        """Handle with threads setup
        
        @type numberOfThreads: int
        @param numberOfThreads: The number of threads used in the fuzzing tests

        Attributes:
            threads: The list with the threads used in the application
            runningThreads: The running threads count
            pausedThreads: The paused threads count
            joinTimeout: The join timeout for the threads
            player: The player event object handler - an internal flag manager for the threads
        """
        self.__threads = []
        for _ in range(numberOfThreads):
            self.__threads.append(Thread(target=self.run, daemon=True))
        self.__runningThreads = numberOfThreads
        self.__pausedThreads = 0
        self.__joinTimeout = 0.001*float(numberOfThreads)
        self.__player = Event()
        self.__player.clear() # Not necessary, but force the blocking of the threads

    def isRunning(self) -> bool:
        """The running flag getter

        @returns bool: The running flag
        """
        return self.__running

    def isPaused(self) -> bool:
        """The paused flag getter

        @returns bool: The paused flag
        """
        return not self.__player.isSet()

    def run(self) -> None:
        """Run the threads"""
        while not self.__dict.isEmpty():
            payloads = next(self.__dict)
            for payload in payloads:
                try:
                    response, RTT, *args = self.__requester.request(payload)
                except InvalidHostname as e:
                    self.exceptionCallbacks[0](e, payload)
                except RequestException as e:
                    self.exceptionCallbacks[1](e, payload)
                else:
                    if (self.__blacklistStatus and
                        response.status_code in self.__blacklistStatus.codes):
                        self.__blacklistStatus.actionCallback(response.status_code)
                    result = Result(response, RTT, self.index, payload)
                    self.__scanner.inspectResult(result, *args)
                    self.resultsCallback(
                        result,
                        self.__scanner.scan(result) if self.__matcher.match(result) else False
                    )
                finally:
                    self.index += 1
                    time.sleep(self.__delay)
            if self.isPaused():
                self.__pausedThreads += 1
                self.__player.wait()
        self.__runningThreads -= 1

    def join(self) -> bool:
        """Join the threads

        @returns bool: A flag to say if the threads are running or not
        """
        for thread in self.__threads:
            thread.join(self.__joinTimeout)
            if thread.is_alive():
                return True
        return False

    def start(self) -> None:
        """Starts the fuzzer application"""
        self.__player.set() # Awake threads
        for thread in self.__threads:
            thread.start()

    def pause(self) -> None:
        """Pause the fuzzer application"""
        self.__player.clear()

    def stop(self) -> None:
        """Stop the fuzzer application"""
        self.__running = False
        self.pause()
        self.waitUntilPause()
    
    def resume(self) -> None:
        """Resume the fuzzer application"""
        self.__pausedThreads = 0
        self.__player.set()
    
    def waitUntilPause(self) -> None:
        while self.__pausedThreads < (self.__runningThreads-1):
            pass
        time.sleep(0.1)