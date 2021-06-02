## FuzzingTool
# 
# Authors:
#    Vitor Oriel C N Borges <https://github.com/VitorOriel>
# License: MIT (LICENSE.md)
#    Copyright (c) 2021 Vitor Oriel
#    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
#    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
#    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
## https://github.com/NESCAU-UFLA/FuzzingTool

from .Dictionary import Dictionary
from .Matcher import Matcher
from .Result import Result
from .scanners import *
from ..conn.requests import *
from ..exceptions.RequestExceptions import RequestException, InvalidHostname

from threading import Thread, Event
import time
from typing import Callable

class Fuzzer:
    """Fuzzer class, the core of the software
    
    Attributes:
        requester: The requester object to deal with the requests
        dict: The dictionary object to handle with the payloads
        matcher: A matcher object, used to match the results
        scanner: A scanner object, used to validate the results
        delay: The delay between each test
        numberOfThreads: The number of threads used in the application
        running: A flag to say if the application is running or not
    """
    def __init__(self,
        requester: Request,
        dictionary: Dictionary,
        matcher: Matcher,
        scanner: BaseScanner,
        delay: float,
        numberOfThreads: int,
        resultCallback: Callable[[dict, bool], None],
        exceptionCallbacks: list, # Callback list
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
        @type resultCallback: Callable
        @param resultCallback: The callback function for the results
        @type exceptionCallbacks: list
        @param exceptionCallbacks: The list that handles with exception callbacks
        """
        self.__requester = requester
        self.__dict = dictionary
        self.__matcher = matcher
        self.__scanner = scanner
        self.__delay = delay
        self.__numberOfThreads = numberOfThreads
        self.__running = True
        self.resultsCallback = resultCallback
        self.exceptionCallbacks = exceptionCallbacks
        self.setup()

    def setup(self):
        """Handle with threads setup
        
        Attributes:
            threads: The list with the threads used in the application
            runningThreads: The running threads count
            joinTimeout: The join timeout for the threads
            player: The player event object handler - an internal flag manager for the threads
        """
        self.__threads = []
        for i in range(self.__numberOfThreads):
            self.__threads.append(Thread(target=self.run, daemon=True))
        self.__runningThreads = self.__numberOfThreads
        self.__joinTimeout = 0.001*float(self.__numberOfThreads)
        self.__player = Event()
        self.__player.clear() # Not necessary, but force the blocking of the threads

    def isRunning(self):
        """The running flag getter

        @returns bool: The running flag
        """
        return self.__running

    def isPaused(self):
        """The paused flag getter

        @returns bool: The paused flag
        """
        return not self.__player.isSet()

    def run(self):
        """Run the threads"""
        while not self.__dict.isEmpty():
            payloads = next(self.__dict)
            for payload in payloads:
                try:
                    response, RTT, *args = self.__requester.request(payload)
                    result = Result(response, RTT, self.__requester.index, payload)
                    self.__scanner.inspectResult(result, *args)
                    self.resultsCallback(
                        result,
                        self.__scanner.scan(result) if self.__matcher.match(result) else False
                    )
                except InvalidHostname as e:
                    self.exceptionCallbacks[0](e, payload)
                except RequestException as e:
                    self.exceptionCallbacks[1](e, payload)
                finally:
                    time.sleep(self.__delay)
            if self.isPaused():
                self.__runningThreads -= 1
                self.__player.wait()

    def join(self):
        """Join the threads

        @returns bool: A flag to say if the threads are running or not
        """
        for thread in self.__threads:
            thread.join(self.__joinTimeout)
            if thread.is_alive():
                return True
        return False

    def start(self):
        """Starts the fuzzer application"""
        self.__player.set() # Awake threads
        for thread in self.__threads:
            thread.start()

    def pause(self):
        """Pause the fuzzer application"""
        self.__player.clear()
        while self.__runningThreads > 1:
            pass
        time.sleep(0.1)

    def stop(self):
        """Stop the fuzzer application"""
        self.__running = False
        self.pause()
    
    def resume(self):
        """Resume the fuzzer application"""
        self.__runningThreads = self.__numberOfThreads
        self.__player.set()