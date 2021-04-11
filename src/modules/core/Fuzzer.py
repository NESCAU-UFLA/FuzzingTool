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

from .dictionaries import *
from .scanners import *
from ..conn.Request import Request
from ..IO.OutputHandler import outputHandler as oh
from ..IO.FileHandler import fileHandler as fh
from ..exceptions.MainExceptions import SkipTargetException
from ..exceptions.RequestExceptions import RequestException, InvalidHostname

from threading import Thread, Event, Semaphore
import time
from typing import Callable

class Fuzzer:
    """Fuzzer class, the core of the software
    
    Attributes:
        requester: The requester object to deal with the requests
        delay: The delay between each test
        numberOfThreads: The number of threads used in the application
        scanner: A scanner object, used to validate the results
        dict: The dictionary object to handle with the payloads
    """
    def __init__(self,
        requester: Request,
        dictionary: BaseDictionary,
        scanner: BaseScanner,
        delay: float,
        numberOfThreads: int,
        resultCallback: Callable[[dict, bool], None],
        exceptionCallbacks: list, # Callback list
    ):
        """Class constructor

        @type requester: requester
        @param requester: The requester object to deal with the requests
        @type dict: BaseDictionary
        @param dict: The dicttionary object to deal with the payload dictionary
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
        self.__delay = delay
        self.__numberOfThreads = numberOfThreads
        self.__scanner = scanner
        self.__dict = dictionary
        self.__resultsCallback = resultCallback
        self.__exceptionCallbacks = exceptionCallbacks

    def isRunning(self):
        """The running flag getter

        @returns bool: The running flag
        """
        return self.__running

    def isPaused(self):
        """The paused flag getter

        @returns bool: The paused flag
        """
        return self.__paused

    def threadHandle(self, action: str):
        """Function that handle with all of the threads functions and atributes

        @type action: str
        @param action: The action taken by the thread handler
        @returns func: A thread function
        """
        def run():
            """Run the threads"""
            while self.__running and not self.__dict.isEmpty():
                if not self.__paused:
                    payload = next(self.__dict)
                    for p in payload:
                        try:
                            result = self.__scanner.getResult(
                                response=self.__requester.request(p)
                            )
                            self.__resultsCallback(
                                result,
                                self.__scanner.scan(result) if self.__scanner.match(result) else False
                            )
                        except InvalidHostname as e:
                            self.__exceptionCallbacks[0](e)
                        except RequestException as e:
                            self.__exceptionCallbacks[1](e)
                        finally:
                            time.sleep(self.__delay)
                if not self.__playerHandler.isSet():
                    self.__threadsRunning -= 1
                    self.__semaphoreHandler.release()

        def start():
            """Handle with threads start"""
            self.__playerHandler.set() # Awake threads
            for thread in self.__threads:
                thread.start()

        def stop():
            """Handle with threads stop"""
            self.__running = False
            self.__playerHandler.clear()

        def resume():
            """Handle with the threads resume"""
            self.__playerHandler.set()
            self.__threadsRunning = self.__numberOfThreads
            self.__paused = False
            self.__semaphoreHandler.release()

        def pause():
            """Handle with the threads pause"""
            self.__paused = True
            if self.__numberOfThreads > 1:
                self.__playerHandler.clear()
                for thread in self.__threads:
                    if thread.is_alive():
                        self.__semaphoreHandler.acquire()
                        time.sleep(self.__joinTimeout)

        def join():
            """Join the threads

            @returns bool: A flag to say if the threads are running or not
            """
            for thread in self.__threads:
                thread.join(self.__joinTimeout)
                if thread.is_alive():
                    return False
            return True

        def setup():
            """Handle with threads setup
            
            New Fuzzer Attributes:
                threads: The list with the threads used in the application
                running: A flag to say if the application is running or not
                joinTimeout: The join timeout for the threads
                playerHandler: The Event object handler - an internal flag manager for the threads
                semaphoreHandler: The Semaphore object handler - an internal counter manager for the threads
            """
            self.__paused = False
            self.__threadsRunning = self.__numberOfThreads
            self.__threads = []
            self.__running = True
            for i in range(self.__numberOfThreads):
                self.__threads.append(Thread(target=run, daemon=True))
            self.__joinTimeout = 0.001*float(self.__numberOfThreads)
            self.__playerHandler = Event()
            self.__semaphoreHandler = Semaphore(0)
            self.__playerHandler.clear() # Not necessary, but force the blocking of the threads

        if action == 'setup': return setup()
        elif action == 'start': return start()
        elif action == 'stop': return stop()
        elif action == 'join': return join
        elif action == 'resume': return resume()
        elif action == 'pause': return pause()

    def start(self):
        """Starts the fuzzer application"""
        self.threadHandle('setup')
        self.threadHandle('start')
        self.join = self.threadHandle('join')

    def stop(self):
        """Stop the fuzzer application"""
        self.threadHandle('stop')
        while self.__threadsRunning > 1:
            pass
        time.sleep(0.1)
    
    def resume(self):
        """Resume the fuzzer application"""
        self.threadHandle('resume')
    
    def pause(self):
        """Pause the fuzzer application"""
        self.threadHandle('pause')
        while self.__threadsRunning > 0:
            pass