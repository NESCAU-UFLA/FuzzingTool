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

from .VulnValidator import VulnValidator
from .Payloader import Payloader
from ..conn.Request import Request
from ..conn.RequestException import RequestException
from ..IO.OutputHandler import outputHandler as oh
from ..IO.FileHandler import fileHandler as fh

from threading import Thread, Event, Semaphore
import time

class Fuzzer:
    """Fuzzer class, the core of the software
    
    Attributes:
        requester: The requester object to deal with the requests
        delay: The delay between each test
        verboseMode: The verbose mode flag
        numberOfThreads: The number of threads used in the application
        output: The output content to be send to the file
        dictSizeof: The number of payloads in the payload file
        vulnValidator: A vulnerability validator object
        payloader: The payloader object to handle with the payloads
    """
    def __init__(self, requester: Request, payloader: Payloader, dictSizeof: int):
        """Class constructor

        @type requester: requester
        @param requester: The requester object to deal with the requests
        @type payloader: Payloader
        @param payloader: The payloader object to deal with the payload dictionary
        @type dictSizeof: int
        @param dictSizeof: The number of payloads in total
        """
        self.__requester = requester
        self.__delay = 0
        self.__verboseMode = False
        self.__ignoreErrors = False
        self.__numberOfThreads = 1
        self.__output = []
        self.__dictSizeof = dictSizeof
        self.__vulnValidator = VulnValidator()
        self.__payloader = payloader

    def getRequester(self):
        """The requester getter

        @returns object: The requester object
        """
        return self.__requester

    def isVerboseMode(self):
        """The verboseMode getter

        @returns bool: The verbose mode flag
        """
        return self.__verboseMode
    
    def getOutput(self):
        """The output content getter

        @returns list: The output content list
        """
        return self.__output

    def getVulnValidator(self):
        """The vulnerability validator getter

        @returns VulnValidator: A vulnerability validator object
        """
        return self.__vulnValidator

    def getPayloader(self):
        """The payloader getter

        @returns Payloader: The payloader object
        """
        return self.__payloader

    def setDelay(self, delay: float):
        """The delay setter

        @type delay: float
        @param delay: The delay used between each request
        """
        self.__delay = delay
    
    def setVerboseMode(self, verboseMode: bool):
        """The verboseMode setter

        @type verboseMode: bool
        @param verboseMode: The verbose mode flag
        """
        self.__verboseMode = verboseMode

    def setIgnoreErrors(self, ignoreErrors: bool):
        """The ignoreErrors setter

        @type ignoreErrors: bool
        @param ignoreErrors: The ignore errors flag
        """
        self.__ignoreErrors = ignoreErrors

    def setNumThreads(self, numberOfThreads: int):
        """The numberOfThreads setter

        @type numberOfThreads: int
        @param numberOfThreads: The number of threads
        """
        self.__numberOfThreads = numberOfThreads

    def threadHandle(self, action: str):
        """Function that handle with all of the threads functions and atributes

        @type action: str
        @param action: The action taken by the thread handler
        @returns func: A thread function
        """
        def run():
            """Run the threads"""
            self.__playerHandler.wait()
            while self.__running and not self.__payloader.isEmpty():
                payload = self.__payloader.get()
                for p in payload:
                    try:
                        self.do(p)
                        time.sleep(self.__delay)
                    except RequestException as e:
                        self.__handleRequestException(e, p)
                if not self.__playerHandler.isSet():
                    self.__numberOfThreads -= 1
                    self.__semaphoreHandler.release()
                    self.__playerHandler.wait()

        def start():
            """Handle with threads start"""
            self.__playerHandler.set() # Awake threads
            for thread in self.__threads:
                thread.start()
            for thread in self.__threads:
                thread.join()

        def stop():
            """Handle with threads stop"""
            self.__running = False
            self.__playerHandler.clear()

        def setup():
            """Handle with threads setup
            
            New Fuzzer Attributes:
                threads: The list with the threads used in the application
                running: A flag to say if the application is running or not
                playerHandler: The Event object handler - an internal flag manager for the threads
                semaphoreHandler: The Semaphore object handler - an internal counter manager for the threads
            """
            self.__threads = []
            self.__running = True
            for i in range(self.__numberOfThreads):
                self.__threads.append(Thread(target=run, daemon=True))
            self.__playerHandler = Event()
            self.__semaphoreHandler = Semaphore(0)
            self.__playerHandler.clear() # Not necessary, but force the blocking of the threads
        
        if action == 'setup': return setup()
        elif action == 'start': return start()
        elif action == 'stop': return stop()

    def start(self):
        """Starts the fuzzer application"""
        self.threadHandle('setup')
        self.threadHandle('start')

    def stop(self):
        """Stop the fuzzer application"""
        self.threadHandle('stop')
        while self.__numberOfThreads > 0:
            pass

    def do(self, payload: str):
        """Do the fuzzing test with a given payload
        
        @type payload: str
        @param payload: The payload to be used on the request
        """
        thisResponse = self.__requester.request(payload)
        probablyVulnerable = self.__vulnValidator.scan(thisResponse)
        if probablyVulnerable:
            self.__output.append(thisResponse)
        if self.__verboseMode:
            oh.printContent(thisResponse, probablyVulnerable)
        else:
            oh.progressStatus(
                str(int((int(thisResponse['Request'])/self.__dictSizeof)*100)),
                len(self.__output)
            )

    def __handleRequestException(self, e: RequestException, payload: str):
        """Handle with the request exceptions based on their types
        
        @type e: RequestException
        @param e: The request exception
        @type payload: str
        @param payload: The payload used in the request
        """
        if e.type == 'continue':
            if self.__verboseMode:
                oh.notWorkedBox(str(e))
            else:
                oh.progressStatus(
                    str(int((int(self.__requester.getRequestIndex())/self.__dictSizeof)*100)),
                    len(self.__output)
                )
        elif e.type == 'stop':
            if self.__ignoreErrors:
                fh.writeLog(str(e))
            else:
                if self.__running:
                    self.stop()
                    oh.abortBox(str(e))