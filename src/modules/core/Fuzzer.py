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
from ..conn.Request import Request
from ..conn.RequestException import RequestException
from ..IO.OutputHandler import outputHandler as oh
from ..IO.FileHandler import fileHandler as fh

from threading import Thread, Event, Semaphore
from queue import Queue
import time

class Fuzzer:
    """Fuzzer class, the core of the software
    
    Attributes:
        requester: The requester object to deal with the requests
        delay: The delay between each test
        verboseMode: The verbose mode flag
        numberOfThreads: The number of threads used in the application
        output: The output content to be send to the file
        numLines: The number of payloads in the payload file
        vulnValidator: A vulnerability validator object
    """
    def __init__(self, requester: Request):
        """Class constructor

        @type requester: requester
        @param requester: The requester object to deal with the requests
        """
        self.__requester = requester
        self.__delay = 0
        self.__verboseMode = False
        self.__numberOfThreads = 1
        self.__output = []
        self.__numLines = 0
        self.__vulnValidator = None

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

    def setNumThreads(self, numberOfThreads: int):
        """The numberOfThreads setter

        @type numberOfThreads: int
        @param numberOfThreads: The number of threads
        """
        self.__numberOfThreads = numberOfThreads

    def threadHandle(self, action: str = 'setup'):
        """Function that handle with all of the threads functions and atributes

        @type action: str
        @param action: The action taken by the thread handler
        @returns func: A thread function
        """
        def run():
            """Run the threads"""
            self.__playerHandler.wait()
            while self.__running and not self.__payloads.empty():
                payload = self.__payloads.get()
                try:
                    self.do(payload)
                    time.sleep(self.__delay)
                except RequestException as e:
                    self.__handleRequestException(e, payload)
                finally:
                    if not self.__playerHandler.isSet():
                        self.__numberOfThreads -= 1
                        self.__semaphoreHandler.release()
                        self.__playerHandler.wait()
            self.__numberOfThreads -= 1

        def start():
            """Handle with threads start"""
            self.__playerHandler.set() # Awake threads
            for thread in self.__threads:
                thread.start()
            for thread in self.__threads:
                thread.join()

        def resume():
            """Handle with threads resume process"""
            self.__semaphoreHandler.release()
            self.__playerHandler.set()
            self.__numberOfThreads = len(self.__threads)

        def pause():
            """Handle with threads pause"""
            self.__playerHandler.clear() # Block the threads
            for thread in self.__threads:
                if thread.is_alive():
                    self.__semaphoreHandler.acquire()

        def isRunning():
            """Getter for the event handler flag
            
            @returns bool: A running flag
            """
            return self.__playerHandler.isSet()

        def stop():
            """Handle with threads stop"""
            self.__running = False
            self.__playerHandler.set()

        def setup():
            """Handle with threads setup
            
            New Fuzzer Attributes:
                payloads: The queue that contains all payloads inside the wordlist file
                threads: The list with the threads used in the application
                running: A flag to say if the application is running or not
                paused: A flag to say if the application is paused or not
                playerHandler: The Event object handler - an internal flag manager for the threads
                semaphoreHandler: The Semaphore object handler - an internal counter manager for the threads
            """
            self.__payloads = Queue()
            self.__threads = []
            self.__running = True
            self.__paused = False
            for i in range(self.__numberOfThreads):
                self.__threads.append(Thread(target=self.threadHandle('run')))
                self.__threads[i].daemon = True
            self.__playerHandler = Event()
            self.__semaphoreHandler = Semaphore(0)
            self.__playerHandler.clear() # Not necessary, but force the blocking of the threads
            wordlist, self.__numLines = fh.getWordlistContentAndLength()
            for payload in wordlist:
                self.__payloads.put(payload)
        
        if action == 'setup': return setup()
        elif action == 'run': return run
        elif action == 'start': return start()
        elif action == 'pause': return pause()
        elif action == 'resume': return resume()
        elif action == 'stop': return stop()
        elif action == 'isRunning': return isRunning()

    def start(self):
        """Starts the fuzzer application"""
        urlFuzzing = False if not self.__requester.getUrlIndexToPayload() else True
        if not urlFuzzing:
            firstResponse = self.__requester.request(payload)
            self.__vulnValidator = VulnValidator(
                urlFuzzing,
                int(firstResponse['Length']),
                (firstResponse['Req Time']+firstResponse['Resp Time'])
            )
        else:
            self.__vulnValidator = VulnValidator(urlFuzzing)
        if self.__verboseMode:
            oh.getHeader()
            if not urlFuzzing:
                oh.printContent([value for key, value in firstResponse.items()], False)
        self.threadHandle('setup')
        self.threadHandle('start')

    def stop(self):
        """stop the fuzzer application"""
        self.threadHandle('stop')
        while self.__numberOfThreads > 0:
            pass

    def resume(self):
        """Resume the fuzzer application"""
        self.__paused = False
        self.threadHandle('resume')

    def pause(self):
        """Pause the fuzzer application"""
        self.__paused = True
        self.threadHandle('pause')

    def isRunning(self):
        """Check if the application is running or not
        
        @returns bool: A running flag
        """
        return self.threadHandle('isRunning')

    def do(self, payload: str):
        """Do the fuzzing test with a given payload
        
        @type payload: str
        @param payload: The payload to be used on the request
        """
        thisResponse = self.__requester.request(payload)
        probablyVulnerable = self.__vulnValidator.isVulnerable(thisResponse)
        if probablyVulnerable:
            self.__output.append(thisResponse)
        if self.__verboseMode:
            oh.printContent([value for key, value in thisResponse.items()], probablyVulnerable)
        else:
            oh.progressStatus(str(int((int(thisResponse['Request'])/self.__numLines)*100)), len(self.__output))

    def __handleRequestException(self, e: RequestException, payload: str):
        if e.type == 'pause':
            if not self.__paused:
                self.pause()
                oh.warningBox("Pausing due "+str(e))
                if 'proxy' in str(e).tolower():
                    if self.__requester.handleProxyException():
                        self.resume()
                    else:
                        self.stop()
        elif e.type == 'stop':
            if self.__running:
                self.__numberOfThreads = 0
                self.stop()
                oh.abortBox(str(e))