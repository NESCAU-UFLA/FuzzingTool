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
        defaultComparator: The dictionary with the default entries to be compared with the current request
        outputFileContent: The output content to be send to the file
        numLines: The number of payloads in the payload file
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
        self.__defaultComparator = {
            'Length': 300,
            'Time': 5,
        }
        self.__output = []
        self.__numLines = 0

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
            while self.__running:
                payload = self.__payloads.get()
                try:
                    self.do(payload)
                    time.sleep(self.__delay)
                except RequestException as e:
                    oh.warningBox(e.getMessage())
                finally:
                    self.__payloads.task_done()
                    if not self.__eventHandler.isSet():
                        self.__numberOfThreads -= 1
                        self.__semaphoreHandler.release()
                        self.__eventHandler.wait()

        def start():
            """Handle with threads start"""
            self.__eventHandler.set() # Awake threads
            for thread in self.__threads:
                thread.start()
            self.__payloads.join()

        def stop():
            """Handle with threads stop"""
            self.__running = False
            self.__eventHandler.clear() # Block the threads
            for thread in self.__threads:
                if thread.is_alive():
                    self.__semaphoreHandler.acquire()

        def setup():
            """Handle with threads setup"""
            self.__payloads = Queue()
            self.__threads = []
            self.__running = True
            for i in range(self.__numberOfThreads):
                self.__threads.append(Thread(target=self.threadHandle('run')))
                self.__threads[i].daemon = True
            self.__eventHandler = Event()
            self.__semaphoreHandler = Semaphore(0)
            self.__eventHandler.clear() # Not necessary, but force the blocking of the threads
            wordlist, self.__numLines = fh.getWordlistContentAndLength()
            for payload in wordlist:
                self.__payloads.put(payload)
        
        if action == 'setup':
            return setup()
        elif action == 'run':
            return run
        elif action == 'start':
            return start()
        elif action == 'stop':
            return stop()

    def start(self):
        """Starts the fuzzer application"""
        firstResponse = self.__requester.request(' ')
        self.__defaultComparator['Length'] += int(firstResponse['Length'])
        self.__defaultComparator['Time'] += (firstResponse['Req Time']+firstResponse['Resp Time'])
        if self.__verboseMode:
            oh.getHeader()
            oh.printContent([value for key, value in firstResponse.items()], False)
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
        probablyVulnerable = self.__isVulnerable(thisResponse)
        if probablyVulnerable:
            self.__output.append(thisResponse)
        if self.__verboseMode:
            oh.printContent([value for key, value in thisResponse.items()], probablyVulnerable)
        else:
            oh.progressStatus(str(int((int(thisResponse['Request'])/self.__numLines)*100)), len(self.__output))

    def __isVulnerable(self, thisResponse: dict):
        """Check if the request content has some predefined characteristics based on a payload, it'll be considered as vulnerable
        
        @type thisResponse: dict
        @param thisResponse: The actual response dictionary
        @returns bool: A vulnerability flag
        """
        if thisResponse['Status'] < 400:
            if self.__requester.getUrlIndexToPayload():
                return True
            elif self.__defaultComparator['Length'] < int(thisResponse['Length']):
                return True
        if not self.__requester.getUrlIndexToPayload() and self.__defaultComparator['Time'] < (thisResponse['Resp Time']+thisResponse['Req Time']):
            return True
        return False