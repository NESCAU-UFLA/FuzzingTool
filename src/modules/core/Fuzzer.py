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
        self.__outputFileContent = []
        self.__numLines = 0
        self.__startedTime = 0

    def getRequester(self):
        """The requester getter

        @returns object: The requester object
        """
        return self.__requester

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

    def prepareApplication(self):
        """Prepares the application"""
        try:
            self.__checkConnectionAndRedirections()
            self.__checkProxies()
        except KeyboardInterrupt:
            exit('')
        try:
            oh.infoBox(f"Starting test on '{self.__requester.getUrl()}' ...")
            self.__startApplication()
        except KeyboardInterrupt:
            self.threadHandle('stop')
            while self.__numberOfThreads > 0:
                pass
            oh.abortBox("Test aborted")
            self.__showFooter()
        else:
            oh.infoBox("Test completed")

    def __checkConnectionAndRedirections(self):
        """Test the connection and redirection to target"""
        # If we'll not fuzzing the url paths, so
        # test the redirections before start the fuzzing
        if self.__requester.getUrlIndexToPayload():
            oh.infoBox("Test mode set to URL Fuzzing")
            try:
                self.__requester.testConnection()
            except RequestException:
                if not oh.askYesNo("Connection to target failed. Continue anyway? "):
                    exit()
            else:
                oh.infoBox("Connection status: OK")
            oh.infoBox("No redirection verifications to target are being tested")
        else:
            try:
                self.__requester.testConnection()
            except RequestException:
                oh.errorBox("Failed to connect to the server")
            oh.infoBox("Connection status: OK")
            oh.infoBox("Testing redirections ...")
            if self.__requester.hasRedirection():
                if (not oh.askYesNo("You was redirected to another page. Continue? (y/N): ")):
                    exit()
            else:
                oh.infoBox("No redirections")

    def __startApplication(self):
        """Starts the application"""
        firstResponse = self.__requester.request(' ')
        self.__defaultComparator['Length'] += int(firstResponse['Length'])
        self.__defaultComparator['Time'] += (firstResponse['Req Time']+firstResponse['Resp Time'])
        if (self.__verboseMode):
            oh.getHeader()
            oh.printContent([value for key, value in firstResponse.items()], False)
        self.threadHandle()
        if (self.__verboseMode):
            oh.getHeader()
        else:
            print("")
        self.__showFooter()

    def do(self, payload: str):
        """Do the fuzzing test with a given payload
        
        @type payload: str
        @param payload: The payload to be used on the request
        """
        thisResponse = self.__requester.request(payload)
        probablyVulnerable = self.__isVulnerable(thisResponse)
        if probablyVulnerable:
            self.__outputFileContent.append(thisResponse)
        if self.__verboseMode:
            oh.printContent([value for key, value in thisResponse.items()], probablyVulnerable)
        else:
            oh.progressStatus(str(int((int(thisResponse['Request'])/self.__numLines)*100)), len(self.__outputFileContent))

    def __checkProxies(self):
        if self.__requester.getProxy():
            oh.infoBox("Testing proxy ...")
            try:
                self.__requester.testConnection(proxy=True)
                oh.infoBox(f"Proxy {self.__requester.getProxy()['http']} worked")
            except RequestException:
                oh.warningBox(f"Proxy {proxy['http']} not worked")
                self.__requester.setProxy({})
        elif self.__requester.getProxyList():
            proxyList = []
            oh.infoBox("Testing proxies ...")
            for proxy in self.__requester.getProxyList():
                self.__requester.setProxy(proxy)
                try:
                    self.__requester.testConnection(proxy=True)
                    proxyList.append(proxy)
                    oh.infoBox(f"Proxy {proxy['http']} worked")
                except RequestException:
                    oh.warningBox(f"Proxy {proxy['http']} not worked")
            self.__requester.setProxy({})
            self.__requester.setProxyList(proxyList)

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

    def __showFooter(self):
        """Show the footer content of the software, after making the fuzzing"""
        if  self.__startedTime:
            oh.infoBox(f"Time taken: {float('%.2f'%(time.time() - self.__startedTime))} seconds")
        if self.__outputFileContent:
            oh.infoBox(f"Found {len(self.__outputFileContent)} possible payload(s)")
            oh.getHeader()
            for content in self.__outputFileContent:
                oh.printContent([value for key, value in content.items()], True)
            oh.getHeader()
            fh.writeOnOutput(self.__outputFileContent)
        else:
            oh.infoBox("No vulnerable entries was found")
    
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
            self.threadHandle('start')
            self.__startedTime = time.time()
            self.__payloads.join()
        
        if action == 'setup':
            return setup()
        elif action == 'run':
            return run
        elif action == 'start':
            return start()
        elif action == 'stop':
            return stop()