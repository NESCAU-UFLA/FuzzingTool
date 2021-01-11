from ..conn.Request import Request
from ..IO.OutputHandler import outputHandler as oh
from ..IO.FileHandler import fileHandler as fh
from threading import Thread
from queue import Queue
import time

class ThreadHandler(Thread):
    """ThreadHandler class, handles with the threads

    Attributes:
        queue: The payload queue
        fuzzer: The fuzzer object to do the fuzzing tests
    """
    def __init__(self, queue, fuzzer):
        """Class constructor

        @type queue: Queue
        @param queue: The payload queue
        @type fuzzer: Fuzzer
        @param fuzzer: The fuzzer object to do the fuzzing tests
        """
        Thread.__init__(self)
        self.__queue = queue
        self.__fuzzer = fuzzer

    def run(self):
        """Run the threads"""
        while True:
            payload = self.__queue.get()
            try:
                self.__fuzzer.do(payload)
            finally:
                self.__queue.task_done()

class Fuzzer:
    """Fuzzer class, the core of the software
    
    Attributes:
        requestHandler: The RequestHandler object to deal with the requests
        delay: The delay between each test
        verboseMode: The verbose mode flag
        defaultComparator: The dictionary with the default entries to be compared with the current request
        outputFileContent: The output content to be send to the file
        numLines: The number of payloads in the payload file
    """
    def __init__(self, requestHandler: Request):
        """Class constructor

        @type requestHandler: RequestHandler
        @param requestHandler: The RequestHandler object to deal with the requests
        """
        self.__requestHandler = requestHandler
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

    def getRequestHandler(self):
        """The requestHandler getter

        @returns object: The RequestHandler object
        """
        return self.__requestHandler

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
        except KeyboardInterrupt:
            exit('')
        try:
            oh.infoBox(f"Starting test on '{self.__requestHandler.getUrl()}' ...")
            self.__startApplication()
        except KeyboardInterrupt:
            oh.abortBox("Test aborted")
            self.__showFooter()
        else:
            oh.infoBox("Test completed")

    def __checkConnectionAndRedirections(self):
        """Test the connection and redirection to target"""
        # If we'll not fuzzing the url paths, so
        # test the redirections before start the fuzzing
        rh = self.__requestHandler
        if rh.getUrlIndexToPayload():
            oh.infoBox("Test mode set to URL Fuzzing")
            try:
                rh.testConnection()
            except:
                if not oh.askYesNo("Connection to target failed. Continue anyway? "):
                    exit()
            else:
                oh.infoBox("Connection status: OK")
            oh.infoBox("No redirection verifications to target are being tested")
        else:
            try:
                rh.testConnection()
            except:
                oh.errorBox("Failed to connect to the server")
            oh.infoBox("Connection status: OK")
            oh.infoBox("Testing redirections ...")
            rh.testRedirection()

    def __startApplication(self):
        """Starts the application"""
        rh = self.__requestHandler
        firstResponse = rh.request(' ')
        self.__defaultComparator['Length'] += int(firstResponse['Length'])
        self.__defaultComparator['Time'] += (firstResponse['Req Time']+firstResponse['Resp Time'])
        if (self.__verboseMode):
            oh.getHeader()
            oh.printContent([value for key, value in firstResponse.items()], False)
        self.__prepareFuzzEnv()
        if (self.__verboseMode):
            oh.getHeader()
        else:
            print("")
        self.__showFooter()

    def __prepareFuzzEnv(self):
        """Prepare the Fuzzing env"""
        queue = Queue()
        for i in range(self.__numberOfThreads):
            worker = ThreadHandler(queue, self)
            worker.daemon = True
            worker.start()
        wordlist, self.__numLines = fh.getWordlistContentAndLength()
        for payload in wordlist:
            queue.put(payload)
        self.__startedTime = time.time()
        queue.join()

    def do(self, payload: str):
        """Do the fuzzing test with a given payload
        
        @type payload: str
        @param payload: The payload to be used on the request
        """
        thisResponse = self.__requestHandler.request(payload)
        probablyVulnerable = self.__isVulnerable(thisResponse)
        if probablyVulnerable:
            self.__outputFileContent.append(thisResponse)
        if (self.__verboseMode):
            oh.printContent([value for key, value in thisResponse.items()], probablyVulnerable)
        else:
            oh.progressStatus(str(int((int(thisResponse['Request'])/self.__numLines)*100)), len(self.__outputFileContent))
        time.sleep(self.__delay)

    def __isVulnerable(self, thisResponse: dict):
        """Check if the request content has some predefined characteristics based on a payload, it'll be considered as vulnerable
        
        @type thisResponse: dict
        @param thisResponse: The actual response dictionary
        @returns bool: A vulnerability flag
        """
        if thisResponse['Status'] < 400:
            if self.__requestHandler.getUrlIndexToPayload():
                return True
            elif self.__defaultComparator['Length'] < int(thisResponse['Length']):
                return True
        if not self.__requestHandler.getUrlIndexToPayload() and self.__defaultComparator['Time'] < (thisResponse['Resp Time']+thisResponse['Req Time']):
            return True
        return False

    def __showFooter(self):
        """Show the footer content of the software, after making the fuzzing"""
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