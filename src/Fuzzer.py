from modules.RequestHandler import RequestHandler
from modules.IO.OutputHandler import outputHandler as oh
from modules.IO.FileHandler import fileHandler as fh
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
        self.queue = queue
        self.fuzzer = fuzzer

    def run(self):
        while True:
            payload = self.queue.get()
            try:
                self.fuzzer.do(payload)
            finally:
                self.queue.task_done()

class Fuzzer:
    """Fuzzer class, the core of the software
    
    Attributes:
        requestHandler: The RequestHandler object to deal with the requests
        delay: The delay between each test
        verboseMode: The verbose mode flag
        additionalLength: The additional length to consider an entry probably vulnerable
        additionalTime: The additional time to consider an entry probably vulnerable
        firstResponse: The first response to be used in comparation with the requests with payloads
        outputFileContent: The output content to be send to the file
        numLines: The number of payloads in the payload file
    """
    def __init__(self, requestHandler: RequestHandler):
        """Class constructor

        @type requestHandler: RequestHandler
        @param requestHandler: The RequestHandler object to deal with the requests
        """
        self.__requestHandler = requestHandler
        self.__delay = 0
        self.__verboseMode = False
        self.__numberOfThreads = 1
        self.__additionalLength = 300
        self.__additionalTime = 5
        self.__firstResponse = {}
        self.__outputFileContent = []
        self.__numLines = 0

    def getRequestHandler(self):
        """The requestHandler getter

        @returns object: The RequestHandler object
        """
        return self.__requestHandler

    def getDelay(self):
        """The delay getter

        @returns float: The delay used between each request
        """
        return self.__delay

    def getVerboseMode(self):
        """The verboseMode getter

        @returns bool: The verbose mode flag
        """
        return self.__verboseMode

    def getFirstResponse(self):
        """The firstResponse getter

        @returns dict: The first response dictionary
        """
        return self.__firstResponse

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
        rh = self.__requestHandler
        try:
            self.__checkConnectionAndRedirections()
            oh.infoBox(f"Starting test on '{rh.getUrl()}' ...")
            self.__startApplication()
        except KeyboardInterrupt:
            oh.abortBox("Test aborted.")
            fh.writeOnOutput(self.__outputFileContent)
        else:
            oh.infoBox("Test completed.")

    def __checkConnectionAndRedirections(self):
        """Test the connection and redirection to target"""
        # If we'll not fuzzing the url paths, so
        # test the redirections before start the fuzzing
        if rh.getUrlIndexToPayload():
            oh.infoBox("Test mode set to URL Fuzzing. No redirection verifications to target are being tested.")
            try:
                rh.testConnection()
            except:
                if not oh.askYesNo("Connection to target failed. Continue anyway? "):
                    exit()
            else:
                oh.infoBox("Connection status: OK")
        else:
            try:
                rh.testConnection()
            except:
                oh.errorBox("Failed to connect to the server.")
            oh.infoBox("Connection status: OK")
            oh.infoBox("Testing redirections ...")
            rh.testRedirection()

    def __startApplication(self):
        """Starts the application"""
        rh = self.__requestHandler
        self.__firstResponse = rh.request(' ')
        if (self.__verboseMode):
            oh.getHeader()
            oh.printContent([value for key, value in self.__firstResponse.items()], False)
        self.__prepareFuzzEnv()
        if (self.__verboseMode):
            oh.getHeader()
        else:
            print("")
        fh.writeOnOutput(self.__outputFileContent)

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
            oh.progressStatus(str(int((int(thisResponse['Request'])/self.__numLines)*100)))
        time.sleep(self.__delay)

    def __isVulnerable(self, thisResponse: dict):
        """Check if the request content has some predefined characteristics based on a payload, it'll be considered as vulnerable
        
        @type thisResponse: dict
        @param thisResponse: The actual response dictionary
        @returns bool: A vulnerability flag
        """
        if self.__requestHandler.getUrlIndexToPayload():
            if thisResponse['Status'] < 400:
                return True
            else:
                return False
        elif (int(thisResponse['Length']) > (int(self.__firstResponse['Length'])+self.__additionalLength)
              or (thisResponse['Resp Time']+thisResponse['Req Time']) > ((self.__firstResponse['Req Time']+self.__firstResponse['Resp Time'])+self.__additionalTime)):
            return True
        return False