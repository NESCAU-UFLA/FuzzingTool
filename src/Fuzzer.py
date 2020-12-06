from RequestHandler import RequestHandler
from OutputHandler import *
from FileHandler import *
import time

class Fuzzer:
    """Fuzzer class, the core of the software
    
    Attributes:
        requestHandler: The RequestHandler object to deal with the requests
        delay: The delay between each test
        verboseMode: The verbose mode flag
        additionalLength: The additional length to consider an entry probably vulnerable
        additionalTime: The additional time to consider an entry probably vulnerable
        hasProxies: A flag to define if a proxies file is used
    """
    def __init__(self, requestHandler: RequestHandler):
        """Class constructor

        @type requestHandler: RequestHandler
        @param requestHandler: The RequestHandler object to deal with the requests
        """
        self.__requestHandler = requestHandler
        self.__delay = 0
        self.__verboseMode = False
        self.__additionalLength = 300
        self.__additionalTime = 5
        self.__hasProxies = False

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

    def prepareApplication(self):
        """Prepares the application"""
        rh = self.getRequestHandler()
        if fh.getProxiesFile() != None:
            self.__hasProxies = True
            rh.setProxiesFromFile()
        # If we'll not fuzzing the url paths, so
        # test the connection and redirections before start the fuzzing
        if rh.getUrlIndexToPayload() != -1:
            oh.infoBox("Test mode set to URL Fuzzing. No connections or redirections to target are being tested.")
        else:
            if rh.testConnection() != None:
                oh.infoBox("Connection status: OK")
            else:
                oh.errorBox("Failed to connect to the server.")
            oh.infoBox("Testing redirections ...")
            rh.testRedirection()
        oh.infoBox("Starting test on '"+rh.getUrl()+"' ...")
        try:
            self.__start()
        except KeyboardInterrupt:
            oh.infoBox("Test cancelled.")
        else:
            oh.infoBox("Test completed.")

    def __start(self):
        """Starts the application"""
        rh = self.getRequestHandler()
        firstResponse = rh.request(' ')
        if (self.getVerboseMode()):
            oh.getHeader()
            oh.printContent([0, '', firstResponse['Status'], firstResponse['Length'], firstResponse['Time']], False)
        outputFileContent = []
        self.__startFuzz(firstResponse, outputFileContent)
        fh.writeOnOutput(outputFileContent)
        if (self.getVerboseMode()):
            oh.getHeader()
        else:
            print("")

    def __startFuzz(self, firstResponse: object, outputFileContent: list):
        """Starts the fuzzing tests

        @type firstResponse: object
        @param firstResponse: The first response
        @type outputFileContent: list
        @param outputFileContent: The output list with probably vulnerable data into a dictionary
        """
        rh = self.getRequestHandler()
        wordlist, numLines = fh.getWordlistContentAndLength()
        i = 0 # The request index
        for payload in wordlist:
            if (self.__hasProxies and i%1000 == 0):
                rh.setProxyByRequestIndex(i)
            i += 1
            thisResponse = rh.request(payload)
            thisResponse['Request'] = str(i)
            probablyVulnerable = self.__isVulnerable(thisResponse, firstResponse)
            if probablyVulnerable:
                outputFileContent.append(thisResponse)
            if (self.getVerboseMode()):
                oh.printContent([value for key, value in thisResponse.items()], probablyVulnerable)
            else:
                oh.progressStatus(str(int((i/numLines)*100)))
            time.sleep(self.getDelay())

    def __isVulnerable(self, thisResponse: dict, firstResponse: dict):
        """Check if the request content has some predefined characteristics based on a payload, it'll be considered as vulnerable
        
        @type thisResponse: dict
        @param thisResponse: The actual response dictionary
        @type firstResponse: dict
        @param firstResponse: The first response dictionary
        @returns bool: A vulnerability flag
        """
        if self.getRequestHandler().getUrlIndexToPayload() != -1 and thisResponse['Status'] < 400:
            return True
        elif ((int(thisResponse['Length']) > (int(firstResponse['Length'])+self.__additionalLength)
              or thisResponse['Time'] > (firstResponse['Time']+self.__additionalTime))):
            return True
        return False