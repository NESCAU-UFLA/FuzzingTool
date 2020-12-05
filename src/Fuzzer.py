from RequestHandler import RequestHandler
from OutputHandler import *
from FileHandler import *
import time

class Fuzzer:
    """
        delay: The delay time between each request
    """
    def __init__(self, requestHandler: RequestHandler):
        self.__requestHandler = requestHandler
        self.__delay = 0
        self.__verboseMode = False
        self.__additionalLength = 300
        self.__additionalTime = 5
        self.__hasProxies = False

    def getRequestHandler(self):
        return self.__requestHandler

    def getDelay(self):
        """The delay getter

        @returns float: The delay used between each request
        """
        return self.__delay

    def getVerboseMode(self):
        return self.__verboseMode

    def setRequestHandler(self, requestHandler: RequestHandler):
        self.__requestHandler = requestHandler

    def setDelay(self, delay: float):
        """The delay setter

        @param type: float
        @param delay: The delay used between each request
        """
        self.__delay = delay

    def setVerboseMode(self, verboseMode: bool):
        self.__verboseMode = verboseMode

    def prepareApplication(self):
        """Prepares the application
           test the connection and redirections before start the fuzzing
        """
        rh = self.getRequestHandler()
        if (fh.getProxiesFile() != None):
            self.__hasProxies = True
            rh.setProxiesFromFile()
        if (rh.testConnection() != None):
            oh.infoBox("Connection status: OK")
        else:
            oh.errorBox("Failed to connect to the server.")
        oh.infoBox("Testing redirections ...")
        rh.testRedirection()
        oh.infoBox("Starting test on '"+rh.getUrl()+"' ...")
        self.__start()
        oh.infoBox("Test completed.")

    def __start(self):
        """Make the start

        @param type: bool
        @param hasProxies: Case will use proxies from a list
        """
        rh = self.getRequestHandler()
        firstResponse = rh.request(' ')
        if (self.getVerboseMode()):
            oh.getHeader()
            oh.printContent([0, '', firstResponse['Status'], firstResponse['Length'], firstResponse['Time']], False)
        outputFileContent = []
        self.__startFuzzy(firstResponse, outputFileContent)
        fh.writeOnOutput(outputFileContent)
        if (self.getVerboseMode()):
            oh.getHeader()
        else:
            print("")

    def __startFuzzy(self, firstResponse: object, outputFileContent: list):
        rh = self.getRequestHandler()
        wordlist, numLines = fh.getWordlistContentAndLength()
        i = 0 # The request index
        for payload in wordlist:
            if (self.__hasProxies and i%10 == 0):
                rh.setProxyByRequestIndex(i)
            i += 1
            thisResponse = rh.request(payload)
            probablyVulnerable = False
            # If the request content has some predefined characteristics (settings.py) based on a parameter, it'll be considered as vulnerable
            if (int(thisResponse['Length']) > (int(firstResponse['Length'])+self.__additionalLength) or thisResponse['Time'] > firstResponse['Time']+self.__additionalTime):
                probablyVulnerable = True
                outputFileContent.append({
                    'Request': str(i),
                    'Payload': payload,
                    'Status code': thisResponse['Status'],
                    'Response Length': str(thisResponse['Length']),
                    'Response Time': str(thisResponse['Time'])+' seconds',
                })
            if (self.getVerboseMode()):
                oh.printContent([i, oh.fixLineToOutput(payload), thisResponse['Status'], thisResponse['Length'], thisResponse['Time']], probablyVulnerable)
            else:
                oh.progressStatus(str(int((i/numLines)*100)))
            time.sleep(self.getDelay())