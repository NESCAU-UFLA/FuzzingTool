from ..core.Fuzzer import Fuzzer
from ..conn.Request import Request
from ..IO.OutputHandler import outputHandler as oh
from ..IO.FileHandler import fileHandler as fh
from collections import deque

class CLIParser:
    def __init__(self, argv: list):
        self.__argv = argv

    def getUrl(self):
        """Get the target URL

        @returns str: The target URL
        """
        try:
            return self.__argv[self.__argv.index('-u')+1]
        except ValueError:
            oh.errorBox("An URL is needed to make the fuzzing.")

    def getDefaultRequestData(self):
        '''Get the default data of the requests

        @returns tuple(str, str, dict, dict): The default data of the requests
        '''
        if '-r' in self.__argv:
            headerList = deque(fh.readData(self.__argv[self.__argv.index('-r')+1]))
            method, path, httpVer = headerList.popleft().split(' ')
            httpHeader = self.__getHeader(headerList)
            param = ''
            if method == 'GET' and '?' in path:
                path, param = path.split('?', 1)
            url = 'http://'+httpHeader['Host']+path
            if method == 'POST' and len(headerList) > 0:
                param = headerList.popleft()
        else:
            url, method, param = self.__getMethodAndArgs(self.getUrl())
            httpHeader = {}
        requestData = self.__getRequestParams(param) if param != '' else {}
        return (url, method, requestData, httpHeader)

    def getWordlistFile(self):
        """Get the fuzzing wordlist filename from -f argument
        if the argument -f doesn't exists, or the file couldn't be open, an error is thrown and the application exits
        """
        try:
            wordlistFileName = self.__argv[self.__argv.index('-f')+1]
            fh.openWordlist(wordlistFileName)
        except ValueError:
            oh.errorBox("An file is needed to make the fuzzing")

    def checkCookie(self, requestHandler: Request):
        """Check if the --cookie argument is present, and set the value into the requestHandler

        @type requestHandler: Request
        @param requestHandler: The object responsible to handle the requests
        """
        if ('--cookie' in self.__argv):
            cookie = self.__argv[self.__argv.index('--cookie')+1]
            requestHandler.setHeaderContent('Cookie', cookie)
            oh.infoBox(f"Set cookie: {cookie}")

    def checkProxy(self, requestHandler: Request):
        """Check if the --proxy argument is present, and set the value into the requestHandler

        @type requestHandler: Request
        @param requestHandler: The object responsible to handle the requests
        """
        if ('--proxy' in self.__argv):
            proxy = self.__argv[self.__argv.index('--proxy')+1]
            requestHandler.setProxy({
                'http://': 'http://'+proxy,
                'https://': 'http://'+proxy
            })
            oh.infoBox(f"Set proxy: {proxy}")

    def checkProxies(self, requestHandler: Request):
        """Check if the --proxies argument is present, and open a file
        
        @type requestHandler: Request
        @param requestHandler: The object responsible to handle the requests
        """
        if ('--proxies' in self.__argv):
            proxiesFileName = self.__argv[self.__argv.index('--proxies')+1]
            fh.openProxies(proxiesFileName)
            oh.infoBox(f"Loading proxies from file '{proxiesFileName}' ...")
            requestHandler.setProxiesFromFile()

    def checkDelay(self, fuzzer: Fuzzer):
        """Check if the --delay argument is present, and set the value into the fuzzer

        @type fuzzer: Fuzzer
        @param fuzzer: The Fuzzer object
        """
        if ('--delay' in self.__argv):
            delay = self.__argv[self.__argv.index('--delay')+1]
            fuzzer.setDelay(float(delay))
            oh.infoBox(f"Set delay: {delay} second(s)")

    def checkVerboseMode(self, fuzzer: Fuzzer):
        """Check if the -V or --verbose argument is present, and set the verbose mode

        @type fuzzer: Fuzzer
        @param fuzzer: The Fuzzer object
        """
        if ('-V' in self.__argv or '--verbose' in self.__argv):
            fuzzer.setVerboseMode(True)

    def checkNumThreads(self, fuzzer: Fuzzer):
        """Check if the -t argument is present, and set the number of threads in the fuzzer

        @type fuzzer: Fuzzer
        @param fuzzer: The Fuzzer object
        """
        if ('-t' in self.__argv):
            numThreads = self.__argv[self.__argv.index('-t')+1]
            fuzzer.setNumThreads(int(numThreads))
            oh.infoBox(f"Set number of threads: {numThreads} thread(s)")

    def __getHeader(self, args: list):
        '''Get the HTTP header

        @tyoe args: list
        @param args: the list with HTTP header
        @returns dict: the HTTP header parsed into a dict
        '''
        httpHeader = {}
        i = 0
        thisArg = args.popleft()
        argsLength = len(args)
        while i < argsLength and thisArg != '':
            key, value = thisArg.split(': ', 1)
            httpHeader[key] = value
            thisArg = args.popleft()
            i += 1
        return httpHeader

    def __makeDefaultParam(self, defaultParam: dict, param: str):
        """Set the default parameter values if are given

        @type defaultParam: dict
        @param defaultParam: The entries data of the request
        @type param: str
        @param param: The parameter string of the request
        """
        if '=' in param:
            param, value = param.split('=')
            if not '$' in value:
                defaultParam[param] = value
            else:
                defaultParam[param] = ''
        else:
            defaultParam[param] = ''
    
    def __getMethodAndArgs(self, url: str):
        """Get the param method to use ('?' or '$' in URL if GET, or --data) and the request param string

        @type url: str
        @param url: The target URL
        @returns tuple(str, str, str): The tuple with the new target URL, the request method and params
        """
        param = ''
        if '?' in url or '$' in url:
            if '?' in url:
                url, param = url.split('?', 1)
            method = 'GET'
        else:
            method = 'POST'
            try:
                param = self.__argv[self.__argv.index('--data')+1]
            except ValueError:
                oh.errorBox("You must set at least GET or POST parameters for the fuzzing test.")
        return (url, method, param)
    
    def __getRequestParams(self, param: str):
        """Split all the request parameters into a list of arguments used in the request

        @type param: str
        @param param: The parameter string of the request
        @returns dict: The entries data of the request
        """
        defaultParam = {}
        if ('&' in param):
            param = param.split('&', param.count('&'))
            for arg in param:
                self.__makeDefaultParam(defaultParam, arg)
        else:
            self.__makeDefaultParam(defaultParam, param)
        return defaultParam