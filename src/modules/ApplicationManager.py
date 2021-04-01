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

from .parsers.CLIParser import CLIParser
from .parsers.RequestParser import getTargetUrl, getHost
from .core.Fuzzer import Fuzzer
from .core.dictionaries.Payloader import Payloader
from .core.scanners.Matcher import Matcher
from .conn.Request import Request
from .conn.Response import Response
from .IO.OutputHandler import outputHandler as oh
from .IO.FileHandler import fileHandler as fh
from .exceptions.MainExceptions import SkipTargetException
from .exceptions.RequestExceptions import InvalidHostname, RequestException

import time

APP_VERSION = {
    'MAJOR_VERSION': 3,
    "MINOR_VERSION": 8,
    "PATCH": 1
}

def version():
    global APP_VERSION
    version = (str(APP_VERSION['MAJOR_VERSION'])+"."+
               str(APP_VERSION['MINOR_VERSION'])+"."+
               str(APP_VERSION['PATCH']))
    return version

def banner():
    banner = ("\033[36m   ____                        _____       _"+'\n'+
              "\033[36m  |  __|_ _ ___ ___ _ ___ ___ |_   _|_ ___| |"+"\033[0m Version "+version()+'\n'+
              "\033[36m  |  __| | |- _|- _|'|   | . |  | | . | . | |"+'\n'+
              "\033[36m  |_|  |___|___|___|_|_|_|_  |  |_|___|___|_|"+'\n'+
              "\033[36m                         |___|\033[0m\n\n"+
              "  [!] Disclaimer: We're not responsible for the misuse of this tool.\n"+
              "      This project was created for educational purposes\n"+
              "      and should not be used in environments without legal authorization.\n")
    return banner

class ApplicationManager:
    """Class that handle with the entire application

    Attributes:
        requesters: The requesters list
        startedTime: The time when start the fuzzing test
        allResults: The results dictionary for each host
        payloader: The payloader object to handle with the payload options
    """
    def __init__(self):
        """Class constructor"""
        self.requesters = []
        self.startedTime = 0
        self.allResults = {}
        self.dict = Payloader()

    def isVerboseMode(self):
        """The verboseMode getter

        @returns bool: The verbose mode flag
        """
        return self.verbose[0]

    def main(self, argv: list):
        """The main function

        @type argv: list
        @param argv: The arguments given in the execution
        """
        if len(argv) < 2:
            oh.print(banner())
            oh.errorBox("Invalid format! Use -h on 2nd parameter to show the help menu.")
        if argv[1] == '-h' or argv[1] == '--help':
            oh.showHelpMenu()
        if argv[1] == '-v' or argv[1] == '--version':
            exit(f"FuzzingTool v{version()}")
        oh.print(banner())
        self.init(argv)
        self.checkConnectionAndRedirections()
        self.start()

    def init(self, argv: list):
        """The initialization function

        @type argv: list
        @param argv: The arguments given in the execution
        """
        cliParser = CLIParser(argv)
        self.dict = cliParser.getDictionary()
        self.dictSizeof = len(self.dict)
        cookie = cliParser.checkCookie()
        proxy = cliParser.checkProxy()
        proxies = cliParser.checkProxies()
        timeout = cliParser.checkTimeout()
        followRedirects = cliParser.checkUnfollowRedirects()
        targets = cliParser.getTargets()
        for target in targets:
            oh.infoBox(f"Set target: {target['url']}")
            oh.infoBox(f"Set request method: {target['methods']}")
            if target['data']['PARAM'] or target['data']['BODY']:
                oh.infoBox(f"Set request data: {str(target['data'])}")
            requester = Request(
                url=target['url'],
                methods=target['methods'],
                data=target['data'],
                httpHeader=target['header'],
            )
            if cookie:
                requester.setHeaderContent('Cookie', cookie)
            requester.setProxy(proxy)
            requester.setProxyList(proxies)
            if timeout:
                requester.setTimeout(timeout)
            requester.setFollowRedirects(followRedirects)
            self.requesters.append(requester)
        self.delay = cliParser.checkDelay()
        self.verbose = cliParser.checkVerboseMode()
        self.numberOfThreads = cliParser.checkNumThreads()
        cliParser.checkPrefixAndSuffix(self.dict)
        cliParser.checkCase(self.dict)
        self.globalScanner = cliParser.checkGlobalScanner()
        self.matcher = cliParser.checkMatcher()
        cliParser.checkReporter()

    def start(self):
        """Starts the application"""
        self.startedTime = time.time()
        self.fuzzer = None
        try:
            for requester in self.requesters:
                self.prepareTarget(requester)
                oh.infoBox(f"Starting test on '{self.requester.getUrl()}' ...")
                try:
                    for method in self.requester.methods:
                        self.requester.resetRequestIndex()
                        self.requester.setMethod(method)
                        oh.infoBox(f"Set method for fuzzing: {method}")
                        self.prepareFuzzer()
                        self.fuzzer.start()
                        if not self.isVerboseMode():
                            oh.print("")
                except SkipTargetException as e:
                    if self.fuzzer.isRunning():
                        self.fuzzer.stop()
                    oh.abortBox(f"{str(e)}. Skipping target")
        except KeyboardInterrupt:
            if self.fuzzer and self.fuzzer.isRunning():
                self.fuzzer.stop()
            oh.abortBox("Test aborted by the user")
        finally:
            self.showFooter()
            oh.infoBox("Test completed")

    def prepareTarget(self, requester: Request):
        """Prepare the target variables for the fuzzing tests"""
        self.requester = requester
        targetHost = getHost(getTargetUrl(requester.getUrlDict()))
        self.checkIgnoreErrors(targetHost)
        self.results = []
        self.allResults[targetHost] = self.results
        if not self.globalScanner:
            self.scanner = self.getDefaultScanner()
        else:
            self.scanner = self.globalScanner
        self.scanner.update(self.matcher)
        oh.setPrintResultMode(self.scanner, self.isVerboseMode())
        if not self.requester.isUrlFuzzing() and not self.matcher.comparatorIsSet():
            self.scanner.setComparator(self.getDataComparator())

    def prepareFuzzer(self):
        """Prepare the fuzzer for the fuzzing tests"""
        self.dict.reload()
        self.fuzzer = Fuzzer(
            requester=self.requester,
            dictionary=self.dict,
            scanner=self.scanner,
            delay=self.delay,
            numberOfThreads=self.numberOfThreads,
            resultCallback=self.resultCallback,
            exceptionCallbacks=[self.invalidHostnameCallback, self.requestExceptionCallback],
        )

    def resultCallback(self, result: dict, validate: bool):
        """Callback function for the results output

        @type result: dict
        @param result: The FuzzingTool result
        @type validate: bool
        @param validate: A validator flag for the result, gived by the scanner
        """
        if self.verbose[0]:
            if validate:
                self.results.append(result)
            oh.printResult(result, validate)
        else:
            if validate:
                self.results.append(result)
                oh.printResult(result, validate)
            oh.progressStatus(
                f"[{result['Request']}/{self.dictSizeof}] {str(int((int(result['Request'])/self.dictSizeof)*100))}%"
            )
    
    def requestExceptionCallback(self, e: RequestException):
        """Handle with the request exceptions
        
        @type e: RequestException
        @param e: The request exception
        """
        if self.ignoreErrors:
            if not self.verbose[0]:
                oh.progressStatus(
                    f"[{self.requester.getRequestIndex()}/{self.dictSizeof}] {str(int((int(self.requester.getRequestIndex())/self.dictSizeof)*100))}%"
                )
            else:
                if self.verbose[1]:
                    oh.notWorkedBox(str(e))
            fh.logger.write(str(e))
        else:
            raise SkipTargetException(str(e))

    def invalidHostnameCallback(self, e: InvalidHostname):
        """Handle with the subdomain request exceptions
        
        @type e: InvalidHostname
        @param e: The invalid hostname exception
        """
        if self.verbose[0]:
            if self.verbose[1]:
                oh.notWorkedBox(str(e))
        else:
            oh.progressStatus(
                f"[{self.requester.getRequestIndex()}/{self.dictSizeof}] {str(int((int(self.requester.getRequestIndex())/self.dictSizeof)*100))}%"
            )

    def getDefaultScanner(self):
        """Check what's the scanners that will be used on Fuzzer"""
        if self.requester.isUrlFuzzing():
            if self.requester.isSubdomainFuzzing():
                from .core.scanners.default.SubdomainScanner import SubdomainScanner
                scanner = SubdomainScanner()
            else:
                from .core.scanners.default.PathScanner import PathScanner
                scanner = PathScanner()
        else:
            from .core.scanners.default.DataScanner import DataScanner
            scanner = DataScanner()
        return scanner

    def checkConnectionAndRedirections(self):
        """Test the connection and redirection to target"""
        # If we'll not fuzzing the url paths, so
        # test the redirections before start the fuzzing
        for requester in self.requesters:
            oh.infoBox(f"Checking {requester.getUrl()} ...")
            if requester.isUrlFuzzing():
                oh.infoBox("Test mode set for URL fuzzing")
                oh.infoBox("Testing connection ...")
                try:
                    requester.testConnection()
                except RequestException as e:
                    if oh.askYesNo('warning', f"{str(e)}. Remove this target?"):
                        self.requesters.remove(requester)
                else:
                    oh.infoBox("Connection status: OK")
            else:
                oh.infoBox("Test mode set for data fuzzing")
                oh.infoBox("Testing connection ...")
                try:
                    requester.testConnection()
                except RequestException as e:
                    if len(self.requesters) == 1:
                        oh.errorBox(f"{str(e)}.")
                    else:
                        oh.warningBox(f"{str(e)}. Target removed from list.")
                        self.requesters.remove(requester)
                oh.infoBox("Connection status: OK")
                self.checkRedirections(requester)
        if len(self.requesters) == 0:
            oh.errorBox("No targets left for fuzzing!")

    def checkRedirections(self, requester: Request):
        """Check the redirections for a target"""
        oh.infoBox("Testing redirections ...")
        for method in requester.methods:
            oh.infoBox(f"Testing with {method} method")
            requester.setMethod(method)
            try:
                if requester.hasRedirection():
                    if oh.askYesNo('warning', "You was redirected to another page. Remove this method?"):
                        requester.methods.remove(method)
                        oh.infoBox(f"Method {method} removed from list")
                else:
                    oh.infoBox("No redirections")
            except RequestException as e:
                oh.warningBox(f"{str(e)}. Removing method {method}")
        if len(requester.methods) == 0:
            self.requesters.remove(requester)
            oh.warningBox("No methods left on this target, removed from targets list")

    def checkIgnoreErrors(self, host: str):
        """Check if the user wants to ignore the errors during the tests
        
        @type host: str
        @param host: The target hostname
        """
        fh.logger.close()
        if self.requester.isUrlFuzzing():
            self.ignoreErrors = True
            fh.logger.open(host)
        else:
            if oh.askYesNo('info', "Do you want to ignore errors during the tests, and save them into a log file?"):
                self.ignoreErrors = True
                fh.logger.open(host)
            else:
                self.ignoreErrors = False

    def getDataComparator(self):
        """Check if the user wants to insert custom data comparator to validate the responses"""
        comparator = {
            'Length': None,
            'Time': None,
        }
        payload = ' '
        oh.infoBox(f"Making first request with '{payload}' as payload ...")
        try:
            response = self.requester.request(payload)
        except RequestException as e:
            raise SkipTargetException(f"{str(e)}")
        firstResult = self.scanner.getResult(
            response=response
        )
        oh.printResult(firstResult, False)
        defaultLength = int(firstResult['Length'])+300
        if oh.askYesNo('info', "Do you want to exclude responses based on custom length?"):
            length = oh.askData(f"Insert the length (default {defaultLength})")
            if not length:
                length = defaultLength
            comparator['Length'] = int(length)
        defaultTime = firstResult['Time Taken']+5.0
        if oh.askYesNo('info', "Do you want to exclude responses based on custom time?"):
            time = oh.askData(f"Insert the time (in seconds, default {defaultTime} seconds)")
            if not time:
                time = defaultTime
            comparator['Time'] = float(time)
        return comparator

    def showFooter(self):
        """Show the footer content of the software, after maked the fuzzing"""
        if self.startedTime:
            oh.infoBox(f"Time taken: {float('%.2f'%(time.time() - self.startedTime))} seconds")
        for key, value in self.allResults.items():
            if value:
                oh.infoBox(f"Found {len(value)} possible payload(s) on target {key}:")
                if self.isVerboseMode():
                    for result in value:
                        oh.printResult(result, True)
                fh.reporter.open(key)
                fh.reporter.write(value)
            else:
                oh.infoBox(f"No vulnerable entries was found on target {key}")