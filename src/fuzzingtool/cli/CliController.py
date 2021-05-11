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

from .CliParser import CliParser
from .CliOutput import cliOutput as co
from .. import version
from ..utils.utils import getCustomPackageNames
from ..utils.FileHandler import fileHandler as fh
from ..core.Fuzzer import Fuzzer
from ..core.dictionaries.Payloader import Payloader
from ..core.scanners.Matcher import Matcher
from ..conn import *
from ..factories.HttpFactory import HttpFactory
from ..factories.PluginFactory import PluginFactory
from ..exceptions.MainExceptions import SkipTargetException
from ..exceptions.RequestExceptions import InvalidHostname, RequestException

import time
import threading
from sys import argv

def banner():
    banner = ("\033[36m   ____                        _____       _\n"+
              "\033[36m  |  __|_ _ ___ ___ _ ___ ___ |_   _|_ ___| |"+f"\033[0m Version {version()}\n"+
              "\033[36m  |  __| | |- _|- _|'|   | . |  | | . | . | |\n"+
              "\033[36m  |_|  |___|___|___|_|_|_|_  |  |_|___|___|_|\n"+
              "\033[36m                         |___|\033[0m\n\n"+
              "  [!] Disclaimer: We're not responsible for the misuse of this tool.\n"+
              "      This project was created for educational purposes\n"+
              "      and should not be used in environments without legal authorization.\n")
    return banner

class CliController:
    """Class that handle with the entire application

    Attributes:
        requesters: The requesters list
        startedTime: The time when start the fuzzing test
        allResults: The results dictionary for each host
        lock: A thread locker to prevent overwrites on logfiles
    """
    def __init__(self):
        self.requesters = []
        self.startedTime = 0
        self.allResults = {}
        self.lock = threading.Lock()

    def isVerboseMode(self):
        """The verboseMode getter

        @returns bool: The verbose mode flag
        """
        return self.verbose[0]

    def main(self):
        """The main function.
           Prepares the application environment and starts the fuzzing
        """
        if len(argv) < 2:
            co.print(banner())
            co.errorBox("Invalid format! Use -h on 2nd parameter to show the help menu.")
        if '-h' in argv[1] or '--help' in argv[1]:
            if '=' in argv[1]:
                askedHelp = argv[1].split('=')[1]
                if 'dictionaries' in askedHelp:
                    showDictionariesHelp()
                elif 'encoders' in askedHelp:
                    showEncodersHelp()
                elif 'scanners' in askedHelp:
                    showScannersHelp()
                else:
                    co.errorBox("Invalid help argument")
            else:
                showHelpMenu()
            exit(0)
        if argv[1] == '-v' or argv[1] == '--version':
            exit(f"FuzzingTool v{version()}")
        co.print(banner())
        try:
            self.init(argv)
            self.checkConnectionAndRedirections()
        except KeyboardInterrupt:
            co.abortBox("Test aborted by the user")
            exit(0)
        self.start()

    def init(self, argv: list):
        """The initialization function.
           Set the application variables including plugins requires

        @type argv: list
        @param argv: The arguments given in the execution
        """
        cliParser = CliParser(argv)
        targets = cliParser.getTargets()
        self.globalScanner = cliParser.checkGlobalScanner()
        self.matcher = cliParser.checkMatcher()
        self.verbose = cliParser.checkVerboseMode()
        co.setVerbosityOutput(self.isVerboseMode())
        self.blacklistedStatus, action = cliParser.checkBlacklistedStatus()
        self.blacklistAction = lambda status : None
        if self.blacklistedStatus:
            self.blacklistAction = self.getBlacklistedStatusAction(action)
        self.delay = cliParser.checkDelay()
        self.numberOfThreads = cliParser.checkNumThreads()
        cliParser.checkReporter()
        if self.globalScanner:
            self.globalScanner.update(self.matcher)
            self.scanner = self.globalScanner
            co.setMessageCallback(self.scanner.cliCallback)
        cookie = cliParser.checkCookie()
        proxy = cliParser.checkProxy()
        proxies = cliParser.checkProxies()
        timeout = cliParser.checkTimeout()
        followRedirects = cliParser.checkFollowRedirects()
        for target in targets:
            co.infoBox(f"Set target URL: {target['url']}")
            co.infoBox(f"Set request method: {target['methods']}")
            if target['data']:
                co.infoBox(f"Set request data: {target['data']}")
            if checkForSubdomainFuzz(target['url']):
                requestType = 'SubdomainRequest'
            else:
                requestType = 'Request'
            requester = HttpFactory.requestCreator(
                requestType,
                url=target['url'],
                methods=target['methods'],
                data=target['data'],
                headers=target['header'],
                followRedirects=followRedirects,
                proxy=proxy,
                proxies=proxies,
                timeout=timeout,
                cookie=cookie,
            )
            self.requesters.append(requester)
        self.dict = cliParser.getDictionary()
        cliParser.checkPrefixAndSuffix(self.dict)
        self.dictSizeof = len(self.dict)
        if self.dictSizeof < self.numberOfThreads:
            self.numberOfThreads = self.dictSizeof
        cliParser.checkCase(self.dict)
        cliParser.checkEncoder(self.dict)

    def getBlacklistedStatusAction(self, action: str):
        """Get the action callback if a blacklisted status code is set

        @returns Callable: A callback function for the blacklisted status code
        """
        def skipTarget(status: int):
            """The skip target callback for the blacklistAction

            @type status: int
            @param status: The identified status code into the blacklist
            """
            self.skipTarget = f"Status code {str(status)} detected"
        
        def wait(status: int):
            """The wait (pause) callback for the blacklistAction

            @type status: int
            @param status: The identified status code into the blacklist
            """
            if not self.fuzzer.isPaused():
                if not self.isVerboseMode():
                    co.print("")
                co.warningBox(f"Status code {str(status)} detected. Pausing threads ...")
                self.fuzzer.pause()
                if not self.isVerboseMode():
                    co.print("")
                co.infoBox(f"Waiting for {self.waitingTime} seconds ...")
                time.sleep(self.waitingTime)
                co.infoBox("Resuming target ...")
                self.fuzzer.resume()

        if 'skip' in action:
            return skipTarget
        if 'wait' in action:
            try:
                action, timeToWait = action.split('=')
            except:
                co.errorBox("Must set a time to wait")
            try:
                self.waitingTime = float(timeToWait)
            except:
                co.errorBox("Time to wait must be a number")
            return wait
        else:
            co.errorBox("Invalid type of blacklist action")

    def checkConnectionAndRedirections(self):
        """Test the connection and redirection to target.
           If data fuzzing is detected, check for redirections
        """
        for requester in self.requesters:
            co.infoBox(f"Checking connection and redirections on {requester.getUrl()} ...")
            if requester.isUrlFuzzing():
                co.infoBox("Test mode set for URL fuzzing")
                co.infoBox("Testing connection ...")
                try:
                    requester.testConnection()
                except RequestException as e:
                    if co.askYesNo('warning', f"{str(e)}. Remove this target?"):
                        self.requesters.remove(requester)
                    if len(self.requesters) == 0:
                        co.errorBox("No targets left for fuzzing")
                else:
                    co.infoBox("Connection status: OK")
            else:
                co.infoBox("Test mode set for data fuzzing")
                co.infoBox("Testing connection ...")
                try:
                    requester.testConnection()
                except RequestException as e:
                    if "connected" in str(e).lower():
                        if co.askYesNo('warning', f"{str(e)}. Remove this target?"):
                            self.requesters.remove(requester)
                    else:
                        co.warningBox(f"{str(e)}. Target removed from list.")
                        self.requesters.remove(requester)
                    if len(self.requesters) == 0:
                        co.errorBox("No targets left for fuzzing")
                co.infoBox("Connection status: OK")
                if requester.isDataFuzzing():
                    self.checkRedirections(requester)

    def checkRedirections(self, requester: Request):
        """Check the redirections for a target.
           Perform a redirection check for each method in requester methods list
        
        @type requester: Request
        @param requester: The requester for the target
        """
        co.infoBox("Testing redirections ...")
        for method in requester.methods:
            requester.setMethod(method)
            co.infoBox(f"Testing with {method} method ...")
            try:
                if requester.hasRedirection():
                    if co.askYesNo('warning', "You was redirected to another page. Remove this method?"):
                        requester.methods.remove(method)
                        co.infoBox(f"Method {method} removed from list")
                else:
                    co.infoBox("No redirections")
            except RequestException as e:
                co.warningBox(f"{str(e)}. Removing method {method}")
        if len(requester.methods) == 0:
            self.requesters.remove(requester)
            co.warningBox("No methods left on this target, removed from targets list")

    def start(self):
        """Starts the fuzzing application.
           Each target is fuzzed based on their own methods list
        """
        self.startedTime = time.time()
        self.fuzzer = None
        try:
            for requester in self.requesters:
                try:
                    self.prepareTarget(requester)
                    co.infoBox(f"Starting test on '{self.requester.getUrl()}' ...")
                    for method in self.requester.methods:
                        self.requester.resetRequestIndex()
                        self.requester.setMethod(method)
                        co.infoBox(f"Set method for fuzzing: {method}")
                        self.prepareFuzzer()
                        if not self.isVerboseMode():
                            co.print("")
                except SkipTargetException as e:
                    if self.fuzzer and self.fuzzer.isRunning():
                        if not self.isVerboseMode():
                            co.print("")
                        co.warningBox("Skip target detected, stopping threads ...")
                        self.fuzzer.stop()
                    co.abortBox(f"{str(e)}. Target skipped")
        except KeyboardInterrupt:
            if self.fuzzer and self.fuzzer.isRunning():
                co.abortBox("Test aborted, stopping threads ...")
                self.fuzzer.stop()
            co.abortBox("Test aborted by the user")
        finally:
            self.showFooter()
            co.infoBox("Test completed")

    def prepareTarget(self, requester: Request):
        """Prepare the target variables for the fuzzing tests.
           Both error logger and default scanners are seted
        
        @type requester: Request
        @param requester: The requester for the target
        """
        self.requester = requester
        targetHost = getHost(getPureUrl(requester.getUrlDict()))
        co.infoBox(f"Preparing target {targetHost} ...")
        before = time.time()
        self.checkIgnoreErrors(targetHost)
        self.startedTime += (time.time() - before)
        self.results = []
        self.allResults[targetHost] = self.results
        self.skipTarget = None
        if not self.globalScanner:
            self.scanner = self.getDefaultScanner()
            self.scanner.update(self.matcher)
            co.setMessageCallback(self.scanner.cliCallback)
            if (self.requester.isDataFuzzing() and
                not self.matcher.comparatorIsSet()):
                co.infoBox("DataFuzzing detected, checking for a data comparator ...")
                before = time.time()
                self.scanner.setComparator(self.getDataComparator())
                self.startedTime += (time.time() - before)

    def prepareFuzzer(self):
        """Prepare the fuzzer for the fuzzing tests.
           Refill the dictionary with the wordlist content
        """
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
        self.fuzzer.start()
        while self.fuzzer.join():
            if self.skipTarget:
                raise SkipTargetException(self.skipTarget)

    def resultCallback(self, result: dict, validate: bool):
        """Callback function for the results output

        @type result: dict
        @param result: The FuzzingTool result
        @type validate: bool
        @param validate: A validator flag for the result, gived by the scanner
        """
        if self.blacklistedStatus and result['Status'] in self.blacklistedStatus:
            self.blacklistAction(result['Status'])
        else:
            if self.verbose[0]:
                if validate:
                    self.results.append(result)
                co.printResult(result, validate)
            else:
                if validate:
                    self.results.append(result)
                    co.printResult(result, validate)
                co.progressStatus(
                    f"[{result['Request']}/{self.dictSizeof}] {str(int((int(result['Request'])/self.dictSizeof)*100))}%"
                )
    
    def requestExceptionCallback(self, e: RequestException):
        """Callback that handle with the request exceptions
        
        @type e: RequestException
        @param e: The request exception
        """
        if self.ignoreErrors:
            if not self.verbose[0]:
                co.progressStatus(
                    f"[{self.requester.getRequestIndex()}/{self.dictSizeof}] {str(int((int(self.requester.getRequestIndex())/self.dictSizeof)*100))}%"
                )
            else:
                if self.verbose[1]:
                    co.notWorkedBox(str(e))
            with self.lock:
                fh.logger.write(str(e))
        else:
            self.skipTarget = str(e)

    def invalidHostnameCallback(self, e: InvalidHostname):
        """Callback that handle with the subdomain hostname resolver exceptions
        
        @type e: InvalidHostname
        @param e: The invalid hostname exception
        """
        if self.verbose[0]:
            if self.verbose[1]:
                co.notWorkedBox(str(e))
        else:
            co.progressStatus(
                f"[{self.requester.getRequestIndex()}/{self.dictSizeof}] {str(int((int(self.requester.getRequestIndex())/self.dictSizeof)*100))}%"
            )

    def getDefaultScanner(self):
        """Check what's the scanners that will be used
        
        @returns BaseScanner: The scanner used in the fuzzing tests
        """
        if self.requester.isUrlFuzzing():
            if "SubdomainRequest" in str(type(self.requester)):
                from ..core.scanners.default.SubdomainScanner import SubdomainScanner
                scanner = SubdomainScanner()
            else:
                from ..core.scanners.default.PathScanner import PathScanner
                scanner = PathScanner()
        else:
            from ..core.scanners.default.DataScanner import DataScanner
            scanner = DataScanner()
        return scanner

    def checkIgnoreErrors(self, host: str):
        """Check if the user wants to ignore the errors during the tests.
           By default, URL fuzzing (path and subdomain) ignore errors
        
        @type host: str
        @param host: The target hostname
        """
        fh.logger.close()
        if self.requester.isUrlFuzzing():
            self.ignoreErrors = True
            logPath = fh.logger.open(host)
            co.infoBox(f'The logs will be saved on \'{logPath}\'')
        else:
            if co.askYesNo('info', "Do you want to ignore errors on this target, and save them into a log file?"):
                self.ignoreErrors = True
                logPath = fh.logger.open(host)
                co.infoBox(f'The logs will be saved on \'{logPath}\'')
            else:
                self.ignoreErrors = False

    def getDataComparator(self):
        """Check if the user wants to insert custom data comparator to validate the responses
        
        @returns dict: The data comparator dictionary
        """
        comparator = {
            'Length': None,
            'Time': None,
        }
        payload = ' ' # Set an arbitraty payload
        co.infoBox(f"Making first request with '{payload}' as payload ...")
        try:
            # Make the first request to get some info about the target
            response = self.requester.request(payload)
        except RequestException as e:
            raise SkipTargetException(f"{str(e)}")
        firstResult = self.scanner.getResult(
            response=response
        )
        co.printResult(firstResult, False)
        defaultLength = int(firstResult['Length'])+300
        if co.askYesNo('info', "Do you want to exclude responses based on custom length?"):
            length = co.askData(f"Insert the length (default {defaultLength})")
            if not length:
                length = defaultLength
            comparator['Length'] = int(length)
        defaultTime = firstResult['Time Taken']+5.0
        if co.askYesNo('info', "Do you want to exclude responses based on custom time?"):
            time = co.askData(f"Insert the time (in seconds, default {defaultTime} seconds)")
            if not time:
                time = defaultTime
            comparator['Time'] = float(time)
        return comparator

    def showFooter(self):
        """Show the footer content of the software, after maked the fuzzing.
           The results are shown for each target
        """
        if self.fuzzer:
            if self.startedTime:
                co.infoBox(f"Time taken: {float('%.2f'%(time.time() - self.startedTime))} seconds")
            for key, value in self.allResults.items():
                if value:
                    if self.isVerboseMode():
                        co.infoBox(f"Found {len(value)} matched results on target {key}:")
                        for result in value:
                            co.printResult(result, True)
                    reportPath = fh.reporter.open(key)
                    co.infoBox(f'Saving results for {key} on \'{reportPath}\' ...')
                    fh.reporter.write(value)
                    co.infoBox('Results saved')
                else:
                    co.infoBox(f"No matched results was found on target {key}")

def showHelpMenu():
    co.helpTitle(0, "Parameters:")
    co.helpTitle(3, "Misc:")
    co.helpContent(5, "-h, --help", "Show the help menu and exit")
    co.helpContent(5, "-v, --version", "Show the current version and exit")
    co.helpTitle(3, "Request options:")
    co.helpContent(5, "-r FILE", "Define the file with the raw HTTP request (scheme not specified)")
    co.helpContent(5, "--scheme SCHEME", "Define the scheme used in the URL (default http)")
    co.helpContent(5, "-u URL", "Define the target URL")
    co.helpContent(5, "-X METHOD", "Define the request http verbs (method)")
    co.helpContent(5, "-d DATA", "Define the request body data")
    co.helpContent(5, "--proxy IP:PORT", "Define the proxy")
    co.helpContent(5, "--proxies FILE", "Define the file with a list of proxies")
    co.helpContent(5, "--cookie COOKIE", "Define the HTTP Cookie header value")
    co.helpContent(5, "--timeout TIMEOUT", "Define the request timeout (in seconds)")
    co.helpContent(5, "--unfollow-redirects", "Stop to follow redirects")
    co.helpTitle(3, "Payload options:")
    co.helpContent(5, "-w WORDLIST", "Define the wordlist dictionary (--help=dictionaries for more info)")
    co.helpContent(5, "-e ENCODER", "Define the encoder used on payloads (--help=encoders for more info)")
    co.helpContent(5, "--prefix PREFIX", "Define the prefix(es) used with the payload")
    co.helpContent(5, "--suffix SUFFIX", "Define the suffix(es) used with the payload")
    co.helpContent(5, "--upper", "Set the uppercase case for the payloads")
    co.helpContent(5, "--lower", "Set the lowercase case for the payloads")
    co.helpContent(5, "--capitalize", "Set the capitalize case for the payloads")
    co.helpTitle(3, "Match options:")
    co.helpContent(5, "-Mc STATUS", "Match responses based on their status codes")
    co.helpContent(5, "-Ms SIZE", "Match responses based on their length (in bytes)")
    co.helpContent(5, "-Mt TIME", "Match responses based on their elapsed time (in seconds)")
    co.helpContent(5, "--scanner SCANNER", "Define the custom scanner (--help=scanners for more info)")
    co.helpTitle(3, "More options:")
    co.helpContent(5, "(-V, -V1) | -V2", "Enable the verbose mode (common or full verbose)")
    co.helpContent(5, "--delay DELAY", "Define the delay between each request (in seconds)")
    co.helpContent(5, "-t NUMBEROFTHREADS", "Define the number of threads used in the tests")
    co.helpContent(5, "-o REPORT", "Define the report format (accept txt, csv and json)")
    co.helpContent(5, "--blacklist-status STATUS:ACTION", "Blacklist status codes from response, and take an action when one is detected. Available actions: skip (to skip the current target), wait=SECONDS (to pause the app for some seconds)")
    co.helpTitle(0, "Examples:\n")
    co.print("FuzzingTool -u http://127.0.0.1/post.php?id= -w /path/to/wordlist/sqli.txt -Mt 20 -Mc 500-600 -t 30 -o fuzzingGet.csv\n")
    co.print("FuzzingTool -w /path/to/wordlist/sqli.txt -u http://127.0.0.1/controller/user.php -d 'login&passw&user=login' -Ms 1200\n")
    co.print("FuzzingTool -w /path/to/wordlist/paths.txt -u http://127.0.0.1/$ -u http://192.168.0.133/$ --suffix .php,.html --unfollow-redirects -Mc 200,302,303\n")
    co.print("FuzzingTool -w /path/to/wordlist/subdomains.txt -u https://$.domainexample.com/ -t 100 -Ms 1500 --timeout 5\n")
    co.print("FuzzingTool -r /path/to/raw-http1.txt -r /path/to/raw-http2.txt --scheme https -w /path/to/wordlist/sqli.txt -V -o json\n")

def showCustomPackageHelp(packageName: str):
    """Show the custom package help

    @type packageName: str
    @param packageName: The package to search for the custom content
    """
    for customPackage in getCustomPackageNames(packageName):
        Package = PluginFactory.classCreator(customPackage, packageName)
        if not Package.__type__:
            typeFuzzing = ''
        else:
            typeFuzzing = f" (Used for {Package.__type__})"
        if not Package.__params__:
            params = ''
        else:
            params = f"={Package.__params__}"
        co.helpContent(5, f"{Package.__name__}{params}", f"{Package.__desc__}{typeFuzzing}\n")

def showDictionariesHelp():
    co.helpTitle(0, "Dictionary options: (-w)")
    co.helpTitle(2, "Default: The default dictionaries are selected by default when no custom are choiced\n")
    co.helpContent(5, "FILEPATH", "Set the path of the wordlist file")
    co.helpContent(5, "[PAYLOAD1,PAYLOAD2,]", "Set the payloads list to be used as wordlist")
    co.helpTitle(2, "Custom (Dictionary=PARAM): Set the custom dictionary and his parameter\n")
    showCustomPackageHelp('dictionaries')
    co.helpTitle(0, "Examples:\n")
    co.print("FuzzingTool -u https://$.domainexample.com/ -w /path/to/wordlist/subdomains.txt -t 30 --timeout 5 -V2\n")
    co.print("FuzzingTool -u https://$.domainexample.com/ -w [wp-admin,admin,webmail,www,cpanel] -t 30 --timeout 5 -V2\n")
    co.print("FuzzingTool -u https://$.domainexample.com/ -w CrtDictionary=domainexample.com -t 30 --timeout 5 -V2\n")
    co.print("FuzzingTool -u https://domainexample.com/$ -w OverflowDictionary=5000,:../:etc/passwd -t 30 --timeout 5 -V2\n")

def showEncodersHelp():
    co.helpTitle(0, "Encoder options: (-e)")
    co.helpTitle(2, "Set the encoder used on the payloads\n")
    showCustomPackageHelp('encoders')
    co.helpTitle(0, "Examples:\n")
    co.print("FuzzingTool -u https://domainexample.com/page.php?id= -w /path/to/wordlist/sqli.txt -e UrlEncoder=2 -t 30 --scanner GrepScanner=SQL\n")

def showScannersHelp():
    co.helpTitle(0, "Scanner options:")
    co.helpTitle(2, "Default: The default scanners are selected automatically during the tests, if a custom scanner wasn't gived\n")
    co.helpContent(5, "DataScanner", "Scanner for the data fuzzing")
    co.helpContent(5, "PathScanner", "Scanner for the path URL fuzzing")
    co.helpContent(5, "SubdomainScanner", "Scanner for the subdomain URL fuzzing")
    co.helpTitle(2, "Custom (--scaner SCANNER): Set the custom scanner\n")
    showCustomPackageHelp('scanners')
    co.helpTitle(0, "Examples:\n")
    co.print("FuzzingTool -u https://domainexample.com/search.php?query= -w /path/to/wordlist/xss.txt --scanner ReflectedScanner -t 30 -o csv\n")