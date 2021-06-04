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

from .CliArguments import *
from .CliOutput import CliOutput, Colors
from ..ArgumentBuilder import ArgumentBuilder as AB
from ... import version
from ...utils.FileHandler import fileHandler as fh
from ...core import *
from ...conn import *
from ...factories import *
from ...exceptions.MainExceptions import SkipTargetException
from ...exceptions.RequestExceptions import *

from queue import Queue
import time
import threading

def banner():
    """Gets the program banner

    @returns str: The program banner
    """
    banner = (f"{Colors.BLUE_GRAY}   ____                        _____       _\n"+
              f"{Colors.BLUE_GRAY}  |  __|_ _ ___ ___ _ ___ ___ |_   _|_ ___| |{Colors.RESET} Version {version()}\n"+
              f"{Colors.BLUE_GRAY}  |  __| | |- _|- _|'|   | . |  | | . | . | |\n"+
              f"{Colors.BLUE_GRAY}  |_|  |___|___|___|_|_|_|_  |  |_|___|___|_|\n"+
              f"{Colors.BLUE_GRAY}                         |___|{Colors.RESET}\n\n"+
              f"  [!] Disclaimer: We're not responsible for the misuse of this tool.\n"+
              f"      This project was created for educational purposes\n"+
              f"      and should not be used in environments without legal authorization.\n")
    return banner

class CliController:
    """Class that handle with the entire application

    Attributes:
        requesters: The requesters list
        startedTime: The time when start the fuzzing test
        fuzzer: The fuzzer object to handle with the fuzzing test
        allResults: The results dictionary for each host
        lock: A thread locker to prevent overwrites on logfiles
        blacklistStatus: The blacklist status object
    """
    def __init__(self):
        self.requesters = []
        self.startedTime = 0
        self.fuzzer = None
        self.allResults = {}
        self.lock = threading.Lock()
        self.blacklistStatus = None

    def isVerboseMode(self):
        """The verboseMode getter

        @returns bool: The verbose mode flag
        """
        return self.verbose[0]

    def main(self, arguments: CliArguments):
        """The main function.
           Prepares the application environment and starts the fuzzing
        
        @type arguments: CliArguments
        @param arguments: The command line interface arguments object
        """
        self.co = CliOutput() # Abbreviation to cli output
        self.co.setOutputMode(arguments.simpleOutput)
        self.verbose = arguments.verbose
        self.co.setVerbosityMode(self.isVerboseMode())
        CliOutput.print(banner())
        try:
            self.co.infoBox("Setupping arguments ...")
            self.init(arguments)
            self.co.printConfigs(
                output='normal' if not arguments.simpleOutput else 'simple',
                verbose='quiet' if not self.verbose[0] else 'common' if not self.verbose[1] else 'detailed',
                targets=self.targetsList,
                dictionaries=self.dictionariesMetadata,
                prefix=arguments.prefix,
                suffix=arguments.suffix,
                case='lowercase' if arguments.lowercase else 'uppercase' if arguments.uppercase else 'capitalize' if arguments.capitalize else None,
                encoder=arguments.encoder,
                match={
                    'status': arguments.matchStatus,
                    'length': arguments.matchLength,
                    'time': arguments.matchTime,
                },
                scanner=arguments.scanner,
                blacklistStatus={
                    'status': arguments.blacklistedStatus,
                    'action': arguments.blacklistAction,
                } if arguments.blacklistedStatus else {},
                delay=self.delay,
                threads=self.numberOfThreads,
                report=arguments.report,
            )
            self.checkConnectionAndRedirections()
        except KeyboardInterrupt:
            self.co.abortBox("Test aborted by the user")
            exit(0)
        except Exception as e:
            self.co.errorBox(str(e))
        try:
            self.start()
        except KeyboardInterrupt:
            if self.fuzzer and self.fuzzer.isRunning():
                self.co.abortBox("Test aborted, stopping threads ...")
                self.fuzzer.stop()
            self.co.abortBox("Test aborted by the user")
        finally:
            self.showFooter()
            self.co.infoBox("Test completed")

    def init(self, arguments: CliArguments):
        """The initialization function.
           Set the application variables including plugins requires
        
        @type arguments: CliArguments
        @param arguments: The command line interface arguments object
        """
        self.__initRequesters(arguments)
        scanner = None
        if arguments.scanner:
            scanner, param = arguments.scanner
            try:
                scanner = PluginFactory.objectCreator(
                    scanner, 'scanners', param
                )
            except Exception as e:
                raise Exception(str(e))
        self.globalScanner = scanner
        self.__checkForDuplicatedTargets()
        matchStatus = arguments.matchStatus
        if matchStatus:
            if '200' not in matchStatus:
                if self.co.askYesNo('warning', "Status code 200 (OK) wasn't included. Do you want to include it to the allowed status codes?"):
                    matchStatus += ",200"
        self.globalMatcher = Matcher.fromString(
            matchStatus,
            arguments.matchLength,
            arguments.matchTime
        )
        if arguments.blacklistedStatus:
            blacklistedStatus = arguments.blacklistedStatus
            action = arguments.blacklistAction
            self.blacklistStatus = BlacklistStatus(
                status=blacklistedStatus,
                action=action,
                actionParam=arguments.blacklistActionParam,
                actionCallbacks={
                    'skip': self._skipCallback,
                    'wait': self._waitCallback,
                },
            )
        self.delay = arguments.delay
        self.numberOfThreads = arguments.numberOfThreads
        if self.globalScanner:
            self.localScanner = self.globalScanner
            self.co.setMessageCallback(self.localScanner.cliCallback)
        if arguments.report:
            fh.reporter.setMetadata(arguments.report)
        self.__initDictionary(arguments)

    def checkConnectionAndRedirections(self):
        """Test the connection to target.
           If data fuzzing is detected, check for redirections
        """
        for requester in self.requesters:
            self.co.infoBox(f"Validating {requester.getUrl()} ...")
            if self.isVerboseMode():
                self.co.infoBox("Testing connection ...")
            try:
                requester.testConnection()
            except RequestException as e:
                if not self.co.askYesNo('warning', f"{str(e)}. Continue anyway?"):
                    self.co.infoBox(f"Target removed from list.")
                    self.requesters.remove(requester)
            else:
                if self.isVerboseMode():
                    self.co.infoBox("Connection status: OK")
                if requester.isDataFuzzing():
                    self.checkRedirections(requester)
        if len(self.requesters) == 0:
            raise Exception("No targets left for fuzzing")

    def checkRedirections(self, requester: Request):
        """Check the redirections for a target.
           Perform a redirection check for each method in requester methods list
        
        @type requester: Request
        @param requester: The requester for the target
        """
        if self.isVerboseMode():
            self.co.infoBox("Testing redirections ...")
        for method in requester.methods:
            requester.setMethod(method)
            if self.isVerboseMode():
                self.co.infoBox(f"Testing with {method} method ...")
            try:
                if requester.hasRedirection():
                    if self.co.askYesNo('warning', "You was redirected to another page. Remove this method?"):
                        requester.methods.remove(method)
                        self.co.infoBox(f"Method {method} removed from list")
                else:
                    if self.isVerboseMode():
                        self.co.infoBox("No redirections")
            except RequestException as e:
                self.co.warningBox(f"{str(e)}. Removing method {method}")
        if len(requester.methods) == 0:
            self.requesters.remove(requester)
            self.co.warningBox("No methods left on this target, removed from targets list")

    def start(self):
        """Starts the fuzzing application.
           Each target is fuzzed based on their own methods list
        """
        self.startedTime = time.time()
        for i, requester in enumerate(self.requesters):
            try:
                self.prepareTarget(requester)
                for method in self.requester.methods:
                    self.requester.resetRequestIndex()
                    self.requester.setMethod(method)
                    self.co.infoBox(f"Starting {self.targetsList[i]['typeFuzzing']} on {self.targetHost} with method {method}")
                    self.prepareFuzzer()
                    if not self.isVerboseMode():
                        CliOutput.print("")
            except SkipTargetException as e:
                if self.fuzzer and self.fuzzer.isRunning():
                    if not self.isVerboseMode():
                        CliOutput.print("")
                    self.co.warningBox("Skip target detected, stopping threads ...")
                    self.fuzzer.stop()
                self.co.abortBox(f"{str(e)}. Target skipped")

    def prepareTarget(self, requester: Request):
        """Prepare the target variables for the fuzzing tests.
           Both error logger and default scanners are setted
        
        @type requester: Request
        @param requester: The requester for the target
        """
        self.requester = requester
        self.targetHost = getHost(getPureUrl(requester.getUrl()))
        if self.isVerboseMode():
            self.co.infoBox(f"Preparing target {self.targetHost} ...")
        before = time.time()
        self.checkIgnoreErrors(self.targetHost)
        self.startedTime += (time.time() - before)
        self.results = []
        self.allResults[self.targetHost] = self.results
        self.skipTarget = None
        self.localMatcher = Matcher(
            allowedStatus=self.globalMatcher.getAllowedStatus(),
            comparator=self.globalMatcher.getComparator()
        )
        if not self.globalScanner:
            self.localScanner = self.getDefaultScanner()
            if (self.requester.isDataFuzzing() and
                not self.globalMatcher.comparatorIsSet()):
                self.co.infoBox("DataFuzzing detected, checking for a data comparator ...")
                before = time.time()
                self.localMatcher.setComparator(
                    self.getDataComparator()
                )
                self.startedTime += (time.time() - before)
        if not self.globalDictionary:
            self.localDictionary = self.dictionaries.get()
            self.totalRequests = len(self.localDictionary)
        self.localDictionary.reload()

    def prepareFuzzer(self):
        """Prepare the fuzzer for the fuzzing tests.
           Refill the dictionary with the wordlist content if a global dictionary was given
        """
        self.fuzzer = Fuzzer(
            requester=self.requester,
            dictionary=self.localDictionary,
            matcher=self.localMatcher,
            scanner=self.localScanner,
            delay=self.delay,
            numberOfThreads=self.numberOfThreads,
            resultCallback=self._resultCallback,
            exceptionCallbacks=[self._invalidHostnameCallback, self._requestExceptionCallback],
        )
        self.fuzzer.start()
        while self.fuzzer.join():
            if self.skipTarget:
                raise SkipTargetException(self.skipTarget)

    def getDefaultScanner(self):
        """Check what's the scanners that will be used
        
        @returns BaseScanner: The scanner used in the fuzzing tests
        """
        if self.requester.isUrlDiscovery():
            if self.requester.isPathFuzzing():
                from ...core.scanners.default.PathScanner import PathScanner
                scanner = PathScanner()
            else:
                from ...core.scanners.default.SubdomainScanner import SubdomainScanner
                scanner = SubdomainScanner()
            if self.globalMatcher.allowedStatusIsDefault():
                self.localMatcher.setAllowedStatus(
                    Matcher.buildAllowedStatus("200-399,401,403")
                )
        else:
            from ...core.scanners.default.DataScanner import DataScanner
            scanner = DataScanner()
        self.co.setMessageCallback(scanner.cliCallback)
        return scanner

    def checkIgnoreErrors(self, host: str):
        """Check if the user wants to ignore the errors during the tests.
           By default, URL fuzzing (path and subdomain) ignore errors
        
        @type host: str
        @param host: The target hostname
        """
        if self.requester.isUrlFuzzing():
            self.ignoreErrors = True
            logPath = fh.logger.setup(host)
            self.co.infoBox(f'The logs will be saved on \'{logPath}\'')
        else:
            if self.co.askYesNo('info', "Do you want to ignore errors on this target, and save them into a log file?"):
                self.ignoreErrors = True
                logPath = fh.logger.setup(host)
                self.co.infoBox(f'The logs will be saved on \'{logPath}\'')
            else:
                self.ignoreErrors = False

    def getDataComparator(self):
        """Check if the user wants to insert custom data comparator to validate the responses
        
        @returns dict: The data comparator dictionary for the Matcher object
        """
        payload = ' ' # Set an arbitraty payload
        self.co.infoBox(f"Making first request with '{payload}' as payload ...")
        try:
            # Make the first request to get some info about the target
            response, RTT, *_ = self.requester.request(payload)
        except RequestException as e:
            raise SkipTargetException(f"{str(e)}")
        firstResult = Result(response, RTT)
        self.co.printResult(firstResult, False)
        length = None
        defaultLength = int(firstResult.length)+300
        if self.co.askYesNo('info', "Do you want to exclude responses based on custom length?"):
            length = self.co.askData(f"Insert the length (default {defaultLength})")
            if not length:
                length = defaultLength
            try:
                length = int(length)
            except ValueError:
                self.co.errorBox(f"The length ({length}) must be an integer")
        time = None
        defaultTime = firstResult.RTT+5.0
        if self.co.askYesNo('info', "Do you want to exclude responses based on custom time?"):
            time = self.co.askData(f"Insert the time (in seconds, default {defaultTime} seconds)")
            if not time:
                time = defaultTime
            try:
                time = float(time)
            except ValueError:
                self.co.errorBox(f"The time ({time}) must be a number")
        return Matcher.buildComparator(length, time)

    def showFooter(self):
        """Show the footer content of the software, after maked the fuzzing.
           The results are shown for each target
        """
        if self.fuzzer:
            if self.startedTime:
                self.co.infoBox(f"Time taken: {float('%.2f'%(time.time() - self.startedTime))} seconds")
            requesterIndex = 0
            for key, value in self.allResults.items():
                if value:
                    self.co.infoBox(f"Found {len(value)} matched results on target {key}")
                    if self.isVerboseMode():
                        if not self.globalScanner:
                            self.requester = self.requesters[requesterIndex]
                            self.getDefaultScanner()
                        for result in value:
                            self.co.printResult(result, True)
                    reportPath = fh.reporter.open(key)
                    self.co.infoBox(f'Saving results for {key} on \'{reportPath}\' ...')
                    fh.reporter.write(value)
                    self.co.infoBox('Results saved')
                else:
                    self.co.infoBox(f"No matched results was found on target {key}")
                requesterIndex += 1

    def _skipCallback(self, status: int):
        """The skip target callback for the blacklistAction

        @type status: int
        @param status: The identified status code into the blacklist
        """
        self.skipTarget = f"Status code {str(status)} detected"
    
    def _waitCallback(self, status: int):
        """The wait (pause) callback for the blacklistAction

        @type status: int
        @param status: The identified status code into the blacklist
        """
        if not self.fuzzer.isPaused():
            if not self.isVerboseMode():
                CliOutput.print("")
            self.co.warningBox(f"Status code {str(status)} detected. Pausing threads ...")
            self.fuzzer.pause()
            if not self.isVerboseMode():
                CliOutput.print("")
            self.co.infoBox(f"Waiting for {self.blacklistStatus.actionParam} seconds ...")
            time.sleep(self.blacklistStatus.actionParam)
            self.co.infoBox("Resuming target ...")
            self.fuzzer.resume()

    def _resultCallback(self, result: dict, validate: bool):
        """Callback function for the results output

        @type result: dict
        @param result: The FuzzingTool result
        @type validate: bool
        @param validate: A validator flag for the result, gived by the scanner
        """
        if self.blacklistStatus and result.status in self.blacklistStatus.codes:
            self.blacklistStatus.actionCallback(result.status)
        else:
            if self.verbose[0]:
                if validate:
                    self.results.append(result)
                self.co.printResult(result, validate)
            else:
                if validate:
                    self.results.append(result)
                    self.co.printResult(result, validate)
                self.co.progressStatus(
                    result.index, self.totalRequests, result.payload
                )
    
    def _requestExceptionCallback(self,
        e: RequestException,
        payload: str
    ):
        """Callback that handle with the request exceptions
        
        @type e: RequestException
        @param e: The request exception
        @type payload: str
        @param payload: The payload used in the request
        """
        if self.ignoreErrors:
            if not self.verbose[0]:
                self.co.progressStatus(
                    self.requester.index, self.totalRequests, payload
                )
            else:
                if self.verbose[1]:
                    self.co.notWorkedBox(str(e))
            with self.lock:
                fh.logger.write(str(e), payload)
        else:
            self.skipTarget = str(e)

    def _invalidHostnameCallback(self,
        e: InvalidHostname,
        payload: str
    ):
        """Callback that handle with the subdomain hostname resolver exceptions
        
        @type e: InvalidHostname
        @param e: The invalid hostname exception
        @type payload: str
        @param payload: The payload used in the request
        """
        if self.verbose[0]:
            if self.verbose[1]:
                self.co.notWorkedBox(str(e))
        else:
            self.co.progressStatus(
                self.requester.index, self.totalRequests, payload
            )

    def __initRequesters(self, arguments: CliArguments):
        """Initialize the requesters

        @type arguments: CliArguments
        @param arguments: The command line interface arguments object
        """
        self.targetsList = []
        if arguments.targetsFromUrl:
            self.targetsList.extend(AB.buildTargetsFromArgs(
                arguments.targetsFromUrl, arguments.method, arguments.data
            ))
        if arguments.targetsFromRawHttp:
            self.targetsList.extend(AB.buildTargetsFromRawHttp(
                arguments.targetsFromRawHttp, arguments.scheme
            ))
        if not self.targetsList:
            raise Exception("A target is needed to make the fuzzing")
        for target in self.targetsList:
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
                followRedirects=arguments.followRedirects,
                proxy=arguments.proxy,
                proxies=fh.read(arguments.proxies) if arguments.proxies else [],
                timeout=arguments.timeout,
                cookie=arguments.cookie,
            )
            self.requesters.append(requester)
            if requester.isMethodFuzzing():
                target['typeFuzzing'] = "MethodFuzzing"
            elif requester.isDataFuzzing():
                target['typeFuzzing'] = "DataFuzzing"
            elif requester.isUrlDiscovery():
                if requester.isPathFuzzing():
                    target['typeFuzzing'] = "PathFuzzing"
                else:
                    target['typeFuzzing'] = "SubdomainFuzzing"
            else:
                target['typeFuzzing'] = "Couldn't determine the fuzzing type"

    def __checkForDuplicatedTargets(self):
        """Checks for duplicated targets, if they'll use the same scanner (based on fuzzing type)
           Also, checks if a global scanner was already specified before make the check
        """
        if not self.globalScanner:
            targetsChecker = [{
                'host': getHost(getPureUrl(target['url'])),
                'typeFuzzing': target['typeFuzzing'],
            } for target in self.targetsList]
            if len(set([target['host'] for target in targetsChecker])) != len(self.targetsList):
                targetsChecker.sort(key=lambda e: e['host'])
                for i in range(len(targetsChecker)-1):
                    thisTarget = targetsChecker[i]
                    nextTarget = targetsChecker[i+1]
                    if (thisTarget['host'] == nextTarget['host'] and
                        thisTarget['typeFuzzing'] != nextTarget['typeFuzzing']):
                        raise Exception("Duplicated target detected with different type of fuzzing scan, exiting.")

    def __initDictionary(self, arguments: CliArguments):
        """Initialize the dictionary

        @type arguments: CliArguments
        @param arguments: The command line interface arguments object
        """
        def buildDictionary(
            wordlists: list,
            requester: Request = None,
            encoder: object = None,
        ):
            """Build the dictionary

            @type wordlists: list
            @param wordlists: The wordlists used in the dictionary
            @type requester: Request
            @param requester: The requester for the given dictionary
            @returns Dictionary: The dictionary object
            """
            lastDictIndex = len(self.dictionariesMetadata)
            self.dictionariesMetadata.append({
                'wordlists': [],
                'sizeof': 0
            })
            buildedWordlist = []
            for wordlist in wordlists:
                name, params = wordlist
                self.dictionariesMetadata[lastDictIndex]['wordlists'].append(
                    f"{name}={params}" if params else name
                )
                try:
                    buildedWordlist.extend(WordlistFactory.creator(name, params, requester))
                except Exception as e:
                    self.co.warningBox(str(e))
            if not buildedWordlist:
                raise Exception("The wordlist is empty")
            dictionary = Dictionary(buildedWordlist)
            self.dictionariesMetadata[lastDictIndex]['sizeof'] = len(buildedWordlist)
            dictionary.setPrefix(arguments.prefix)
            dictionary.setSuffix(arguments.suffix)
            if arguments.lowercase:
                dictionary.setLowercase()
            elif arguments.uppercase:
                dictionary.setUppercase()
            elif arguments.capitalize:
                dictionary.setCapitalize()
            if encoder:
                dictionary.setEncoder(encoder)
            return dictionary
        
        encoder = None
        if arguments.encoder:
            encoder, param = arguments.encoder
            try:
                encoder = PluginFactory.objectCreator(
                    encoder, 'encoders', param
                )
            except Exception as e:
                raise Exception(str(e))
        self.globalDictionary = None
        self.dictionaries = []
        self.dictionariesMetadata = []
        lenWordlists = len(arguments.wordlists)
        lenRequesters = len(self.requesters)
        if lenWordlists > lenRequesters:
            raise Exception("The quantity of wordlists is greater than the requesters")
        elif lenWordlists != lenRequesters:
            wordlist = arguments.wordlists[0]
            self.globalDictionary = buildDictionary(wordlist, encoder=encoder)
            self.localDictionary = self.globalDictionary
            self.totalRequests = len(self.localDictionary)
        else:
            self.dictionaries = Queue()
            for i, wordlist in enumerate(arguments.wordlists):
                self.dictionaries.put(buildDictionary(wordlist, self.requesters[i], encoder))