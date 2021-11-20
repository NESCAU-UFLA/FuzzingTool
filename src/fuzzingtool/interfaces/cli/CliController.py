# Copyright (c) 2020 - present Vitor Oriel <https://github.com/VitorOriel>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from .CliArguments import *
from .CliOutput import CliOutput, Colors
from ..ArgumentBuilder import ArgumentBuilder as AB
from ... import version
from ...utils.http_utils import *
from ...utils.file_utils import readFile
from ...utils.Logger import Logger
from ...core import *
from ...conn import *
from ...factories import *
from ...reports.Report import Report
from ...exceptions.MainExceptions import SkipTargetException
from ...exceptions.RequestExceptions import *

from queue import Queue
import time
import threading
from typing import Tuple, List

def banner() -> str:
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
        logger: The object to handle with the program log
    """
    def __init__(self):
        self.requesters = []
        self.startedTime = 0
        self.fuzzer = None
        self.allResults = {}
        self.lock = threading.Lock()
        self.blacklistStatus = None
        self.logger = Logger()

    def isVerboseMode(self) -> bool:
        """The verboseMode getter

        @returns bool: The verbose mode flag
        """
        return self.verbose[0]

    def main(self, arguments: CliArguments) -> None:
        """The main function.
           Prepares the application environment and starts the fuzzing
        
        @type arguments: CliArguments
        @param arguments: The command line interface arguments object
        """
        self.co = CliOutput() # Abbreviation to cli output
        self.verbose = arguments.verbose
        if arguments.simpleOutput:
            self.co.setSimpleOutputMode()
        else:
            CliOutput.print(banner())
        try:
            self.co.infoBox("Setting up arguments ...")
            self.init(arguments)
            if not arguments.simpleOutput:
                self.co.printConfigs(
                    output='normal' if not arguments.simpleOutput else 'simple',
                    verbose='quiet' if not self.verbose[0] else 'common' if not self.verbose[1] else 'detailed',
                    targets=self.targetsList,
                    dictionaries=self.dictionariesMetadata,
                    prefix=arguments.prefix,
                    suffix=arguments.suffix,
                    case='lowercase' if arguments.lowercase else 'uppercase' if arguments.uppercase else 'capitalize' if arguments.capitalize else None,
                    encoder=arguments.strEncoder,
                    encodeOnly=arguments.encodeOnly,
                    match={
                        'status': arguments.matchStatus,
                        'length': arguments.matchLength,
                        'time': arguments.matchTime,
                    },
                    scanner=arguments.strScanner,
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
        self.co.setVerbosityMode(self.isVerboseMode())
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

    def init(self, arguments: CliArguments) -> None:
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
        self.report = Report.build(arguments.report)
        self.__initDictionary(arguments)

    def checkConnectionAndRedirections(self) -> None:
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

    def checkRedirections(self, requester: Request) -> None:
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

    def start(self) -> None:
        """Starts the fuzzing application.
           Each target is fuzzed based on their own methods list
        """
        self.startedTime = time.time()
        for requester in self.requesters:
            self.co.infoBox(f"Start fuzzing on {getHost(getPureUrl(requester.getUrl()))}")
            startIndex = 1
            try:
                self.prepareTarget(requester)
                for method in self.requester.methods:
                    self.requester.setMethod(method)
                    self.prepareFuzzer(startIndex)
                    startIndex = self.fuzzer.index
                if not self.isVerboseMode():
                    CliOutput.print("")
            except SkipTargetException as e:
                if self.fuzzer and self.fuzzer.isRunning():
                    self.co.warningBox("Skip target detected, stopping threads ...")
                    self.fuzzer.stop()
                self.co.abortBox(f"{str(e)}. Target skipped")

    def prepareTarget(self, requester: Request) -> None:
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
            comparator=self.globalMatcher.getComparator(),
            matchFunctions=self.globalMatcher.getMatchFunctions()
        )
        if (self.requester.isUrlDiscovery() and
            self.globalMatcher.allowedStatusIsDefault()):
            self.localMatcher.setAllowedStatus(
                Matcher.buildAllowedStatus("200-399,401,403")
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
        self.totalRequests = len(self.localDictionary)*len(self.requester.methods)

    def prepareFuzzer(self, startIndex: int = 1) -> None:
        """Prepare the fuzzer for the fuzzing tests.
           Refill the dictionary with the wordlist content if a global dictionary was given
        
        @type startIndex: int
        @param startIndex: The index value to start the Fuzzer index
        """
        self.localDictionary.reload()
        self.fuzzer = Fuzzer(
            requester=self.requester,
            dictionary=self.localDictionary,
            matcher=self.localMatcher,
            scanner=self.localScanner,
            delay=self.delay,
            numberOfThreads=self.numberOfThreads,
            blacklistStatus=self.blacklistStatus,
            startIndex=startIndex,
            resultCallback=self._resultCallback,
            exceptionCallbacks=[self._invalidHostnameCallback, self._requestExceptionCallback],
        )
        self.fuzzer.start()
        while self.fuzzer.join():
            if self.skipTarget:
                raise SkipTargetException(self.skipTarget)

    def getDefaultScanner(self) -> BaseScanner:
        """Check what's the scanners that will be used
        
        @returns BaseScanner: The scanner used in the fuzzing tests
        """
        if self.requester.isUrlDiscovery():
            if self.requester.isPathFuzzing():
                scanner = PathScanner()
            else:
                scanner = SubdomainScanner()
        else:
            scanner = DataScanner()
        self.co.setMessageCallback(scanner.cliCallback)
        return scanner

    def checkIgnoreErrors(self, host: str) -> None:
        """Check if the user wants to ignore the errors during the tests.
           By default, URL fuzzing (path and subdomain) ignore errors
        
        @type host: str
        @param host: The target hostname
        """
        if self.requester.isUrlDiscovery():
            self.ignoreErrors = True
            logPath = self.logger.setup(host)
            self.co.infoBox(f'The logs will be saved on \'{logPath}\'')
        else:
            if self.co.askYesNo('info', "Do you want to ignore errors on this target, and save them into a log file?"):
                self.ignoreErrors = True
                logPath = self.logger.setup(host)
                self.co.infoBox(f'The logs will be saved on \'{logPath}\'')
            else:
                self.ignoreErrors = False

    def getDataComparator(self) -> dict:
        """Check if the user wants to insert custom data comparator to validate the responses
        
        @returns dict: The data comparator dictionary for the Matcher object
        """
        payload = ' ' # Set an arbitraty payload
        self.co.infoBox(f"Making first request with '{payload}' as payload ...")
        try:
            # Make the first request to get some info about the target
            response, RTT = self.requester.request(payload)
        except RequestException as e:
            raise SkipTargetException(f"{str(e)}")
        resultToComparator = Result(response, RTT)
        self.co.printResult(resultToComparator, False)
        length = None
        defaultLength = int(resultToComparator.length)+300
        if self.co.askYesNo('info', "Do you want to exclude responses based on custom length?"):
            length = self.co.askData(f"Insert the length (in bytes, default >{defaultLength})")
            if not length:
                length = defaultLength
        time = None
        defaultTime = resultToComparator.RTT+5.0
        if self.co.askYesNo('info', "Do you want to exclude responses based on custom time?"):
            time = self.co.askData(f"Insert the time (in seconds, default >{defaultTime} seconds)")
            if not time:
                time = defaultTime
        return Matcher.buildComparator(length, time)

    def showFooter(self) -> None:
        """Show the footer content of the software, after maked the fuzzing.
           The results are shown for each target
        """
        if self.fuzzer:
            if self.startedTime:
                self.co.infoBox(f"Time taken: {float('%.2f'%(time.time() - self.startedTime))} seconds")
            requesterIndex = 0
            for key, value in self.allResults.items():
                if value:
                    if self.isVerboseMode():
                        self.co.infoBox(f"Found {len(value)} matched results on target {key}")
                        if not self.globalScanner:
                            self.requester = self.requesters[requesterIndex]
                            self.getDefaultScanner()
                        for result in value:
                            self.co.printResult(result, True)
                        self.co.infoBox(f'Saving results for {key} ...')
                    reportPath = self.report.open(key)
                    self.report.write(value)
                    self.co.infoBox(f"Results saved on {reportPath}")
                else:
                    self.co.infoBox(f"No matched results was found on target {key}")
                requesterIndex += 1

    def _skipCallback(self, status: int) -> None:
        """The skip target callback for the blacklistAction

        @type status: int
        @param status: The identified status code into the blacklist
        """
        self.skipTarget = f"Status code {str(status)} detected"
    
    def _waitCallback(self, status: int) -> None:
        """The wait (pause) callback for the blacklistAction

        @type status: int
        @param status: The identified status code into the blacklist
        """
        if not self.fuzzer.isPaused():
            self.fuzzer.pause()
            self.co.warningBox(f"Status code {str(status)} detected. Pausing threads ...")
            self.fuzzer.waitUntilPause()
            if not self.isVerboseMode():
                CliOutput.print("")
            self.co.infoBox(f"Waiting for {self.blacklistStatus.actionParam} seconds ...")
            time.sleep(self.blacklistStatus.actionParam)
            self.co.infoBox("Resuming target ...")
            self.fuzzer.resume()

    def _resultCallback(self, result: dict, validate: bool) -> None:
        """Callback function for the results output

        @type result: dict
        @param result: The FuzzingTool result
        @type validate: bool
        @param validate: A validator flag for the result, gived by the scanner
        """
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
    ) -> None:
        """Callback that handle with the request exceptions
        
        @type e: RequestException
        @param e: The request exception
        @type payload: str
        @param payload: The payload used in the request
        """
        if self.ignoreErrors:
            if not self.verbose[0]:
                self.co.progressStatus(
                    self.fuzzer.index, self.totalRequests, payload
                )
            else:
                if self.verbose[1]:
                    self.co.notWorkedBox(str(e))
            with self.lock:
                self.logger.write(str(e), payload)
        else:
            self.skipTarget = str(e)

    def _invalidHostnameCallback(self,
        e: InvalidHostname,
        payload: str
    ) -> None:
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
                self.fuzzer.index, self.totalRequests, payload
            )

    def __initRequesters(self, arguments: CliArguments) -> None:
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
            requester = RequestFactory.creator(
                requestType,
                url=target['url'],
                methods=target['methods'],
                body=target['body'],
                headers=target['header'],
                followRedirects=arguments.followRedirects,
                proxy=arguments.proxy,
                proxies=readFile(arguments.proxies) if arguments.proxies else [],
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

    def __checkForDuplicatedTargets(self) -> None:
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

    def __initDictionary(self, arguments: CliArguments) -> None:
        """Initialize the dictionary

        @type arguments: CliArguments
        @param arguments: The command line interface arguments object
        """
        def buildEncoders() -> Tuple[
            List[BaseEncoder], List[List[BaseEncoder]]
        ]:
            """Build the encoders

            @returns Tuple[List[BaseEncoder], List[List[BaseEncoder]]]: The encoders used in the program
            """
            if not arguments.encoder:
                return None
            if arguments.encodeOnly:
                try:
                    Payloader.encoder.setRegex(arguments.encodeOnly)
                except Exception as e:
                    raise e
            encodersDefault = []
            encodersChain = []
            for encoders in arguments.encoder:
                if len(encoders) > 1:
                    appendTo = []
                    isChain = True
                else:
                    appendTo = encodersDefault
                    isChain = False
                for encoder in encoders:
                    name, param = encoder
                    try:
                        encoder = PluginFactory.objectCreator(
                            name, 'encoders', param
                        )
                    except Exception as e:
                        raise e
                    appendTo.append(encoder)
                if isChain:
                    encodersChain.append(appendTo)
            return (encodersDefault, encodersChain)

        def buildDictionary(
            wordlists: List[Tuple[str, str]],
            isUnique: bool,
            requester: Request = None
        ) -> None:
            """Build the dictionary

            @type wordlists: List[Tuple[str, str]]
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
                if self.verbose[1]:
                    self.co.infoBox(f"Building wordlist from {name} ...")
                self.dictionariesMetadata[lastDictIndex]['wordlists'].append(
                    f"{name}={params}" if params else name
                )
                try:
                    buildedWordlist.extend(WordlistFactory.creator(name, params, requester))
                except Exception as e:
                    if self.isVerboseMode():
                        self.co.warningBox(str(e))
                else:
                    if self.verbose[1]:
                        self.co.infoBox(f"Wordlist {name} builded")
            if not buildedWordlist:
                raise Exception("The wordlist is empty")
            atualLength = len(buildedWordlist)
            if isUnique:
                previousLength = atualLength
                buildedWordlist = set(buildedWordlist)
                atualLength = len(buildedWordlist)
                self.dictionariesMetadata[lastDictIndex]['removed'] = previousLength-atualLength
            dictionary = Dictionary(buildedWordlist)
            self.dictionariesMetadata[lastDictIndex]['len'] = atualLength
            return dictionary
        
        Payloader.setPrefix(arguments.prefix)
        Payloader.setSuffix(arguments.suffix)
        if arguments.lowercase:
            Payloader.setLowercase()
        elif arguments.uppercase:
            Payloader.setUppercase()
        elif arguments.capitalize:
            Payloader.setCapitalize()
        encoders = buildEncoders()
        if encoders:
            Payloader.encoder.setEncoders(encoders)
        self.globalDictionary = None
        self.dictionaries = []
        self.dictionariesMetadata = []
        lenWordlists = len(arguments.wordlists)
        lenRequesters = len(self.requesters)
        if lenWordlists > lenRequesters:
            raise Exception("The quantity of wordlists is greater than the requesters")
        elif lenWordlists != lenRequesters:
            wordlist = arguments.wordlists[0]
            self.globalDictionary = buildDictionary(wordlist, arguments.unique)
            self.localDictionary = self.globalDictionary
        else:
            self.dictionaries = Queue()
            for i, wordlist in enumerate(arguments.wordlists):
                self.dictionaries.put(buildDictionary(
                    wordlist, arguments.unique, self.requesters[i]
                ))