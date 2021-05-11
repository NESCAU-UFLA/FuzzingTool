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

from .CliOutput import cliOutput as co
from ..conn.RequestParser import getUrlWithoutScheme
from ..utils.utils import getIndexesToParse
from ..utils.FileHandler import fileHandler as fh
from ..exceptions.MainExceptions import InvalidPluginName
from ..factories.PluginFactory import PluginFactory
from ..core.dictionaries.Payloader import Payloader
from ..core.scanners.Matcher import Matcher

from collections import deque

class CliParser:
    """Class that handle with the sys argument parsing"""
    def __init__(self, argv: list):
        """Class constructor

        @type argv: list
        @param argv: The system arguments list
        """
        self.__argv = argv

    def getTargets(self):
        """Get the targets for the fuzzing tests

        @returns list: The targets into a list
        """
        if '-r' in self.__argv:
            return self.buildTargetsFromRawHttp()
        else:
            return self.buildTargetsFromArgs()

    def getDictionary(self):
        """Get the fuzzing dictionary
        
        @returns BaseDictionary: The dictionary object used to provide the payloads
        """
        try:
            wordlistSource = self.__argv[self.__argv.index('-w')+1]
        except ValueError:
            co.errorBox("An wordlist is needed to make the fuzzing")
        if '=' in wordlistSource:
            dictionary, sourceParam = wordlistSource.split('=')
        else:
            dictionary = wordlistSource
            sourceParam = ''
        try:
            dictionary = PluginFactory.objectCreator(dictionary, 'dictionaries', sourceParam)
        except InvalidPluginName:
            try:
                if dictionary.startswith('[') and dictionary.endswith(']'):
                    from ..core.dictionaries.default.ListDictionary import ListDictionary
                    dictionary = ListDictionary(dictionary)
                else:
                    # For default, read the wordlist from a file
                    from ..core.dictionaries.default.FileDictionary import FileDictionary
                    dictionary = FileDictionary(dictionary)
            except Exception as e:
                co.errorBox(str(e))
        except Exception as e:
            co.errorBox(str(e))
        co.infoBox("Building dictionary ...")
        try:
            dictionary.setWordlist()
        except Exception as e:
            co.errorBox(str(e))
        co.infoBox(f"Dictionary is done, loaded {len(dictionary)} payloads")
        return dictionary

    def checkCookie(self):
        """Check if the --cookie argument is present, and set the value into the requester

        @returns str: The cookie used in the request
        """
        cookie = ''
        if '--cookie' in self.__argv:
            cookie = self.__argv[self.__argv.index('--cookie')+1]
            co.infoBox(f"Set cookie: {cookie}")
        return cookie

    def checkProxy(self):
        """Check if the --proxy argument is present, and set the value into the requester

        @returns dict: The proxy dictionary used in the request
        """
        if '--proxy' in self.__argv:
            proxy = self.__argv[self.__argv.index('--proxy')+1]
            co.infoBox(f"Set proxy: {proxy}")
            return proxy
        return {}

    def checkProxies(self):
        """Check if the --proxies argument is present, and open a file
        
        @returns list: THe proxies list used in the request
        """
        if '--proxies' in self.__argv:
            proxiesFileName = self.__argv[self.__argv.index('--proxies')+1]
            co.infoBox(f"Loading proxies from file '{proxiesFileName}' ...")
            try:
                return fh.read(proxiesFileName)
            except Exception as e:
                co.errorBox(str(e))
        return []

    def checkTimeout(self):
        """Check if the --timeout argument is present, and set the request timeout

        @returns None|int: The request timeout
        """
        if '--timeout' in self.__argv:
            timeout = self.__argv[self.__argv.index('--timeout')+1]
            co.infoBox(f"Set request timeout: {timeout} seconds")
            try:
                return int(timeout)
            except:
                co.errorBox(f"The request timeout ({timeout}) must be an integer")
        return None

    def checkFollowRedirects(self):
        """Check if the --unfollow-redirects argument is present, and set the follow redirects flag

        @returns bool: The follow redirections flag used in the request
        """
        if '--unfollow-redirects' in self.__argv:
            return False
        return True

    def checkDelay(self):
        """Check if the --delay argument is present, and set the value into the fuzzer

        @returns float: The delay between each request
        """
        if '--delay' in self.__argv:
            delay = self.__argv[self.__argv.index('--delay')+1]
            co.infoBox(f"Set delay: {delay} second(s)")
            try:
                return float(delay)
            except:
                co.errorBox(f"The delay ({delay}) must be a number")
        return 0

    def checkVerboseMode(self):
        """Check if the -V or --verbose argument is present, and set the verbose mode

        @returns list: The verbosity mode list
        """
        if '-V' in self.__argv or '-V1' in self.__argv:
            return [True, False]
        elif '-V2' in self.__argv:
            return [True, True]
        return [False, False]

    def checkNumThreads(self):
        """Check if the -t argument is present, and set the number of threads in the fuzzer

        @returns int: The number of threads used in the fuzzer
        """
        if '-t' in self.__argv:
            numThreads = self.__argv[self.__argv.index('-t')+1]
            co.infoBox(f"Set number of threads: {numThreads} thread(s)")
            try:
                return int(numThreads)
            except:
                co.errorBox(f"The number of threads ({numThreads}) must be an integer")
        return 1

    def checkBlacklistedStatus(self):
        """Check if the --blacklist-status argument is present, and set the blacklisted status and action

        @returns tuple(list, str): The tuple with the status list and action
        """
        if '--blacklist-status' in self.__argv:
            status = self.__argv[self.__argv.index('--blacklist-status')+1]
            if ':' in status:
                status, action = status.split(':', 1)
                action = action.lower()
            else:
                action = 'skip'
            if ',' in status:
                statusList = status.split(',')
            else:
                statusList = [status]
            try:
                statusList = [int(status) for status in statusList]
            except:
                co.errorBox("Status code must be an integer")
            return (statusList, action)
        return ([], None)

    def checkPrefixAndSuffix(self, payloader: Payloader):
        """Check if the --prefix argument is present, and set the prefix into request parser
           Check if the --suffix argument is present, and set the suffix into request parser
        
        @type payloader: Payloader
        @param payloader: The object responsible to handle with the payloads
        """
        if '--prefix' in self.__argv:
            prefix = self.__argv[self.__argv.index('--prefix')+1]
            if ',' in prefix:
                prefixes = prefix.split(',')
            else:
                prefixes = [prefix]
            payloader.setPrefix(prefixes)
            co.infoBox(f"Set prefix: {str(prefixes)}")
        if '--suffix' in self.__argv:
            suffix = self.__argv[self.__argv.index('--suffix')+1]
            if ',' in suffix:
                suffixes = suffix.split(',')
            else:
                suffixes = [suffix]
            payloader.setSuffix(suffixes)
            co.infoBox(f"Set suffix: {str(suffixes)}")

    def checkCase(self, payloader: Payloader):
        """Check if the --upper argument is present, and set the uppercase case mode
           Check if the --lower argument is present, and set the lowercase case mode
           Check if the --capitalize argument is present, and set the capitalize case mode

        @type payloader: Payloader
        @param payloader: The object responsible to handle with the payloads
        """
        if '--lower' in self.__argv:
            payloader.setLowercase()
            co.infoBox("Set payload case: lowercase")
        elif '--upper' in self.__argv:
            payloader.setUppecase()
            co.infoBox("Set payload case: uppercase")
        elif '--capitalize' in self.__argv:
            payloader.setCapitalize()
            co.infoBox("Set payload case: capitalize")

    def checkEncoder(self, payloader: Payloader):
        """Check if the -e argument is present, and set the encoder for the payloads

        @type payloader: Payloader
        @param payloader: The object responsible to handle with the payloads
        """
        if '-e' in self.__argv:
            encoderName = self.__argv[self.__argv.index('-e')+1]
            if '=' in encoderName:
                encoderName, params = encoderName.split('=', 1)
            else:
                params = ''
            try:
                payloader.setEncoder(PluginFactory.objectCreator(encoderName, 'encoders', params))
            except Exception as e:
                co.errorBox(str(e))
            co.infoBox(f"Set encoder: {encoderName}")

    def checkReporter(self):
        """Check if the -o argument is present, and set the report data (name and type)
        
        @type requester: Request
        @param requester: The object responsible to handle the requests
        """
        if '-o' in self.__argv:
            report = self.__argv[self.__argv.index('-o')+1]
            co.infoBox(f"Set report: {report}")
            fh.reporter.setMetadata(report)

    def checkGlobalScanner(self):
        """Check if the --scanner argument is present, and return the asked scanner by the user

        @returns None|BaseScanner: The scanner used in the fuzzer
        """
        if '--scanner' in self.__argv:
            scannerName = self.__argv[self.__argv.index('--scanner')+1]
            if '=' in scannerName:
                scannerName, params = scannerName.split('=', 1)
            else:
                params = ''
            try:
                scanner = PluginFactory.objectCreator(scannerName, 'scanners', params)
            except Exception as e:
                co.errorBox(str(e))
            co.infoBox(f"Set scanner: {scannerName}")
        else:
            scanner = None
        return scanner

    def checkMatcher(self):
        """Check for the Matcher arguments
        
        @returns Matcher: The global matcher for the scanners
        """
        matcher = Matcher()
        if '-Mc' in self.__argv:
            allowedStatus = self.__argv[self.__argv.index('-Mc')+1]
            if '200' not in allowedStatus:
                if co.askYesNo('warning', "Status code 200 (OK) wasn't included. Do you want to include it to the allowed status codes?"):
                    allowedStatus += ",200"
            allowedList = []
            allowedRange = []
            if ',' in allowedStatus:
                for status in allowedStatus.split(','):
                    self.__getAllowedStatus(status, allowedList, allowedRange)
            else:
                self.__getAllowedStatus(allowedStatus, allowedList, allowedRange)
            allowedStatus = {
                'List': allowedList,
                'Range': allowedRange,
            }
            matcher.setAllowedStatus(allowedStatus)
            co.infoBox(f"Set the allowed status codes: {str(allowedStatus)}")
        comparator = {
            'Length': None,
            'Time': None,
        }
        if '-Ms' in self.__argv:
            length = self.__argv[self.__argv.index('-Ms')+1]
            try:
                comparator['Length'] = int(length)
            except:
                co.errorBox(f"The match length argument ({length}) must be an integer")
            co.infoBox(f"Exclude by length: {length} bytes")
        if '-Mt' in self.__argv:
            time = self.__argv[self.__argv.index('-Mt')+1]
            try:
                comparator['Time'] = float(time)
            except:
                co.errorBox(f"The match time argument ({time}) must be a number")
            co.infoBox(f"Exclude by time: {time} seconds")
        matcher.setComparator(comparator)
        return matcher

    def buildHeaderFromRawHttp(self, args: list):
        """Get the HTTP header

        @tyoe args: list
        @param args: The list with HTTP header
        @returns dict: The HTTP header parsed into a dict
        """
        headers = {}
        i = 0
        thisArg = args.popleft()
        argsLength = len(args)
        while i < argsLength and thisArg != '':
            key, value = thisArg.split(': ', 1)
            headers[key] = value
            thisArg = args.popleft()
            i += 1
        return headers

    def buildTargetsFromRawHttp(self):
        """Get the raw http of the requests

        @type i: int
        @param i: The index of the raw filename on terminal
        @returns tuple(str, list, dict, dict): The default parameters of the requests
        """
        # Check if a scheme is specified, otherwise set http as default
        if '--scheme' in self.__argv:
            scheme = self.__argv[self.__argv.index('--scheme')+1]
        else:
            scheme = 'http'
        targets = []
        for i in getIndexesToParse(self.__argv, '-r'):
            try:
                headerList = deque(fh.read(self.__argv[i+1]))
            except Exception as e:
                co.errorBox(str(e))
            method, path, httpVer = headerList.popleft().split(' ')
            if ',' in method:
                methods = method.split(',')
            else:
                methods = [method]
            headers = self.__getHeader(headerList)
            url = f"{scheme}://{headers['Host']}{path}"
            if len(headerList) > 0:
                data = headerList.popleft()
            else:
                data = ''
            targets.append({
                'url': url,
                'methods': methods,
                'data': data,
                'header': headers,
            })
        return targets
    
    def buildTargetsFromArgs(self):
        """Get the param method to use ('?' or '$' in URL if GET, or -d) and the request paralisting

        @type i: int
        @param i: The index of the target url in terminal
        @type method: list
        @param method: The request methods
        @returns tuple(str, list, dict): The tuple with the new target URL, the request method and params
        """
        urlIndexes = getIndexesToParse(self.__argv, '-u')
        if not urlIndexes:
            co.errorBox("At least a target URL is needed to make the fuzzing")
        if '-X' in self.__argv:
            method = self.__argv[self.__argv.index('-X')+1]
            if ',' in method:
                methods = method.split(',')
            else:
                methods = [method]
        else:
            methods = []
        targets = []
        for i in urlIndexes:
            url = self.__argv[i+1]
            if '?' in url or '$' in url:
                if not methods:
                    methods = ['GET']
            else:
                if not methods:
                    methods = ['POST']
            if '-d' in self.__argv:
                data = self.__argv[self.__argv.index('-d')+1]
            else:
                data = ''
            targets.append({
                'url': url,
                'methods': methods,
                'data': data,
                'header': {},
            })
        return targets
    
    def __getAllowedStatus(self, status: str, allowedList: list, allowedRange: list):
        """Get the allowed status code list and range

        @type status: str
        @param status: The status cod given in the terminal
        @type allowedList: list
        @param allowedList: The allowed status codes list
        @type allowedRange: list
        @param allowedRange: The range of allowed status codes
        """
        try:
            if '-' not in status:
                allowedList.append(int(status))
            else:
                codeLeft, codeRight = (int(code) for code in status.split('-', 1))
                if codeRight < codeLeft:
                    codeLeft, codeRight = codeRight, codeLeft
                allowedRange[:] = [codeLeft, codeRight]
        except:
            co.errorBox(f"The match status argument ({status}) must be integer")