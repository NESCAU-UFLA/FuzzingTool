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

from .RequestParser import getHost, getPureUrl, getUrlWithoutScheme
from ..utils.utils import getIndexesToParse, getCustomPackageNames, importCustomPackage
from ..core.Fuzzer import Fuzzer
from ..core.dictionaries import *
from ..core.encoders import *
from ..core.scanners import *
from ..conn.Request import Request
from ..IO.OutputHandler import outputHandler as oh
from ..IO.FileHandler import fileHandler as fh
from ..exceptions.MainExceptions import MissingParameter

from collections import deque

class CLIParser:
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
        targets = []
        if '-r' in self.__argv:
            rawIndexes = getIndexesToParse(self.__argv, '-r')
            for i in rawIndexes:
                url, methods, data, headers = self.__getRequestFromRawHttp(i+1)
                targets.append({
                    'url': url,
                    'methods': methods,
                    'data': self.__getRequestData(data),
                    'header': headers,
                })
        else:
            urlIndexes = getIndexesToParse(self.__argv, '-u')
            if not urlIndexes:
                oh.errorBox("At least a target URL is needed to make the fuzzing")
            if '-X' in self.__argv:
                method = self.__argv[self.__argv.index('-X')+1]
                if ',' in method:
                    customMethods = method.split(',')
                else:
                    customMethods = [method]
            else:
                customMethods = []
            for i in urlIndexes:
                url, methods, data = self.__getRequestFromArgs(i+1, customMethods)
                targets.append({
                    'url': url,
                    'methods': methods,
                    'data': self.__getRequestData(data),
                    'header': {},
                })
        return targets

    def getDictionary(self):
        """Get the fuzzing dictionary
        
        @returns BaseDictionary: The dictionary object used to provide the payloads
        """
        try:
            wordlistSource = self.__argv[self.__argv.index('-w')+1]
        except ValueError:
            oh.errorBox("An wordlist is needed to make the fuzzing")
        if '=' in wordlistSource:
            dictionary, sourceParam = wordlistSource.split('=')
        else:
            dictionary = wordlistSource
            sourceParam = ''
        if dictionary in getCustomPackageNames('dictionaries'):
            dictionary = importCustomPackage('dictionaries', dictionary)()
        else:
            if dictionary.startswith('[') and dictionary.endswith(']'):
                from ..core.dictionaries.default.ListDictionary import ListDictionary
                dictionary = ListDictionary()
            else:
                # For default, read the wordlist from a file
                from ..core.dictionaries.default.FileDictionary import FileDictionary
                dictionary = FileDictionary()
            sourceParam = wordlistSource
        oh.infoBox("Building dictionary ...")
        try:
            dictionary.setWordlist(sourceParam)
        except MissingParameter as e:
            oh.errorBox(f"{wordlistSource} missing parameter: {str(e)}")
        except Exception as e:
            oh.errorBox(str(e))
        oh.infoBox(f"Dictionary is done, loaded {len(dictionary)} payloads")
        return dictionary

    def checkCookie(self):
        """Check if the --cookie argument is present, and set the value into the requester

        @returns str: The cookie used in the request
        """
        cookie = ''
        if '--cookie' in self.__argv:
            cookie = self.__argv[self.__argv.index('--cookie')+1]
            oh.infoBox(f"Set cookie: {cookie}")
        return cookie

    def checkProxy(self):
        """Check if the --proxy argument is present, and set the value into the requester

        @returns dict: The proxy dictionary used in the request
        """
        if '--proxy' in self.__argv:
            proxy = self.__argv[self.__argv.index('--proxy')+1]
            oh.infoBox(f"Set proxy: {proxy}")
            return {
                'http': f"http://{proxy}",
                'https': f"https://{proxy}",
            }
        return {}

    def checkProxies(self):
        """Check if the --proxies argument is present, and open a file
        
        @returns list: THe proxies list used in the request
        """
        if '--proxies' in self.__argv:
            proxiesFileName = self.__argv[self.__argv.index('--proxies')+1]
            oh.infoBox(f"Loading proxies from file '{proxiesFileName}' ...")
            try:
                proxies = fh.read(proxiesFileName)
            except Exception as e:
                oh.errorBox(str(e))
            return [{
                'http': f"http://{proxy}",
                'https': f"https://{proxy}",
            } for proxy in proxies]
        return []

    def checkTimeout(self):
        """Check if the --timeout argument is present, and set the request timeout

        @returns None|int: The request timeout
        """
        if '--timeout' in self.__argv:
            timeout = self.__argv[self.__argv.index('--timeout')+1]
            oh.infoBox(f"Set request timeout: {timeout} seconds")
            return int(timeout)
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
            oh.infoBox(f"Set delay: {delay} second(s)")
            return float(delay)
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
            oh.infoBox(f"Set number of threads: {numThreads} thread(s)")
            return int(numThreads)
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
                oh.errorBox("Status code must be an integer")
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
            oh.infoBox(f"Set prefix: {str(prefixes)}")
        if '--suffix' in self.__argv:
            suffix = self.__argv[self.__argv.index('--suffix')+1]
            if ',' in suffix:
                suffixes = suffix.split(',')
            else:
                suffixes = [suffix]
            payloader.setSuffix(suffixes)
            oh.infoBox(f"Set suffix: {str(suffixes)}")

    def checkCase(self, payloader: Payloader):
        """Check if the --upper argument is present, and set the uppercase case mode
           Check if the --lower argument is present, and set the lowercase case mode
           Check if the --capitalize argument is present, and set the capitalize case mode

        @type payloader: Payloader
        @param payloader: The object responsible to handle with the payloads
        """
        if '--lower' in self.__argv:
            payloader.setLowercase()
            oh.infoBox("Set payload case: lowercase")
        elif '--upper' in self.__argv:
            payloader.setUppecase()
            oh.infoBox("Set payload case: uppercase")
        elif '--capitalize' in self.__argv:
            payloader.setCapitalize()
            oh.infoBox("Set payload case: capitalize")

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
            if encoderName in getCustomPackageNames('encoders'):
                encoder = importCustomPackage('encoders', encoderName)
                if not encoder.__params__:
                    encoder = encoder()
                else:
                    try:
                        encoder = encoder(params)
                    except MissingParameter as e:
                        oh.errorBox(f"Encoder {encoderName} missing parameter: {str(e)}")
                    except Exception as e:
                        oh.errorBox(f"Bad encoder argument format: {str(e)}")
                payloader.setEncoder(encoder)
            else:
                oh.errorBox(f"Encoder {encoderName} not available!")
            oh.infoBox(f"Set encoder: {encoder.__name__}")

    def checkReporter(self):
        """Check if the -o argument is present, and set the report data (name and type)
        
        @type requester: Request
        @param requester: The object responsible to handle the requests
        """
        if '-o' in self.__argv:
            report = self.__argv[self.__argv.index('-o')+1]
            if '.' in report:
                reportName, reportType = report.split('.')
            else:
                reportType = report
                reportName = ''
            reportType = reportType.lower()
            if reportType not in ['txt', 'csv', 'json']:
                oh.errorBox(f"Unsupported report format for {reportType}! Accepts: txt, csv and json")
            oh.infoBox(f"Set report: {report}")
        else:
            reportType = 'txt'
            reportName = ''
        fh.reporter.setMetadata({
            'Type': reportType,
            'Name': reportName,
        })

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
            if scannerName in getCustomPackageNames('scanners'):
                scanner = importCustomPackage('scanners', scannerName)
                if not scanner.__params__:
                    scanner = scanner()
                else:
                    try:
                        scanner = scanner(params)
                    except MissingParameter as e:
                        oh.errorBox(f"Scanner {scannerName} missing parameter: {str(e)}")
                    except Exception as e:
                        oh.errorBox(f"Bad scanner argument format: {str(e)}")
            else:
                oh.errorBox(f"Scanner {scannerName} not available!")
            oh.infoBox(f"Set scanner: {scanner.__name__}")
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
            allowedList = []
            allowedRange = []
            if ',' in allowedStatus:
                for status in allowedStatus.split(','):
                    self.__getAllowedStatus(status, allowedList, allowedRange)
            else:
                self.__getAllowedStatus(allowedStatus, allowedList, allowedRange)
            if 200 not in allowedList:
                if oh.askYesNo('warning', "Status code 200 (OK) wasn't included. Do you want to include it to the allowed status codes?"):
                    allowedList = [200] + allowedList
            allowedStatus = {
                'List': allowedList,
                'Range': allowedRange,
            }
            matcher.setAllowedStatus(allowedStatus)
            oh.infoBox(f"Set the allowed status codes: {str(allowedStatus)}")
        comparator = {
            'Length': None,
            'Time': None,
        }
        if '-Ms' in self.__argv:
            length = self.__argv[self.__argv.index('-Ms')+1]
            comparator['Length'] = int(length)
            oh.infoBox(f"Exclude by length: {length} bytes")
        if '-Mt' in self.__argv:
            time = self.__argv[self.__argv.index('-Mt')+1]
            comparator['Time'] = float(time)
            oh.infoBox(f"Exclude by time: {time} seconds")
        matcher.setComparator(comparator)
        return matcher

    def __getHeader(self, args: list):
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

    def __getRequestFromRawHttp(self, i: int):
        """Get the raw http of the requests

        @type i: int
        @param i: The index of the raw filename on terminal
        @returns tuple(str, list, dict, dict): The default parameters of the requests
        """
        try:
            headerList = deque(fh.read(self.__argv[i]))
        except Exception as e:
            oh.errorBox(str(e))
        method, path, httpVer = headerList.popleft().split(' ')
        if ',' in method:
            methods = method.split(',')
        else:
            methods = [method]
        headers = self.__getHeader(headerList)
        data = {
            'PARAM': '',
            'BODY': '',
        }
        if '?' in path:
            path, data['PARAM'] = path.split('?', 1)
        # Check if a scheme is specified, otherwise set http as default
        if '--scheme' in self.__argv:
            scheme = self.__argv[self.__argv.index('--scheme')+1]
        else:
            scheme = 'http'
        url = f"{scheme}://{headers['Host']}{path}"
        if len(headerList) > 0:
            data['BODY'] = headerList.popleft()
        return (url, methods, data, headers)
    
    def __getRequestFromArgs(self, i: int, methods: list):
        """Get the param method to use ('?' or '$' in URL if GET, or -d) and the request paralisting

        @type i: int
        @param i: The index of the target url in terminal
        @type method: list
        @param method: The request methods
        @returns tuple(str, list, dict): The tuple with the new target URL, the request method and params
        """
        url = self.__argv[i]
        if '://' not in url:
            # No schema was defined, default protocol http
            url = f'http://{url}'
        if '/' not in getUrlWithoutScheme(url):
            # Insert a base path if wasn't specified
            url += '/'
        data = {
            'PARAM': '',
            'BODY': '',
        }
        if '?' in url or '$' in url:
            if not methods:
                methods = ['GET']
            if '?' in url:
                url, data['PARAM'] = url.split('?', 1)
        else:
            if not methods:
                methods = ['POST']
        if '-d' in self.__argv:
            data['BODY'] = self.__argv[self.__argv.index('-d')+1]
        return (url, methods, data)
    
    def __makeDataDict(self, dataDict: dict, key: str):
        """Set the default parameter values if are given

        @type data: dict
        @param data: The entries data of the request
        @type key: str
        @param key: The parameter key of the request
        """
        if '=' in key:
            key, value = key.split('=')
            if not '$' in value:
                dataDict[key] = value
            else:
                dataDict[key] = ''
        else:
            dataDict[key] = ''

    def __getRequestData(self, data: dict):
        """Split all the request parameters into a list of arguments used in the request

        @type data: dict
        @param data: The parameters of the request
        @returns dict: The entries data of the request
        """
        dataDict = {
            'PARAM': {},
            'BODY': {},
        }
        keys = []
        if data['PARAM']:
            keys.append('PARAM')
        if data['BODY']:
            keys.append('BODY')
        if not keys:
            return dataDict
        for key in keys:
            if '&' in data[key]:
                data[key] = data[key].split('&')
                for arg in data[key]:
                    self.__makeDataDict(dataDict[key], arg)
            else:
                self.__makeDataDict(dataDict[key], data[key])
        return dataDict
    
    def __getAllowedStatus(self, status: str, allowedList: list, allowedRange: list):
        """Get the allowed status code list and range

        @type status: str
        @param status: The status cod given in the terminal
        @type allowedList: list
        @param allowedList: The allowed status codes list
        @type allowedRange: list
        @param allowedRange: The range of allowed status codes
        """
        if '-' not in status:
            allowedList.append(int(status))
        else:
            codeLeft, codeRight = (int(code) for code in status.split('-', 1))
            if codeRight < codeLeft:
                codeLeft, codeRight = codeRight, codeLeft
            allowedRange[:] = [codeLeft, codeRight]