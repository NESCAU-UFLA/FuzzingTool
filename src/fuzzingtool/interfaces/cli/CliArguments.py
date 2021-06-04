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

from .ArgumentParser import ArgumentParser
from ...utils.utils import splitStrToList
from ...exceptions.MainExceptions import BadArgumentFormat

def parseOptionWithArgs(plugin: str):
    """Parse the plugin name into name and parameter

    @type plugin: str
    @param plugin: The plugin argument
    @returns tuple(str, str): The plugin name and parameter
    """
    if '=' in plugin:
        plugin, param = plugin.split('=')
    else:
        plugin = plugin
        param = ''
    return (plugin, param)

class CliArguments:
    """Class that handle with the FuzzingTool arguments"""
    def __init__(self):
        try:
            parser = ArgumentParser(
                usage="Usage: FuzzingTool [-u|-r TARGET]+ [-w WORDLIST]+ [options]*",
                examples="For usage examples, see: https://github.com/NESCAU-UFLA/FuzzingTool/wiki/Usage-Examples",
            )
            self.options = self.__getOptions(parser)
        except BadArgumentFormat as e:
            exit(f"FuzzingTool bad argument format - {str(e)}")
        self.setRequestArguments()
        self.setDictionaryArguments()
        self.setMatchArguments()
        self.setDisplayArguments()
        self.setGeneralArguments()

    def setRequestArguments(self):
        """Set the request arguments"""
        self.setTargetsFromArgs()
        self.setTargetsFromRawHttp()
        self.cookie = self.options.cookie
        self.proxy = self.options.proxy
        self.proxies = self.options.proxies
        self.timeout = self.options.timeout
        self.followRedirects = self.options.followRedirects

    def setTargetsFromArgs(self):
        """Set the targets from url"""
        self.targetsFromUrl = self.options.url
        self.method = self.options.method
        self.data = self.options.data

    def setTargetsFromRawHttp(self):
        """Set the targets from raw http"""
        self.targetsFromRawHttp = self.options.rawHttp
        self.scheme = self.options.scheme

    def setDictionaryArguments(self):
        """Set the dictionary arguments"""
        self.wordlists = [[parseOptionWithArgs(w) for w in splitStrToList(wordlist, separator=';')] for wordlist in self.options.wordlist]
        self.prefix = splitStrToList(self.options.prefix)
        self.suffix = splitStrToList(self.options.suffix)
        self.uppercase = self.options.upper
        self.lowercase = self.options.lower
        self.capitalize = self.options.capitalize
        self.encoder = None if not self.options.encoder else parseOptionWithArgs(self.options.encoder)

    def setMatchArguments(self):
        """Set the match arguments"""
        self.matchStatus = self.options.matchStatus
        self.matchLength = self.options.matchLength
        self.matchTime = self.options.matchTime
        self.scanner = None if not self.options.scanner else parseOptionWithArgs(self.options.scanner)

    def setDisplayArguments(self):
        """Set the display arguments"""
        self.simpleOutput = self.options.simpleOutput
        if self.options.commonVerbose:
            self.verbose = [True, False]
        elif self.options.detailedVerbose:
            self.verbose = [True, True]
        else:
            self.verbose = [False, False]
        self.disableColors = self.options.disableColors

    def setGeneralArguments(self):
        """Set the general arguments"""
        self.delay = self.options.delay
        self.numberOfThreads = self.options.numberOfThreads
        self.setBlacklistedStatus()
        self.report = self.options.reportName

    def setBlacklistedStatus(self):
        """Sets blacklisted status codes, action and action param"""
        self.blacklistedStatus = ''
        self.blacklistAction = ''
        self.blacklistActionParam = ''
        if self.options.blacklistStatus:
            status = self.options.blacklistStatus
            if ':' in status:
                status, blacklistAction = status.split(':', 1)
                blacklistAction = blacklistAction.lower()
                if '=' in blacklistAction:
                    self.blacklistAction, self.blacklistActionParam = blacklistAction.split('=')
                else:
                    self.blacklistAction = blacklistAction
            else:
                self.blacklistAction = 'skip'
            self.blacklistedStatus = status

    def __getOptions(self, parser: ArgumentParser):
        """Builds and get the FuzzingTool arguments

        @type parser: ArgumentParser
        @param parser: The argument parser object
        @returns Namespace(...args): The parsed arguments
        """
        self.__buildRequestOpts(parser)
        self.__buildDictionaryOpts(parser)
        self.__buildMatchOpts(parser)
        self.__buildDisplayOpts(parser)
        self.__buildMoreOpts(parser)
        return parser.parse_args()
    
    def __buildRequestOpts(self, parser: ArgumentParser):
        """Builds the arguments for request options

        @type parser: ArgumentParser
        @param parser: The argument parser object
        """
        requestOpts = parser.add_argument_group('Request options')
        requestOpts.add_argument('-u',
            action='append',
            dest='url',
            help="Define the target URL",
            metavar='URL',
        )
        requestOpts.add_argument('-r',
            action='append',
            dest='rawHttp',
            help="Define the file with the raw HTTP request (scheme not specified)",
            metavar='FILE',
        )
        requestOpts.add_argument('--scheme',
            action='store',
            dest='scheme',
            help="Define the scheme used in the URL (default http)",
            metavar='SCHEME',
            default="http",
        )
        requestOpts.add_argument('-X',
            action='store',
            dest='method',
            help="Define the request http verbs (method)",
            metavar='METHOD',
        )
        requestOpts.add_argument('-d',
            action='store',
            dest='data',
            help="Define the request body data",
            metavar='DATA',
        )
        requestOpts.add_argument('--proxy',
            action='store',
            dest='proxy',
            help="Define the proxy",
            metavar='IP:PORT',
        )
        requestOpts.add_argument('--proxies',
            action='store',
            dest='proxies',
            help="Define the file with a list of proxies",
            metavar='FILE',
        )
        requestOpts.add_argument('--cookie',
            action='store',
            dest='cookie',
            help="Define the HTTP Cookie header value",
            metavar='COOKIE',
        )
        requestOpts.add_argument('--timeout',
            action='store',
            dest='timeout',
            help="Define the request timeout (in seconds)",
            metavar='TIMEOUT',
            type=int,
            default=0,
        )
        requestOpts.add_argument('--follow-redirects',
            action='store_true',
            dest='followRedirects',
            help="Force to follow redirects",
            default=False,
        )
    
    def __buildDictionaryOpts(self, parser: ArgumentParser):
        """Builds the arguments for dictionary options

        @type parser: ArgumentParser
        @param parser: The argument parser object
        """
        dictionaryOpts = parser.add_argument_group('Dictionary options')
        dictionaryOpts.add_argument('-w',
            action='append',
            dest='wordlist',
            help="Define the wordlists with the payloads, separating with ';' (--help=wordlists for more info)",
            metavar='WORDLIST',
            required=True,
        )
        dictionaryOpts.add_argument('-e',
            action='store',
            dest='encoder',
            help="Define the encoder used on payloads (--help=encoders for more info)",
            metavar='ENCODER',
        )
        dictionaryOpts.add_argument('--prefix',
            action='store',
            dest='prefix',
            help="Define the prefix(es) used with the payload",
            metavar='PREFIX',
        )
        dictionaryOpts.add_argument('--suffix',
            action='store',
            dest='suffix',
            help="Define the suffix(es) used with the payload",
            metavar='SUFFIX',
        )
        dictionaryOpts.add_argument('--upper',
            action='store_true',
            dest='upper',
            help="Set the uppercase case for the payloads",
            default=False,
        )
        dictionaryOpts.add_argument('--lower',
            action='store_true',
            dest='lower',
            help="Set the lowercase case for the payloads",
            default=False,
        )
        dictionaryOpts.add_argument('--capitalize',
            action='store_true',
            dest='capitalize',
            help="Set the capitalize case for the payloads",
            default=False,
        )

    def __buildMatchOpts(self, parser: ArgumentParser):
        """Builds the arguments for match options

        @type parser: ArgumentParser
        @param parser: The argument parser object
        """
        matchOpts = parser.add_argument_group('Match options')
        matchOpts.add_argument('-Mc',
            action='store',
            dest='matchStatus',
            help="Match responses based on their status codes",
            metavar='STATUS',
        )
        matchOpts.add_argument('-Ms',
            action='store',
            dest='matchLength',
            help="Match responses based on their length (in bytes)",
            metavar='SIZE',
            type=int,
        )
        matchOpts.add_argument('-Mt',
            action='store',
            dest='matchTime',
            help="Match responses based on their elapsed time (in seconds)",
            metavar='TIME',
            type=float,
        )
        matchOpts.add_argument('--scanner',
            action='store',
            dest='scanner',
            help="Define the custom scanner (--help=scanners for more info)",
            metavar='SCANNER',
        )

    def __buildDisplayOpts(self, parser: ArgumentParser):
        """Builds the arguments for cli display options

        @type parser: ArgumentParser
        @param parser: The argument parser object
        """
        displayOpts = parser.add_argument_group('Display options')
        displayOpts.add_argument('-S, --simple-output',
            action='store_true',
            dest="simpleOutput",
            help="Set the simple display output mode (affects labels)",
            default=False,
        )
        displayOpts.add_argument('-V', '-V1',
            action='store_true',
            dest='commonVerbose',
            help="Set the common verbose output mode",
            default=False,
        )
        displayOpts.add_argument('-V2',
            action='store_true',
            dest='detailedVerbose',
            help="Set the detailed verbose output mode",
            default=False,
        )
        displayOpts.add_argument('--no-colors',
            action='store_true',
            dest='disableColors',
            help="Disable the colors of the program",
            default=False,
        )

    def __buildMoreOpts(self, parser: ArgumentParser):
        """Builds the arguments for non categorized options

        @type parser: ArgumentParser
        @param parser: The argument parser object
        """
        moreOpts = parser.add_argument_group('More options')
        moreOpts.add_argument('-t',
            action='store',
            dest='numberOfThreads',
            help="Define the number of threads used in the tests",
            metavar='NUMBEROFTHREADS',
            type=int,
            default=1,
        )
        moreOpts.add_argument('--delay',
            action='store',
            dest='delay',
            help="Define delay between each request",
            metavar='DELAY',
            type=float,
            default=0,
        )
        moreOpts.add_argument('-o',
            action='store',
            dest='reportName',
            help="Define the report name and/or format (accept txt, csv and json)",
            metavar='REPORT',
        )
        moreOpts.add_argument('--blacklist-status',
            action='store',
            dest='blacklistStatus',
            help="Blacklist status codes from response, and take an action when one is detected. Available actions: skip (to skip the current target), wait=SECONDS (to pause the app for some seconds)",
            metavar='STATUS:ACTION',
        )