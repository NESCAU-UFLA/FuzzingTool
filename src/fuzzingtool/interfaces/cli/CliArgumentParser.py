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

from .CliOutput import CliOutput as CO
from ..ArgumentBuilder import ArgumentBuilder as AB
from ... import version
from ...utils.utils import getIndexesToParse, getPluginNamesFromCategory, splitStrToList
from ...utils.FileHandler import fileHandler as fh
from ...factories.PluginFactory import PluginFactory
from ...exceptions.MainExceptions import InvalidPluginName

from sys import argv
import argparse

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

def showCustomPackageHelp(category: str):
    """Show the custom package help

    @type category: str
    @param category: The package category to search for his plugins
    """
    for pluginName in getPluginNamesFromCategory(category):
        Plugin = PluginFactory.classCreator(pluginName, category)
        if not Plugin.__type__:
            typeFuzzing = ''
        else:
            typeFuzzing = f" (Used for {Plugin.__type__})"
        if not Plugin.__params__:
            params = ''
        else:
            params = f"={Plugin.__params__}"
        CO.helpContent(5, f"{Plugin.__name__}{params}", f"{Plugin.__desc__}{typeFuzzing}\n")

def showWordlistsHelp():
    CO.helpTitle(0, "Wordlist options: (-w)")
    CO.helpTitle(2, "Default: The default dictionaries are selected by default when no custom are choiced\n")
    CO.helpContent(5, "FILEPATH", "Set the path of the wordlist file")
    CO.helpContent(5, "[PAYLOAD1,PAYLOAD2,]", "Set the payloads list to be used as wordlist")
    CO.helpTitle(2, "Custom (Wordlist=PARAM): Set the custom dictionary and his parameter\n")
    showCustomPackageHelp('wordlists')
    CO.helpTitle(0, "Examples:\n")
    CO.print("FuzzingTool -u https://$.domainexample.com/ -w /path/to/wordlist/subdomains.txt -t 30 --timeout 5 -V2\n")
    CO.print("FuzzingTool -u https://$.domainexample.com/ -w [wp-admin,admin,webmail,www,cpanel] -t 30 --timeout 5 -V2\n")
    CO.print("FuzzingTool -u https://$.domainexample.com/ -w CrtSh=domainexample.com -t 30 --timeout 5 -V2\n")
    CO.print("FuzzingTool -u https://domainexample.com/$ -w Overflow=5000,:../:etc/passwd -t 30 --timeout 5 -V2\n")

def showEncodersHelp():
    CO.helpTitle(0, "Encoder options: (-e)")
    CO.helpTitle(2, "Set the encoder used on the payloads\n")
    showCustomPackageHelp('encoders')
    CO.helpTitle(0, "Examples:\n")
    CO.print("FuzzingTool -u https://domainexample.com/page.php?id= -w /path/to/wordlist/sqli.txt -e Url=2 -t 30 --scanner Find=SQL\n")

def showScannersHelp():
    CO.helpTitle(0, "Scanner options:")
    CO.helpTitle(2, "Default: The default scanners are selected automatically during the tests, if a custom scanner wasn't gived\n")
    CO.helpContent(5, "DataScanner", "Scanner for the data fuzzing")
    CO.helpContent(5, "PathScanner", "Scanner for the path URL fuzzing")
    CO.helpContent(5, "SubdomainScanner", "Scanner for the subdomain URL fuzzing")
    CO.helpTitle(2, "Custom (--scaner SCANNER): Set the custom scanner\n")
    showCustomPackageHelp('scanners')
    CO.helpTitle(0, "Examples:\n")
    CO.print("FuzzingTool -u https://domainexample.com/search.php?query= -w /path/to/wordlist/xss.txt --scanner Reflected -t 30 -o csv\n")

class CliArgumentParser:
    """Class that handle with the sys argument parsing"""
    def __init__(self):
        usage = "Usage: FuzzingTool [-u|-r TARGET]+ [-w WORDLIST]+ [options]*"
        examples = "For usage examples, see: https://github.com/NESCAU-UFLA/FuzzingTool/wiki/Usage-Examples"
        if len(argv) < 2:
            CO.print(f"Invalid format! Use -h on 2nd parameter to show the help menu.\n\n{usage}\n\n{examples}")
            exit(0)
        if len(argv) == 2 and ('-h=' in argv[1] or '--help=' in argv[1]):
            askedHelp = argv[1].split('=')[1]
            if 'wordlists' == askedHelp:
                showWordlistsHelp()
            elif 'encoders' == askedHelp:
                showEncodersHelp()
            elif 'scanners' == askedHelp:
                showScannersHelp()
            else:
                CO.print(f"Help argument '{askedHelp}' not available")
            exit(0)
        parser = argparse.ArgumentParser(
            usage=argparse.SUPPRESS,
            description=usage,
            epilog=examples,
            formatter_class=lambda prog: argparse.HelpFormatter(
                prog, indent_increment=4, max_help_position=30, width=100
            )
        )
        parser.add_argument('-v', '--version',
            action='version',
            version=f"FuzzingTool v{version()}"
        )
        self.options = self.__getOptions(parser)
        self.setArguments()

    def setArguments(self):
        """Set all the app arguments"""
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
        matchStatus = self.options.matchStatus
        if matchStatus:
            if '200' not in matchStatus:
                if CO.askYesNo('warning', "Status code 200 (OK) wasn't included. Do you want to include it to the allowed status codes?"):
                    matchStatus += ",200"
        self.matchStatus = matchStatus
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
        fh.reporter.setMetadata(self.options.reportName)

    def setBlacklistedStatus(self):
        """Check if the --blacklist-status argument is present, and set the blacklisted status and action"""
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

    def __getOptions(self, parser: argparse.ArgumentParser):
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
    
    def __buildRequestOpts(self, parser: argparse.ArgumentParser):
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
    
    def __buildDictionaryOpts(self, parser: argparse.ArgumentParser):
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

    def __buildMatchOpts(self, parser: argparse.ArgumentParser):
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

    def __buildDisplayOpts(self, parser: argparse.ArgumentParser):
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

    def __buildMoreOpts(self, parser: argparse.ArgumentParser):
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
            default='txt'
        )
        moreOpts.add_argument('--blacklist-status',
            action='store',
            dest='blacklistStatus',
            help="Blacklist status codes from response, and take an action when one is detected. Available actions: skip (to skip the current target), wait=SECONDS (to pause the app for some seconds)",
            metavar='STATUS:ACTION',
        )