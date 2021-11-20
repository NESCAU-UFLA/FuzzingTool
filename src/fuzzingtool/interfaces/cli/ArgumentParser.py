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

from .CliOutput import CliOutput as CO
from ... import version
from ...utils.consts import FUZZING_MARK
from ...utils.utils import stringfyList
from ...utils.file_utils import getPluginNamesFromCategory
from ...factories.PluginFactory import PluginFactory
from ...reports.Report import Report
from ...exceptions.MainExceptions import BadArgumentFormat

from sys import argv
import argparse

class ArgumentParser(argparse.ArgumentParser):
    """Class to handle with the arguments parsing
       Overrides the error method from argparse.ArgumentParser, raising an exception instead of exiting
    """
    def __init__(self):
        usage = "Usage: FuzzingTool [-u|-r TARGET]+ [-w WORDLIST]+ [options]*"
        examples = "For usage examples, see: https://github.com/NESCAU-UFLA/FuzzingTool/wiki/Usage-Examples"
        if len(argv) < 2:
            self.error(f"Invalid format! Use -h on 2nd parameter to show the help menu.\n\n{usage}\n\n{examples}")
        if len(argv) == 2 and ('-h=' in argv[1] or '--help=' in argv[1]):
            askedHelp = argv[1].split('=')[1]
            if 'wordlists' == askedHelp:
                self._showWordlistsHelp()
            elif 'encoders' == askedHelp:
                self._showEncodersHelp()
            elif 'scanners' == askedHelp:
                self._showScannersHelp()
            else:
                self.error(f"Help argument '{askedHelp}' not available")
        super().__init__(
            usage=argparse.SUPPRESS,
            description=usage,
            epilog=examples,
            formatter_class=lambda prog: argparse.HelpFormatter(
                prog, indent_increment=4, max_help_position=30, width=100
            )
        )
        self.__buildOptions()

    def error(self, message: str) -> None:
        raise BadArgumentFormat(message)
    
    def getOptions(self) -> argparse.Namespace:
        """Get the FuzzingTool options
        
        @returns argparse.Namespace: The Namespace with the arguments
        """
        return self.parse_args()
    
    def _showWordlistsHelp(self) -> None:
        """Show the help menu for wordlists and exit"""
        CO.helpTitle(0, "Wordlist options: (-w)")
        CO.print("     You can set just one global wordlist, multiple wordlists and wordlists per target!")
        CO.helpTitle(2, "Default: The default wordlists are selected by default if no one from plugins was choiced\n")
        CO.helpContent(5, "FILEPATH", "Set the path of the wordlist file")
        CO.helpContent(5, "[PAYLOAD1,PAYLOAD2,]", "Set the payloads list to be used as wordlist")
        CO.helpTitle(2, "Plugins:\n")
        self.__showPluginsHelpFromCategory('wordlists')
        CO.helpTitle(0, "Examples:\n")
        CO.print(f"FuzzingTool -u https://{FUZZING_MARK}.domainexample.com/ -w /path/to/wordlist/subdomains.txt -t 30 --timeout 5 -V2\n")
        CO.print(f"FuzzingTool -u https://{FUZZING_MARK}.domainexample1.com/ -u https://{FUZZING_MARK}.domainexample2.com/ -w [wp-admin,admin,webmail,www,cpanel] -t 30 --timeout 5 -V2\n")
        CO.print(f"FuzzingTool -u https://{FUZZING_MARK}.domainexample.com/ -w CrtSh -t 30 --timeout 5 -V2\n")
        CO.print(f"FuzzingTool -u https://domainexample.com/{FUZZING_MARK} -w Overflow=5000,:../:etc/passwd -t 30 --timeout 5 -V2\n")
        CO.helpTitle(0, "Examples with multiple wordlists:\n")
        CO.print(f"FuzzingTool -u https://{FUZZING_MARK}.domainexample.com/ -w 'DnsZone;CrtSh' -t 30 --timeout 5 -V2\n")
        CO.print(f"FuzzingTool -u https://domainexample.com/{FUZZING_MARK} -w 'Robots;/path/to/wordlist/paths.txt' -t 30 --timeout 5 -V2\n")
        CO.helpTitle(0, "Example with wordlists per target:\n")
        CO.print(f"FuzzingTool -u domainexample.com/{FUZZING_MARK} -u {FUZZING_MARK}.domainexample2.com -w 'Robots;/path/to/wordlist/paths.txt' -w CrtSh -t 30 --timeout 5 -V2\n")
        exit(0)

    def _showEncodersHelp(self) -> None:
        """Show the help menu for encoders and exit"""
        CO.helpTitle(0, "Encoder options: (-e)")
        CO.helpTitle(2, "Set the encoder used on the payloads\n")
        self.__showPluginsHelpFromCategory('encoders')
        CO.helpTitle(0, "Examples:\n")
        CO.print(f"FuzzingTool -u https://domainexample.com/page.php?id= -w /path/to/wordlist/sqli.txt -e Url=2 -t 30 --scanner Find=SQL\n")
        exit(0)

    def _showScannersHelp(self) -> None:
        """Show the help menu for scanners and exit"""
        CO.helpTitle(0, "Scanner options:")
        CO.helpTitle(2, "Default: The default scanners are selected automatically if no one from plugins was choiced\n")
        CO.helpContent(5, "DataScanner", "Scanner for the data fuzzing")
        CO.helpContent(5, "PathScanner", "Scanner for the path fuzzing")
        CO.helpContent(5, "SubdomainScanner", "Scanner for the subdomain fuzzing")
        CO.helpTitle(2, "Plugins (--scaner SCANNER):\n")
        self.__showPluginsHelpFromCategory('scanners')
        CO.helpTitle(0, "Examples:\n")
        CO.print(f"FuzzingTool -u https://domainexample.com/search.php?query= -w /path/to/wordlist/xss.txt --scanner Reflected -t 30 -o csv\n")
        exit(0)
    
    def __showPluginsHelpFromCategory(self, category: str) -> None:
        """Show the help menu for the plugins

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
                if Plugin.__params__['type'] is list:
                    metavar = Plugin.__params__['metavar']
                    separator = Plugin.__params__['cli_list_separator']
                    params = f"={metavar}[{separator}{metavar}]*"
                else:
                    params = f"={Plugin.__params__['metavar']}"
            CO.helpContent(5, f"{Plugin.__name__}{params}", f"{Plugin.__desc__}{typeFuzzing}\n")
    
    def __buildOptions(self) -> None:
        """Builds the FuzzingTool options"""
        self.add_argument('-v', '--version',
            action='version',
            version=f"FuzzingTool v{version()}"
        )
        self.__buildRequestOpts()
        self.__buildDictionaryOpts()
        self.__buildMatchOpts()
        self.__buildDisplayOpts()
        self.__buildMoreOpts()

    def __buildRequestOpts(self) -> None:
        """Builds the arguments for request options"""
        requestOpts = self.add_argument_group('Request options')
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
    
    def __buildDictionaryOpts(self) -> None:
        """Builds the arguments for dictionary options"""
        dictionaryOpts = self.add_argument_group('Dictionary options')
        dictionaryOpts.add_argument('-w',
            action='append',
            dest='wordlist',
            help="Define the wordlists with the payloads, separating with ';' (--help=wordlists for more info)",
            metavar='WORDLIST',
            required=True,
        )
        dictionaryOpts.add_argument('--unique',
            action='store_true',
            dest='unique',
            help="Removes duplicated payloads from the final wordlist",
            default=False,
        )
        dictionaryOpts.add_argument('-e',
            action='store',
            dest='encoder',
            help="Define the encoder used on payloads (--help=encoders for more info)",
            metavar='ENCODER',
            default='',
        )
        dictionaryOpts.add_argument('--encode-only',
            action='store',
            dest='encodeOnly',
            help="Define the regex pattern to use in the encoder",
            metavar='REGEX',
            default='',
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

    def __buildMatchOpts(self) -> None:
        """Builds the arguments for match options"""
        matchOpts = self.add_argument_group('Match options')
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
        )
        matchOpts.add_argument('-Mt',
            action='store',
            dest='matchTime',
            help="Match responses based on their elapsed time (in seconds)",
            metavar='TIME',
        )
        matchOpts.add_argument('--scanner',
            action='store',
            dest='scanner',
            help="Define the custom scanner (--help=scanners for more info)",
            metavar='SCANNER',
        )

    def __buildDisplayOpts(self) -> None:
        """Builds the arguments for cli display options"""
        displayOpts = self.add_argument_group('Display options')
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

    def __buildMoreOpts(self) -> None:
        """Builds the arguments for non categorized options"""
        moreOpts = self.add_argument_group('More options')
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
            help=f"Define the report name and/or format. Available reports: {stringfyList(list(Report.getAvailableReports().keys()))}",
            metavar='REPORT',
            default='txt'
        )
        moreOpts.add_argument('--blacklist-status',
            action='store',
            dest='blacklistStatus',
            help="Blacklist status codes from response, and take an action when one is detected. Available actions: skip (to skip the current target), wait=SECONDS (to pause the app for some seconds)",
            metavar='STATUS:ACTION',
        )