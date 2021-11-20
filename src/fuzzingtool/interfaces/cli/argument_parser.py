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

from sys import argv
import argparse

from .cli_output import CliOutput as CO
from ... import version
from ...utils.consts import FUZZING_MARK
from ...utils.utils import stringfy_list
from ...factories.plugin_factory import PluginFactory
from ...reports.report import Report
from ...exceptions.main_exceptions import BadArgumentFormat


class ArgumentParser(argparse.ArgumentParser):
    """Class to handle with the arguments parsing
       Overrides the error method from argparse.ArgumentParser,
       raising an exception instead of exiting
    """
    def __init__(self):
        usage = "Usage: FuzzingTool [-u|-r TARGET]+ [-w WORDLIST]+ [options]*"
        examples = ("For usage examples, see: "
                    "https://github.com/NESCAU-UFLA/FuzzingTool/wiki/Usage-Examples")
        if len(argv) < 2:
            self.error("Invalid format! Use -h on 2nd parameter "
                       f"to show the help menu.\n\n{usage}\n\n{examples}")
        if len(argv) == 2 and ('-h=' in argv[1] or '--help=' in argv[1]):
            asked_help = argv[1].split('=')[1]
            self.EXAMPLE_TEXT = "Examples:\n"
            if 'wordlists' == asked_help:
                self._show_wordlists_help()
            elif 'encoders' == asked_help:
                self._show_encoders_help()
            elif 'scanners' == asked_help:
                self._show_scanners_help()
            else:
                self.error(f"Help argument '{asked_help}' not available")
        super().__init__(
            usage=argparse.SUPPRESS,
            description=usage,
            epilog=examples,
            formatter_class=lambda prog: argparse.HelpFormatter(
                prog, indent_increment=4, max_help_position=30, width=100
            )
        )
        self.__build_options()

    def error(self, message: str) -> None:
        raise BadArgumentFormat(message)

    def get_options(self) -> argparse.Namespace:
        """Get the FuzzingTool options

        @returns argparse.Namespace: The Namespace with the arguments
        """
        return self.parse_args()

    def _show_wordlists_help(self) -> None:
        """Show the help menu for wordlists and exit"""
        CO.help_title(0, "Wordlist options: (-w)")
        CO.print("     You can set just one global wordlist, multiple wordlists and wordlists per target!")
        CO.help_title(2, "Default: The default wordlists are selected by default if no one from plugins was choiced\n")
        CO.help_content(5, "FILEPATH", "Set the path of the wordlist file")
        CO.help_content(5, "[PAYLOAD1,PAYLOAD2,]", "Set the payloads list to be used as wordlist")
        CO.help_title(2, "Plugins:\n")
        self.__show_plugins_help_from_category('wordlists')
        CO.help_title(0, self.EXAMPLE_TEXT)
        CO.print(f"FuzzingTool -u https://{FUZZING_MARK}.domainexample.com/ "
                 "-w /path/to/wordlist/subdomains.txt -t 30 --timeout 5 -V2\n")
        CO.print(f"FuzzingTool -u https://{FUZZING_MARK}.domainexample1.com/ "
                 f"-u https://{FUZZING_MARK}.domainexample2.com/ "
                 "-w [wp-admin,admin,webmail,www,cpanel] -t 30 --timeout 5 -V2\n")
        CO.print(f"FuzzingTool -u https://{FUZZING_MARK}.domainexample.com/ "
                 "-w CrtSh -t 30 --timeout 5 -V2\n")
        CO.print(f"FuzzingTool -u https://domainexample.com/{FUZZING_MARK} "
                 "-w Overflow=5000,:../:etc/passwd -t 30 --timeout 5 -V2\n")
        CO.help_title(0, "Examples with multiple wordlists:\n")
        CO.print(f"FuzzingTool -u https://{FUZZING_MARK}.domainexample.com/ "
                 "-w 'DnsZone;CrtSh' -t 30 --timeout 5 -V2\n")
        CO.print(f"FuzzingTool -u https://domainexample.com/{FUZZING_MARK} "
                 "-w 'Robots;/path/to/wordlist/paths.txt' -t 30 --timeout 5 -V2\n")
        CO.help_title(0, "Example with wordlists per target:\n")
        CO.print(f"FuzzingTool -u domainexample.com/{FUZZING_MARK} "
                 f"-u {FUZZING_MARK}.domainexample2.com "
                 "-w 'Robots;/path/to/wordlist/paths.txt' -w CrtSh -t 30 --timeout 5 -V2\n")
        exit(0)

    def _show_encoders_help(self) -> None:
        """Show the help menu for encoders and exit"""
        CO.help_title(0, "Encoder options: (-e)")
        CO.help_title(2, "Set the encoder used on the payloads\n")
        self.__show_plugins_help_from_category('encoders')
        CO.help_title(0, self.EXAMPLE_TEXT)
        CO.print("FuzzingTool -u https://domainexample.com/page.php?id= "
                 "-w /path/to/wordlist/sqli.txt -e Url=2 -t 30 --scanner Find=SQL\n")
        exit(0)

    def _show_scanners_help(self) -> None:
        """Show the help menu for scanners and exit"""
        CO.help_title(0, "Scanner options:")
        CO.help_title(2, "Default: The default scanners are selected automatically "
                         "if no one from plugins was choiced\n")
        CO.help_content(5, "DataScanner", "Scanner for the data fuzzing")
        CO.help_content(5, "PathScanner", "Scanner for the path fuzzing")
        CO.help_content(5, "SubdomainScanner", "Scanner for the subdomain fuzzing")
        CO.help_title(2, "Plugins (--scaner SCANNER):\n")
        self.__show_plugins_help_from_category('scanners')
        CO.help_title(0, self.EXAMPLE_TEXT)
        CO.print("FuzzingTool -u https://domainexample.com/search.php?query= "
                 "-w /path/to/wordlist/xss.txt --scanner Reflected -t 30 -o csv\n")
        exit(0)

    def __show_plugins_help_from_category(self, category: str) -> None:
        """Show the help menu for the plugins

        @type category: str
        @param category: The package category to search for his plugins
        """
        for plugin_cls in PluginFactory.get_plugins_from_category(category):
            if not plugin_cls.__type__:
                type_fuzzing = ''
            else:
                type_fuzzing = f" (Used for {plugin_cls.__type__})"
            if not plugin_cls.__params__:
                params = ''
            else:
                if plugin_cls.__params__['type'] is list:
                    metavar = plugin_cls.__params__['metavar']
                    separator = plugin_cls.__params__['cli_list_separator']
                    params = f"={metavar}[{separator}{metavar}]*"
                else:
                    params = f"={plugin_cls.__params__['metavar']}"
            CO.help_content(5, f"{plugin_cls.__name__}{params}",
                            f"{plugin_cls.__desc__}{type_fuzzing}\n")

    def __build_options(self) -> None:
        """Builds the FuzzingTool options"""
        self.add_argument(
            '-v', '--version',
            action='version',
            version=f"FuzzingTool v{version()}"
        )
        self.__build_request_opts()
        self.__build_dictionary_opts()
        self.__build_match_opts()
        self.__build_display_opts()
        self.__build_more_opts()

    def __build_request_opts(self) -> None:
        """Builds the arguments for request options"""
        request_opts = self.add_argument_group('Request options')
        request_opts.add_argument(
            '-u',
            action='append',
            dest='url',
            help="Define the target URL",
            metavar='URL',
        )
        request_opts.add_argument(
            '-r',
            action='append',
            dest='raw_http',
            help="Define the file with the raw HTTP request (scheme not specified)",
            metavar='FILE',
        )
        request_opts.add_argument(
            '--scheme',
            action='store',
            dest='scheme',
            help="Define the scheme used in the URL (default http)",
            metavar='SCHEME',
            default="http",
        )
        request_opts.add_argument(
            '-X',
            action='store',
            dest='method',
            help="Define the request http verbs (method)",
            metavar='METHOD',
        )
        request_opts.add_argument(
            '-d',
            action='store',
            dest='data',
            help="Define the request body data",
            metavar='DATA',
        )
        request_opts.add_argument(
            '--proxy',
            action='store',
            dest='proxy',
            help="Define the proxy",
            metavar='IP:PORT',
        )
        request_opts.add_argument(
            '--proxies',
            action='store',
            dest='proxies',
            help="Define the file with a list of proxies",
            metavar='FILE',
        )
        request_opts.add_argument(
            '--cookie',
            action='store',
            dest='cookie',
            help="Define the HTTP Cookie header value",
            metavar='COOKIE',
        )
        request_opts.add_argument(
            '--timeout',
            action='store',
            dest='timeout',
            help="Define the request timeout (in seconds)",
            metavar='TIMEOUT',
            type=int,
            default=0,
        )
        request_opts.add_argument(
            '--follow-redirects',
            action='store_true',
            dest='follow_redirects',
            help="Force to follow redirects",
            default=False,
        )

    def __build_dictionary_opts(self) -> None:
        """Builds the arguments for dictionary options"""
        dictionary_opts = self.add_argument_group('Dictionary options')
        dictionary_opts.add_argument(
            '-w',
            action='append',
            dest='wordlist',
            help=("Define the wordlists with the payloads, separating with ';' "
                  "(--help=wordlists for more info)"),
            metavar='WORDLIST',
            required=True,
        )
        dictionary_opts.add_argument(
            '--unique',
            action='store_true',
            dest='unique',
            help="Removes duplicated payloads from the final wordlist",
            default=False,
        )
        dictionary_opts.add_argument(
            '-e',
            action='store',
            dest='encoder',
            help="Define the encoder used on payloads (--help=encoders for more info)",
            metavar='ENCODER',
            default='',
        )
        dictionary_opts.add_argument(
            '--encode-only',
            action='store',
            dest='encode_only',
            help="Define the regex pattern to use in the encoder",
            metavar='REGEX',
            default='',
        )
        dictionary_opts.add_argument(
            '--prefix',
            action='store',
            dest='prefix',
            help="Define the prefix(es) used with the payload",
            metavar='PREFIX',
        )
        dictionary_opts.add_argument(
            '--suffix',
            action='store',
            dest='suffix',
            help="Define the suffix(es) used with the payload",
            metavar='SUFFIX',
        )
        dictionary_opts.add_argument(
            '--upper',
            action='store_true',
            dest='upper',
            help="Set the uppercase case for the payloads",
            default=False,
        )
        dictionary_opts.add_argument(
            '--lower',
            action='store_true',
            dest='lower',
            help="Set the lowercase case for the payloads",
            default=False,
        )
        dictionary_opts.add_argument(
            '--capitalize',
            action='store_true',
            dest='capitalize',
            help="Set the capitalize case for the payloads",
            default=False,
        )

    def __build_match_opts(self) -> None:
        """Builds the arguments for match options"""
        match_opts = self.add_argument_group('Match options')
        match_opts.add_argument(
            '-Mc',
            action='store',
            dest='match_status',
            help="Match responses based on their status codes",
            metavar='STATUS',
        )
        match_opts.add_argument(
            '-Ms',
            action='store',
            dest='match_length',
            help="Match responses based on their length (in bytes)",
            metavar='SIZE',
        )
        match_opts.add_argument(
            '-Mt',
            action='store',
            dest='match_time',
            help="Match responses based on their elapsed time (in seconds)",
            metavar='TIME',
        )
        match_opts.add_argument(
            '--scanner',
            action='store',
            dest='scanner',
            help="Define the custom scanner (--help=scanners for more info)",
            metavar='SCANNER',
        )

    def __build_display_opts(self) -> None:
        """Builds the arguments for cli display options"""
        display_opts = self.add_argument_group('Display options')
        display_opts.add_argument(
            '-S, --simple-output',
            action='store_true',
            dest="simple_output",
            help="Set the simple display output mode (affects labels)",
            default=False,
        )
        display_opts.add_argument(
            '-V', '-V1',
            action='store_true',
            dest='common_verbose',
            help="Set the common verbose output mode",
            default=False,
        )
        display_opts.add_argument(
            '-V2',
            action='store_true',
            dest='detailed_verbose',
            help="Set the detailed verbose output mode",
            default=False,
        )
        display_opts.add_argument(
            '--no-colors',
            action='store_true',
            dest='disable_colors',
            help="Disable the colors of the program",
            default=False,
        )

    def __build_more_opts(self) -> None:
        """Builds the arguments for non categorized options"""
        more_opts = self.add_argument_group('More options')
        more_opts.add_argument(
            '-t',
            action='store',
            dest='number_of_threads',
            help="Define the number of threads used in the tests",
            metavar='NUMBEROFTHREADS',
            type=int,
            default=1,
        )
        more_opts.add_argument(
            '--delay',
            action='store',
            dest='delay',
            help="Define delay between each request",
            metavar='DELAY',
            type=float,
            default=0,
        )
        more_opts.add_argument(
            '-o',
            action='store',
            dest='report_name',
            help=("Define the report name and/or format. Available reports: "
                  + stringfy_list(list(Report.get_available_reports().keys()))),
            metavar='REPORT',
            default='txt'
        )
        more_opts.add_argument(
            '--blacklist-status',
            action='store',
            dest='blacklist_status',
            help=("Blacklist status codes from response, and take an action when one is detected. "
                  "Available actions: skip (to skip the current target), "
                  "wait=SECONDS (to pause the app for some seconds)"),
            metavar='STATUS:ACTION',
        )
