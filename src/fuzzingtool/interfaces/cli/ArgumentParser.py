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
from ... import version
from ...utils.utils import getPluginNamesFromCategory
from ...factories.PluginFactory import PluginFactory
from ...exceptions.MainExceptions import BadArgumentFormat

from sys import argv
import argparse

class ArgumentParser(argparse.ArgumentParser):
    """Class to handle with the arguments parsing
       Overrides the error method from argparse.ArgumentParser, raising an exception instead of exiting
    """
    def __init__(self, usage: str = '', examples: str = ''):
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
        self.add_argument('-v', '--version',
            action='version',
            version=f"FuzzingTool v{version()}"
        )

    def error(self, message: str):
        raise BadArgumentFormat(message)
    
    def _showWordlistsHelp(self):
        """Show the help menu for wordlists and exit"""
        CO.helpTitle(0, "Wordlist options: (-w)")
        CO.print("     You can set just one global wordlist, multiple wordlists and wordlists per target!")
        CO.helpTitle(2, "Default: The default wordlists are selected by default if no one from plugins was choiced\n")
        CO.helpContent(5, "FILEPATH", "Set the path of the wordlist file")
        CO.helpContent(5, "[PAYLOAD1,PAYLOAD2,]", "Set the payloads list to be used as wordlist")
        CO.helpTitle(2, "Plugins:\n")
        self.__showPluginsHelpFromCategory('wordlists')
        CO.helpTitle(0, "Examples:\n")
        CO.print("FuzzingTool -u https://$.domainexample.com/ -w /path/to/wordlist/subdomains.txt -t 30 --timeout 5 -V2\n")
        CO.print("FuzzingTool -u https://$.domainexample1.com/ -u https://$.domainexample2.com/ -w [wp-admin,admin,webmail,www,cpanel] -t 30 --timeout 5 -V2\n")
        CO.print("FuzzingTool -u https://$.domainexample.com/ -w CrtSh -t 30 --timeout 5 -V2\n")
        CO.print("FuzzingTool -u https://domainexample.com/$ -w Overflow=5000,:../:etc/passwd -t 30 --timeout 5 -V2\n")
        CO.helpTitle(0, "Examples with multiple wordlists:\n")
        CO.print("FuzzingTool -u https://$.domainexample.com/ -w 'DnsZone;CrtSh' -t 30 --timeout 5 -V2\n")
        CO.print("FuzzingTool -u https://domainexample.com/$ -w 'Robots;/path/to/wordlist/paths.txt' -t 30 --timeout 5 -V2\n")
        CO.helpTitle(0, "Example with wordlists per target:\n")
        CO.print("FuzzingTool -u domainexample.com/$ -u $.domainexample2.com -w 'Robots;/path/to/wordlist/paths.txt' -w CrtSh -t 30 --timeout 5 -V2\n")
        exit(0)

    def _showEncodersHelp(self):
        """Show the help menu for encoders and exit"""
        CO.helpTitle(0, "Encoder options: (-e)")
        CO.helpTitle(2, "Set the encoder used on the payloads\n")
        self.__showPluginsHelpFromCategory('encoders')
        CO.helpTitle(0, "Examples:\n")
        CO.print("FuzzingTool -u https://domainexample.com/page.php?id= -w /path/to/wordlist/sqli.txt -e Url=2 -t 30 --scanner Find=SQL\n")
        exit(0)

    def _showScannersHelp(self):
        """Show the help menu for scanners and exit"""
        CO.helpTitle(0, "Scanner options:")
        CO.helpTitle(2, "Default: The default scanners are selected automatically if no one from plugins was choiced\n")
        CO.helpContent(5, "DataScanner", "Scanner for the data fuzzing")
        CO.helpContent(5, "PathScanner", "Scanner for the path URL fuzzing")
        CO.helpContent(5, "SubdomainScanner", "Scanner for the subdomain URL fuzzing")
        CO.helpTitle(2, "Plugins (--scaner SCANNER):\n")
        self.__showPluginsHelpFromCategory('scanners')
        CO.helpTitle(0, "Examples:\n")
        CO.print("FuzzingTool -u https://domainexample.com/search.php?query= -w /path/to/wordlist/xss.txt --scanner Reflected -t 30 -o csv\n")
        exit(0)
    
    def __showPluginsHelpFromCategory(self, category: str):
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
                params = f"={Plugin.__params__}"
            CO.helpContent(5, f"{Plugin.__name__}{params}", f"{Plugin.__desc__}{typeFuzzing}\n")