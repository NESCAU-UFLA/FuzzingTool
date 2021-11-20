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

from .ArgumentParser import ArgumentParser
from ...utils.utils import splitStrToList
from ...exceptions.MainExceptions import BadArgumentFormat

from typing import Tuple

def parseOptionWithArgs(plugin: str) -> Tuple[str, str]:
    """Parse the plugin name into name and parameter

    @type plugin: str
    @param plugin: The plugin argument
    @returns tuple[str, str]: The plugin name and parameter
    """
    if '=' in plugin:
        plugin, param = plugin.split('=', 1)
    else:
        plugin = plugin
        param = ''
    return (plugin, param)

class CliArguments:
    """Class that handle with the FuzzingTool arguments"""
    def __init__(self):
        try:
            parser = ArgumentParser()
            self.options = parser.getOptions()
        except BadArgumentFormat as e:
            exit(f"FuzzingTool bad argument format - {str(e)}")
        self.setRequestArguments()
        self.setDictionaryArguments()
        self.setMatchArguments()
        self.setDisplayArguments()
        self.setGeneralArguments()

    def setRequestArguments(self) -> None:
        """Set the request arguments"""
        self.setTargetsFromArgs()
        self.setTargetsFromRawHttp()
        self.cookie = self.options.cookie
        self.proxy = self.options.proxy
        self.proxies = self.options.proxies
        self.timeout = self.options.timeout
        self.followRedirects = self.options.followRedirects

    def setTargetsFromArgs(self) -> None:
        """Set the targets from url"""
        self.targetsFromUrl = self.options.url
        self.method = self.options.method
        self.data = self.options.data

    def setTargetsFromRawHttp(self) -> None:
        """Set the targets from raw http"""
        self.targetsFromRawHttp = self.options.rawHttp
        self.scheme = self.options.scheme

    def setDictionaryArguments(self) -> None:
        """Set the dictionary arguments"""
        self.wordlists = [[parseOptionWithArgs(w) for w in splitStrToList(wordlist, separator=';')] for wordlist in self.options.wordlist]
        self.unique = self.options.unique
        self.prefix = splitStrToList(self.options.prefix)
        self.suffix = splitStrToList(self.options.suffix)
        self.uppercase = self.options.upper
        self.lowercase = self.options.lower
        self.capitalize = self.options.capitalize
        self.strEncoder = self.options.encoder
        self.encoder = [[parseOptionWithArgs(e) for e in splitStrToList(encoder, separator='@')] for encoder in splitStrToList(self.options.encoder)]
        self.encodeOnly = self.options.encodeOnly

    def setMatchArguments(self) -> None:
        """Set the match arguments"""
        self.matchStatus = self.options.matchStatus
        self.matchLength = self.options.matchLength
        self.matchTime = self.options.matchTime
        self.strScanner = self.options.scanner
        self.scanner = None if not self.options.scanner else parseOptionWithArgs(self.options.scanner)

    def setDisplayArguments(self) -> None:
        """Set the display arguments"""
        self.simpleOutput = self.options.simpleOutput
        if self.options.commonVerbose:
            self.verbose = [True, False]
        elif self.options.detailedVerbose:
            self.verbose = [True, True]
        else:
            self.verbose = [False, False]
        self.disableColors = self.options.disableColors

    def setGeneralArguments(self) -> None:
        """Set the general arguments"""
        self.delay = self.options.delay
        self.numberOfThreads = self.options.numberOfThreads
        self.setBlacklistedStatus()
        self.report = self.options.reportName

    def setBlacklistedStatus(self) -> None:
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