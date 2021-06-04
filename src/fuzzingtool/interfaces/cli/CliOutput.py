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

from ...utils.utils import stringfyList
from ...conn.RequestParser import getHost, getPureUrl

from datetime import datetime
import platform
import threading
import sys
import os
from typing import Callable

if platform.system() == 'Windows':
    try:
        from colorama import init
    except:
        exit("Colorama package not installed. Install all dependencies first.")
    init()

def fixPayloadToOutput(
    payload: str,
    maxLength: int = 30,
    isProgressStatus: bool = False,
):
    """Fix the payload's size

    @type payload: str
    @param payload: The payload used in the request
    @type maxLength: int
    @param maxLength: The maximum length of the payload on output
    @type isProgressStatus: bool
    @param isProgressStatus: A flag to say if the function was called by the progressStatus or not
    @returns str: The fixed payload to output
    """
    if '	' in payload:
        payload = payload.replace('	', ' ')
    if len(payload) > maxLength:
        output = ""
        for i in range(27):
            output += payload[i]
        output += '...'
        return output
    if isProgressStatus:
        while len(payload) < maxLength:
            payload += ' '
    return payload

def getFormatedResult(payload: str, RTT: float, length: int):
    """Format the result into a dict of strings

    @type payload: str
    @param payload: The payload used in the request
    @type RTT: float
    @param RTT: The request and response elapsed time
    @type length: int
    @param length: The response body length in bytes
    @returns tuple(str, str, str): The result formated with strings
    """
    return (
        '{:<30}'.format(fixPayloadToOutput(payload)),
        '{:>10}'.format(RTT),
        '{:>8}'.format(length),
    )

class Colors:
    """Class that handle with the colors"""
    RESET = '\033[0m'
    GRAY = '\033[90m'
    YELLOW = '\033[33m'
    RED = '\u001b[31;1m'
    GREEN = '\u001b[32;1m'
    BLUE = '\u001b[34m'
    BLUE_GRAY = '\033[36m'
    CYAN = '\u001b[36m'
    LIGHT_GRAY = '\u001b[38;5;250m'
    LIGHT_YELLOW = '\u001b[33;1m'
    LIGHT_RED = "\033[91m"
    LIGHT_GREEN = '\u001b[38;5;48m'
    BOLD = '\033[1m'

    @staticmethod
    def disable():
        Colors.RESET = Colors.GRAY = Colors.YELLOW = Colors.RED = Colors.GREEN = Colors.BLUE = Colors.BLUE_GRAY = Colors.CYAN = Colors.LIGHT_GRAY = Colors.LIGHT_YELLOW = Colors.LIGHT_RED = Colors.LIGHT_GREEN = Colors.BOLD = ''

class CliOutput:
    """Class that handle with the outputs
    
    Attributes:
        lock: The threads locker
        breakLine: A string to break line
        lastInline: A flag to say if the last output was inline or not
        info: The info label
        warning: The warning label
        error: The error label
        abort: The abort label
        worked: The worked label
        notWorked: The not worked label
    """
    @staticmethod
    def print(msg: str):
        """Print the message

        @type msg: str
        @param msg: The message
        """
        print(msg)

    @staticmethod
    def helpTitle(numSpaces: int, title: str):
        """Output the help title

        @type numSpaces: int
        @param numSpaces: The number of spaces before the title
        @type title: str
        @param title: The title or subtitle
        """
        print("\n"+' '*numSpaces+title)

    @staticmethod
    def helpContent(numSpaces: int, command: str, desc: str):
        """Output the help content

        @type numSpaces: int
        @param numSpaces: The number of spaces before the content
        @type command: str
        @param command: The command to be used in the execution argument
        @type desc: str
        @param desc: The description of the command
        """
        maxCommandSizeWithSpace = 27
        if (len(command)+numSpaces) <= maxCommandSizeWithSpace:
            print(' '*numSpaces+("{:<"+str(maxCommandSizeWithSpace-numSpaces)+"}").format(command)+' '+desc)
        else:
            print(' '*numSpaces+("{:<"+str(maxCommandSizeWithSpace-numSpaces)+"}").format(command))
            print(' '*(maxCommandSizeWithSpace)+' '+desc)

    def __init__(self):
        self.__lock = None
        self.__breakLine = ''
        self.__lastInline = False
        self.__info = f'{Colors.GRAY}[{Colors.BLUE_GRAY}INFO{Colors.GRAY}]{Colors.RESET} '
        self.__warning = f'{Colors.GRAY}[{Colors.YELLOW}WARNING{Colors.GRAY}]{Colors.RESET} '
        self.__error = f'{Colors.GRAY}[{Colors.RED}ERROR{Colors.GRAY}]{Colors.RESET} '
        self.__abord = f'{Colors.GRAY}[{Colors.RED}ABORT{Colors.GRAY}]{Colors.RESET} '
        self.__worked = f'{Colors.GRAY}[{Colors.GREEN}+{Colors.GRAY}]{Colors.RESET} '
        self.__notWorked = f'{Colors.GRAY}[{Colors.RED}-{Colors.GRAY}]{Colors.RESET} '

    def setOutputMode(self, simpleOutput: bool):
        """Set the display output mode, change labels
           By default, the app will use common output mode

        @type simpleOutput: bool
        @param simpleOutput: The simple output mode flag
        """
        if simpleOutput:
            self.__getTime = lambda: ''
            self.__info = f'{Colors.GRAY}[{Colors.BLUE_GRAY}*{Colors.GRAY}]{Colors.RESET} '
            self.__warning = f'{Colors.GRAY}[{Colors.YELLOW}!{Colors.GRAY}]{Colors.RESET} '
            self.__error = f'{Colors.GRAY}[{Colors.RED}!!{Colors.GRAY}]{Colors.RESET} '
            self.__abord = f'{Colors.GRAY}[{Colors.RED}AB{Colors.GRAY}]{Colors.RESET} '
            self.__worked = f'{Colors.GRAY}[{Colors.GREEN}+{Colors.GRAY}]{Colors.RESET} '
            self.__notWorked = f'{Colors.GRAY}[{Colors.RED}-{Colors.GRAY}]{Colors.RESET} '

    def setVerbosityMode(self, verboseMode: bool):
        """Set the verbosity mode

        @type verboseMode: bool
        @param verboseMode: The verbose mode flag
        """
        if verboseMode:
            self.__lock = None
            self.__breakLine = ''
        else:
            self.__lock = threading.Lock()
            self.__breakLine = '\n'

    def setMessageCallback(self, getMessageCallback: Callable):
        """Set the print content mode for the results

        @type getMessageCallback: Callable
        @param getMessageCallback: The get message callback for the results
        """
        self.__getMessage = getMessageCallback

    def infoBox(self, msg: str):
        """Print the message with a info label

        @type msg: str
        @param msg: The message
        """
        print(f'{self.__getTime()}{self.__getInfo(msg)}')

    def errorBox(self, msg: str):
        """End the application with error label and a message

        @type msg: str
        @param msg: The message
        """
        exit(f'{self.__getTime()}{self.__getError(msg)}')
 
    def warningBox(self, msg: str):
        """Print the message with a warning label

        @type msg: str
        @param msg: The message
        """
        print(f'{self.__getTime()}{self.__getWarning(msg)}')

    def abortBox(self, msg: str):
        """Print the message with abort label and a message

        @type msg: str
        @param msg: The message
        """
        if self.__lock:
            with self.__lock:
                sys.stdout.flush()
        print(f'{self.__breakLine}{self.__getTime()}{self.__getAbort(msg)}')

    def workedBox(self, msg: str):
        """Print the message with worked label and a message

        @type msg: str
        @param msg: The message
        """
        print(f'{self.__getTime()}{self.__getWorked(msg)}')

    def notWorkedBox(self, msg: str):
        """Print the message with not worked label and a message

        @type msg: str
        @param msg: The message
        """
        print(f"{self.__getTime()}{self.__getNotWorked(msg)}")

    def askYesNo(self, askType: str, msg: str):
        """Ask a question for the user

        @type askType: str
        @param askType: The type of the asker
        @type msg: str
        @param msg: The message
        @returns bool: The answer based on the user's input
        """
        if askType == 'warning':
            getType = self.__getWarning
        else:
            getType = self.__getInfo
        print(f"{self.__getTime()}{getType(msg)} (y/N) ", end='')
        action = input()
        if action == 'y' or action == 'Y':
            return True
        else:
            return False

    def askData(self, msg: str):
        """Ask data for the user

        @type msg: str
        @param msg: The message
        @returns mixed: The data asked
        """
        print(self.__getTime()+self.__getInfo(msg)+': ', end='')
        return input()

    def printConfig(self, key: str, value: str = '', spaces: int = 0):
        """The config's printer function

        @type key: str
        @param key: The name of the config
        @type value: str
        @param value: The value of that config
        @type spaces: int
        @param spaces: The number of spaces to indent the config output
        """
        print(f"{' '*(spaces+3)}{Colors.BLUE}{key}: {Colors.LIGHT_YELLOW}{value}{Colors.RESET}")

    def printConfigs(self,
        output: str,
        verbose: str,
        targets: list,
        dictionaries: list,
        prefix: list,
        suffix: list,
        case: str,
        encoder: tuple,
        match: dict,
        scanner: tuple,
        blacklistStatus: dict,
        delay: float,
        threads: int,
        report: str,
    ):
        """Prints the program configuration

        @type output: str
        @param output: The display output mode
        @type verbose: str
        @param verbose: The verbosity mode
        @type targets: list
        @param tagets: The targets list
        @type dictionaries: list
        @param dictionaries: The dictionaries used in the tests
        @type prefix: list
        @param prefix: The prefixes used with the payload
        @type suffix: list
        @param suffix: The suffixes used with the payload
        @type case: str
        @param case: The payload case
        @type encoder: tuple
        @param encoder: The encoder tuple that caontains the encoder name and parameters
        @type match: dict
        @param match: The matcher options on a dictionary
        @type scanner: tuple
        @param scanner: The scanner tuple that caontains the scanner name and parameters
        @type blacklistStatus: dict
        @param blacklistStatus: The blacklist status arguments (codes and action taken)
        @type delay: float
        @param delay: The delay between each request
        @type threads: int
        @param threads: The number of threads used in the tests
        @type report: str
        @param report: The report name and/or format
        """
        print("")
        globalDict = False
        if len(dictionaries) != len(targets):
            globalDict = True
            thisDict = dictionaries[0]
        spaces = 3
        self.printConfig("Output mode", output)
        self.printConfig("Verbosity mode", verbose)
        for i, target in enumerate(targets):
            self.printConfig("Target", getHost(getPureUrl(target['url'])))
            self.printConfig("Methods", stringfyList(target['methods']), spaces)
            self.printConfig("HTTP headers", 'custom' if target['header'] else 'default', spaces)
            if target['data']:
                self.printConfig("Body data", target['data'], spaces)
            self.printConfig("Fuzzing type", target['typeFuzzing'], spaces)
            if not globalDict:
                thisDict = dictionaries[i]
                self.printConfig("Dictionary size", thisDict['sizeof'], spaces)
                self.printConfig("Wordlists", stringfyList(thisDict['wordlists']), spaces)
        if globalDict:
            self.printConfig("Dictionary size", thisDict['sizeof'])
            self.printConfig("Wordlists", stringfyList(thisDict['wordlists']))
        if prefix:
            self.printConfig("Prefix", stringfyList(prefix))
        if suffix:
            self.printConfig("Suffix", stringfyList(suffix))
        if case:
            self.printConfig("Payload case", case)
        if encoder:
            encoder, params = encoder
            if params:
                encoder = f"{encoder}={params}"
            self.printConfig("Encoder", f"{encoder}")
        for key, value in match.items():
            if value:
                self.printConfig(f"Match {key}", value)
        if scanner:
            scanner, params = scanner
            if params:
                scanner = f"{scanner}={params}"
            self.printConfig("Scanner", f"{scanner}")
        if blacklistStatus:
            self.printConfig("Blacklisted status", f"{blacklistStatus['status']} with action {blacklistStatus['action']}")
        if delay:
            self.printConfig("Delay", f"{delay} seconds")
        self.printConfig("Threads", threads)
        if report:
            self.printConfig("Report", report)
        print("")

    def progressStatus(self,
        requestIndex: int,
        totalRequests: int,
        payload: str
    ):
        """Output the progress status of the fuzzing

        @type requestIndex: int
        @param requestIndex: The actual request index
        @type totalRequests: int
        @param totalRequests: The total of requests quantity
        @type payload: str
        @param payload: The payload used in the request
        """
        with self.__lock:
            if not self.__lastInline:
                self.__eraseLine()
                self.__lastInline = True
            status = f"{Colors.GRAY}[{Colors.LIGHT_GRAY}{requestIndex}{Colors.GRAY}/{Colors.LIGHT_GRAY}{totalRequests}{Colors.GRAY}]{Colors.RESET} {Colors.LIGHT_YELLOW}{str(int((int(requestIndex)/totalRequests)*100))}%{Colors.RESET}"
            payload = Colors.LIGHT_GRAY + fixPayloadToOutput(
                payload=payload,
                isProgressStatus=True
            )
            sys.stdout.flush()
            print('\r'+f"{self.__getTime()}{status}{Colors.GRAY} :: {payload}", end='')

    def printResult(self, result: dict, vulnValidator: bool):
        """Custom output print for box mode

        @type result: dict
        @param result: The result dictionary
        @type vulnValidator: bool
        @param vulnValidator: Case the output is marked as vulnerable
        """
        msg = self.__getMessage(result)
        if not vulnValidator:
            self.notWorkedBox(msg)
        else:
            if self.__lock:
                with self.__lock:
                    if self.__lastInline:
                        self.__eraseLine()
                        self.__lastInline = False
                    sys.stdout.flush()
            self.workedBox(msg)

    def __getTime(self):
        """Get a time label

        @returns str: The time label with format HH:MM:SS
        """
        time = datetime.now().strftime("%H:%M:%S")
        return f'{Colors.GRAY}[{Colors.LIGHT_GREEN}{time}{Colors.GRAY}]{Colors.RESET} '

    def __getInfo(self, msg: str):
        """The info getter, with a custom message

        @type msg: str
        @param msg: The custom message
        @returns str: The message with info label
        """
        return f'{self.__info}{msg}'

    def __getWarning(self, msg: str):
        """The warning getter, with a custom message

        @type msg: str
        @param msg: The custom message
        @returns str: The message with warning label
        """
        return f'{self.__warning}{msg}'
    
    def __getError(self, msg: str):
        """The error getter, with a custom message

        @type msg: str
        @param msg: The custom message
        @returns str: The message with error label
        """
        return f'{self.__error}{msg}'

    def __getAbort(self, msg: str):
        """The abort getter, with a custom message

        @type msg: str
        @param msg: The custom message
        @returns str: The message with abort label
        """
        return f'{self.__abord}{msg}'

    def __getWorked(self, msg: str):
        """The worked getter, with a custom message

        @type msg: str
        @param msg: The custom message
        @returns str: The message with worked label
        """
        return f'{self.__worked}{msg}'
    
    def __getNotWorked(self, msg: str):
        """The not worked getter, with a custom message

        @type msg: str
        @param msg: The custom message
        @returns str: The message with not worked label
        """
        return f'{self.__notWorked}{Colors.LIGHT_GRAY}{msg}{Colors.RESET}'

    def __eraseLine(self):
        """Erases the current line"""
        sys.stdout.flush()
        sys.stdout.write("\033[1K")
        sys.stdout.write("\033[0G")
        sys.stdout.flush()