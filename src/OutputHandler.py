class OutputHandler:
    """Class that handle with the outputs
    
    Attributes:
        info: The info label
        warning: The warning label
        error: The error label
    """
    def __init__(self):
        """Class constructor"""
        self.__info = '\033[90m['+'\033[36mINFO'+'\033[90m] \033[0m'
        self.__warning = '\033[90m['+'\033[33mWARNING'+'\033[90m] \033[0m'
        self.__error = '\033[90m['+'\u001b[31;1mERROR'+'\033[90m] \033[0m'

    def getInfo(self, msg: str):
        """The info getter, with a custom message

        @param type: str
        @param msg: The custom message
        @returns str: The message with info label
        """
        return self.__info + msg

    def getWarning(self, msg: str):
        """The warning getter, with a custom message

        @param type: str
        @param msg: The custom message
        @returns str: The message with warning label
        """
        return self.__warning + msg
    
    def getError(self, msg: str):
        """The error getter, with a custom message

        @param type: str
        @param msg: The custom message
        @returns str: The message with error label
        """
        return self.__error + msg

    def getInitOrEnd(self):
        """Output the initial line of the requests table"""
        print('  +'+('-'*9)+'+'+('-'*32)+'+'+('-'*8)+'+'+('-'*10)+'+'+('-'*12)+'+')

    def getHeader(self):
        """Output the header of the requests table"""
        self.getInitOrEnd()
        self.printContent(['Request', 'Data Send', 'Status', 'Length', 'Time'], False)
        self.getInitOrEnd()

    def printContent(self, args: list, vulnValidator: bool):
        """Output the content of the requests table

        @param type: list
        @param args: The arguments used in the table content
        @param type: bool
        @param vulnValidator: Case the output is marked as vulnerable
        """
        if (not vulnValidator):
            print('  | '+'{:<7}'.format(args[0])+' | '+'{:<30}'.format(args[1])+' | '+'{:<6}'.format(args[2])+' | '+'{:<8}'.format(args[3])+' | '+'{:<10}'.format(args[4])+' |')
        else:
            print('  | '+u'\u001b[32;1m{:<7}'.format(args[0])+'\033[0m | '+'\u001b[32;1m{:<30}'.format(args[1])+'\033[0m | '+'\u001b[32;1m{:<6}'.format(args[2])+'\033[0m | '+'\u001b[32;1m{:<8}'.format(args[3])+'\033[0m | '+'\u001b[32;1m{:<10}'.format(args[4])+'\033[0m |')

    def askYesNo(self, msg: str):
        """Output an warning message, and ask for the user if wants to continue

        @param type: str
        @param msg: The message
        @returns bool: The answer based on the user's input
        """
        action = input(self.getWarning(msg))
        if (action == 'y' or action == 'Y'):
            return True
        else:
            return False
    
    def infoBox(self, msg: str):
        """Print the message with a info label

        @param type: str
        @param msg: The message
        """
        print(self.getInfo(msg))

    def errorBox(self, msg: str):
        """End the application with error label and a message

        @param type: str
        @param msg: The message
        """
        exit(self.getError(msg))
 
    def fixLineToOutput(self, line: str):
        """Fix the line's size readed by the file

        @param type: str
        @param line: The line from the file
        @returns str: The fixed line to output
        """
        if (len(line) > 30):
            output = ""
            for i in range(27):
                output += line[i]
            output += '...'
            return output
        else:
            return line

    def progressStatus(self, status: str):
        """Output the progress status of the fuzzing

        @param type: str
        @param status: The status progress of the fuzzing (between 0 to 100)
        """
        print('\r'+self.getInfo("Progress status: "+'{:<4}'.format(status+'%')+' completed'), end='')

    def helpTitle(self, numSpaces: int, title: str):
        """Output the help title

        @param type: int
        @param numSpaces: The number of spaces before the title
        @param type: str
        @param title: The title or subtitle
        """
        print("\n"+' '*numSpaces+title)

    def helpContent(self, numSpaces: int, command: str, desc: str):
        """Output the help content

        @param type: int
        @param numSpaces: The number of spaces before the content
        @param type: str
        @param command: The command to be used in the execution argument
        @param type: str
        @param desc: The description of the command
        """
        print(' '*numSpaces+("{:<"+str(26-numSpaces)+"}").format(command)+' '+desc)

    def writeOnFile(self, outputFile: object, i: str, value: str, status: str, requestLength: str, requestTime: str):
        """Write the vulnerable input and request content into a file

        @param type: object
        @param outputFile: The output file
        @param type: str
        @param i: The request index
        @param type: str
        @param value: The request parameter input
        @param type: str
        @param status: The request status
        @param type: str
        @param requestLength: The request length
        @param type: str
        @param requestTime: The request time
        """
        outputFile.write("Request: "+i+"\n")
        outputFile.write("Param value: "+value+"\n")
        outputFile.write("Status code: "+status+"\n")
        outputFile.write("Length: "+requestLength+"\n")
        outputFile.write("Time taken: "+requestTime+" seconds\n\n")

oh = OutputHandler() # The object used in the files that imports this file