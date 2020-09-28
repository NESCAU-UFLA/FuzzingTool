def writeOnFile(outputFile: object, i: str, value: str, status: str, requestLength: str, requestTime: str):
    outputFile.write("Request: "+i+"\n")
    outputFile.write("Param value: "+value+"\n")
    outputFile.write("Status code: "+status+"\n")
    outputFile.write("Length: "+requestLength+"\n")
    outputFile.write("Time taken: "+requestTime+" seconds\n\n")

class OutputHandler:
    def __init__(self):
        self.__info = '\033[90m['+'\033[36mINFO'+'\033[90m] \033[0m'
        self.__warning = '\033[90m['+'\033[33mWARNING'+'\033[90m] \033[0m'
        self.__error = '\033[90m['+'\u001b[31;1mERROR'+'\033[90m] \033[0m'

    def getInfo(self, msg: str):
        return self.__info + msg

    def getWarning(self, msg: str):
        return self.__warning + msg
    
    def getError(self, msg: str):
        return self.__error + msg

    def getInitOrEnd(self):
        print('  +'+('-'*9)+'+'+('-'*32)+'+'+('-'*8)+'+'+('-'*10)+'+'+('-'*12)+'+')

    def getHeader(self):
        self.getInitOrEnd()
        self.printContent(['Request', 'Data Send', 'Status', 'Length', 'Time'], False)
        self.getInitOrEnd()

    def printContent(self, args: list, vulnValidator: bool):
        if (not vulnValidator):
            print('  | '+'{:<7}'.format(args[0])+' | '+'{:<30}'.format(args[1])+' | '+'{:<6}'.format(args[2])+' | '+'{:<8}'.format(args[3])+' | '+'{:<10}'.format(args[4])+' |')
        else:
            print('  | '+u'\u001b[32;1m{:<7}'.format(args[0])+'\033[0m | '+'\u001b[32;1m{:<30}'.format(args[1])+'\033[0m | '+'\u001b[32;1m{:<6}'.format(args[2])+'\033[0m | '+'\u001b[32;1m{:<8}'.format(args[3])+'\033[0m | '+'\u001b[32;1m{:<10}'.format(args[4])+'\033[0m |')

    def askYesNo(self, msg: str):
        action = input(self.getWarning(msg))
        if (action == 'y' or action == 'Y'):
            return True
        else:
            return False
    
    def infoBox(self, msg: str):
        print(self.getInfo(msg))

    def errorBox(self, msg: str):
        exit(self.getError(msg))

    def fixLineToOutput(self, line: str):
        if (len(line) > 30):
            output = ""
            for i in range(27):
                output += line[i]
            output += '...'
            return output
        else:
            return line

    def progressStatus(self, status: str):
        print('\r'+self.getInfo("Progress status: "+'{:<4}'.format(status+'%')+' completed'), end='')

oh = OutputHandler()