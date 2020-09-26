import sys
from RequestHandler import RequestHandler

def main(argv):
    if (len(argv) < 2):
        print("Invalid format! Type -h to show the help menu.")
        exit(0)
    try:
        index = argv.index('-u')
    except ValueError as e:
        exit('Need an URL to make the fuzzying')
    args = []
    try:
        url, get = argv[index+1].split('?', 1)
        if ('=' in get):
            get = get.split('=')[0]
        args.append(get)
        method = 'GET'
    except ValueError as e:
        url = argv[index+1]
        method = 'POST'
    try:
        index = argv.index('-f')
        fileName = argv[index+1]
    except ValueError as e:
        exit('Need an file to make the fuzzying')
    rh = RequestHandler(url, method, args)
    if ('--cookie' in argv):
        index = argv.index('--cookie')
        cookie = argv[index+1].split('=')
        cookie = {cookie[0]: cookie[1]}
        rh.setCookie(cookie)
    proxiesFileName = ""
    if ('--proxies' in argv):
        index = argv.index('--proxies')
        proxiesFileName = argv[index+1]
    rh.start(fileName, proxiesFileName)

if __name__ == "__main__":
   main(sys.argv)