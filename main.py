import sys
from FuzzyTool import FuzzyTool

"""url = 'http://127.0.0.1/VulnerableWebApp/view/post.php'
params = {'id': '9 AND SLEEP(10);--'}
cookies = {'PHPSESSID': 'vk3emhub0v3kqdcu2v6q8bbv2e'}
r = r.get(url, params=params, cookies=cookies)
print(r.elapsed.total_seconds())"""

def main(argv):
    if (len(argv) < 2):
        print("Formato inválido! Siga um dos formatos a seguir:\n")
        print("python3 main.py <nome-do-arquivo>\n")
        print("Plota a matriz original:")
        print("python3 main.py <nome-do-arquivo> -o\n")
        print("Arquivos devem ser retirados de: https://sparse.tamu.edu/")
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
    fuzz = FuzzyTool(method)
    fuzz.setUrl(url)
    fuzz.setArgs(args)
    if ('--cookie' in argv):
        index = argv.index('--cookie')
        cookie = argv[index+1].split('=')
        cookie = {cookie[0]: cookie[1]}
        fuzz.setCookie(cookie)
    fuzz.start(fileName)

    """
    try:
        arquivo = open(argv[1], 'r')
    except FileNotFoundError as e:
        exit("Arquivo '"+argv[1]+"' nao encontrado . . .")
    """

if __name__ == "__main__":
   main(sys.argv)