<h1 align="center">FuzzingTool</h1>
<p align="center">
  <a href="https://github.com/NESCAU-UFLA/FuzzingTool/releases/tag/v3.6.0">
    <img src="https://img.shields.io/static/v1?label=Release&message=v3.6.2&color=darkred" />
  </a>
  <img src="https://img.shields.io/static/v1?label=python&message=v3.6.9&color=informational&logo=python" />
  <a href="https://github.com/NESCAU-UFLA/FuzzingTool/blob/master/LICENSE.md">
    <img src="https://img.shields.io/static/v1?label=License&message=MIT&color=brightgreen" />
  </a>
</p>

FuzzingTool is a web penetration testing tool, that handles with fuzzing. After the test is completed, all possible vulnerable entries (and the response data) are saved on a report file. For examples, see <a href="#usage-examples">Usage Examples</a>.
<br/>

## Disclaimer
We're not responsible for the misuse of this tool. This project was created for educational purposes and should not be used in environments without legal authorization.

## Getting Started
Before we start the *penetration testings*, take a look at the **prerequisites** and **installing**.

### Supported OS
| OS | Supported |
| :--- | :---: |
| Windows | Yes |
| Linux | Yes |
| MacOS | Not tested |

### Prerequisites
* Install the requests python package
```
$ pip install requests
```
* If you are using Windows, please install the colorama too
```
$ pip install colorama
```

### Installing
First, download the last release or clone this repository. Give read and write permissions to the installed folder before start the tests. Run the tests into `src` directory.

### List of Execution Parameters
| Argument | Required | Description | Default |
| :--- | :---: | :--- | :---: |
| `-h, --help` | Misc | Show the help menu and exit | |
| `-v, --version` | Misc | Show the current version and exit | |
| `-r` | Yes/No | Define the file with the request data (including target) | |
| `--scheme` | No | Define the scheme used in the URL | http |
| `-u` | Yes/No | Define the target URL | |
| `--data` | Yes/No | Define the POST data | |
| `--proxy` | No | Define the proxy | |
| `--proxies` | No | Define the file with a list of proxies | |
| `--cookie` | No | Define the HTTP Cookie header value | |
| `--timeout` | No | Define the request timeout | None |
| `-f` | Yes | Define the wordlist file with the payloads | |
| `--prefix` | No | Define the prefix used with payload |  |
| `--suffix` | No | Define the suffix used with payload |  |
| `--upper` | No | Set the uppercase flag for the payloads | |
| `--lower` | No | Set the lowercase flag for the payloads | |
| `--capitalize` | No | Set the capitalize flag for the payloads | |
| `-V, --verbose` | No | Enable the verbose mode | |
| `--delay` | No | Define the delay between each request | 0 |
| `-t` | No | Define the number of threads used in the tests | 1 |
| `--allowed-status` | No | Define the allowed status codes for responses to be saved on report | 200 |
| `-o` | No | Define the report format | txt |

### Usage Examples
#### Data Fuzzing
On this example, you set the GET variable 'id' as an entry for the fuzzing test. The parameter values are read from the file 'sqli.txt'.
```
$ ./FuzzingTool.py -u http://mydomainexample.com/post.php?id= -f sqli.txt -o blind_sqli.csv
```

On this example, you set the POST variables 'login' and 'passw' as entries for the fuzzing test; and also sets the fixed value 'login' for 'user' variable.
```
$ ./FuzzingTool.py -f sqli.txt -u http://mydomainexample.com/controller/user.php --data 'login&passw&user=login'
```

#### URL Fuzzing
You can set the payload mode on URL for the fuzzing test. It's based on the variable '$' position.

Example for path scanning (added suffixes to the payload):
```
$ ./FuzzingTool.py -f paths.txt -u http://mydomainexample.com/$ --suffix .php,.html
```
Example for subdomain scanning:
```
$ ./FuzzingTool.py -f subdomains.txt -u http://$.mydomainexample.com/ --timeout 4 -V -o subdomains.json
```

#### Reading raw HTTP request
On this example, you can read the request content (headers, target, data and method) from a file.
```
$ ./FuzzingTool.py -r data.txt -f sqli.txt -V
```

Here we've two examples of request format. The first one is about the raw data sended to server during the request
```
POST /controller/user.php HTTP/1.1
Host: localhost
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:85.0) Gecko/20100101 Firefox/85.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 40
Origin: http://localhost
Connection: keep-alive
Referer: http://localhost/index.php
Cookie: PHPSESSID=agkkekwsukpvurjmfcasaslj61l
Upgrade-Insecure-Requests: 1

User=Login&Login=usr&Pass=usr
```

This other is a modified version of the Raw, to be readable for the FuzzingTool. Note that the POST data was changed, and removed the Cookie from the HTTP Header (we don't want to send the Cookie as part of the request on this example).
```
POST /controller/user.php HTTP/1.1
Host: localhost
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:85.0) Gecko/20100101 Firefox/85.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 40
Origin: http://localhost
Connection: keep-alive
Referer: http://localhost/index.php
Upgrade-Insecure-Requests: 1

User=Login&Login&Pass
```

## Versioning
We use <a target="_blank" href="https://semver.org/">SemVer</a> for versioning. For the versions available, see the <a target="_blank" href="https://github.com/NESCAU-UFLA/FuzzingTool/releases">tags on this repository</a>.

## Authors
* <b>Vitor Oriel</b> - <a target="_blank" href="https://github.com/VitorOriel">Profile</a>

## License
This project is licensed under the MIT License - see the <a target="_blank" href="https://github.com/NESCAU-UFLA/FuzzingTool/blob/master/LICENSE.md">LICENSE.md</a> for details.
