# FuzzyingTool
FuzzyingTool is a web penetration testing tool, that handles with fuzzing. At now, GET and POST are the parameters that you can send data from a file. After the test is completed, all possible vulnerable entries (and the request) are saved on an output file. For examples, see <a href="#usage-examples">Usage Examples</a>.
<br/><br/>
This application was made under python v3.6.9.

## Disclaimer
We're not responsible for the misuse of this tool. This project was created for educational purposes and should not be used in environments without legal authorization.

## Getting Started
Before we start the *penetration testings*, take a look at the **prerequisites** and **installing**.

### Prerequisites
* Install the requests python package
```
$ pip install requests
```

### Installing
First, download the last release or clone this repository. Give read and write permissions to the installed folder before start the tests. Run the tests into `src` directory.

### List of Execution Parameters
 * `-h, --help`: Display the help menu and exit;
 * `-V, --verbose`: Enable the verbose mode;
 * `-u URL`: Define the target URL;
 * `-f FILENAME`: Define the entry wordlist file;
 * `--data DATA`: Define the POST data;
 * `--proxy IP:PORT`: Define the proxy;
 * `--proxies FILENAME`: Define the file that reads a list of proxies;
 * `--cookie COOKIE`: Define the HTTP Cookie header value;
 * `--delay DELAY`: Define the delay between each request.

### Usage Examples
On this example, you set the GET variable 'id' as an entry for the fuzzing test. The parameter values are read from the file 'sqli.txt'.
```
$ python3 FuzzyingTool.py -u http://mydomainexample.com/post.php?id= -f sqli.txt
```

On this example, you set the POST variables 'login' and 'passw' as entries for the fuzzing test; and also sets the fixed value 'login' for 'user' variable.
```
$ python3 FuzzyingTool.py -f sqli.txt -u http://mydomainexample.com/controller/user.php --data 'login&passw&user=login'
```

## Versioning
We use <a target="_blank" href="https://semver.org/">SemVer</a> for versioning. For the versions available, see the <a target="_blank" href="https://github.com/NESCAU-UFLA/FuzzyingTool/releases">tags on this repository</a>.

## Authors
* <b>Vitor Oriel</b> - <a target="_blank" href="https://github.com/VitorOriel">Profile</a>

## License
This project is licensed under the MIT License - see the <a target="_blank" href="https://github.com/NESCAU-UFLA/FuzzyingTool/blob/master/LICENSE.md">LICENSE.md</a> for details.