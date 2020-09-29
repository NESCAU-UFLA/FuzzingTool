# FuzzyingTool


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
First, download the last release or clone this repository. Give read and write permissions to the installed folder before start the tests.

### Usage examples
On this example, you set the GET variable 'id' as an entry for the fuzzying test. The parameter values are read from the file 'sqli.txt'.
```
$ python3 FuzzyingTool.py -u http://mydomainexample.com/post.php?id= -f sqli.txt
```

On this example, you set the POST variables 'login' and 'passw' as entries for the fuzzying test; and also sets the fixed value 'login' for 'user' variable.
```
$ python3 FuzzyingTool.py -f sqli.txt -u http://mydomainexample.com/controller/user.php --data 'login&passw&user=login'
```

## Authors
* <b>Vitor Oriel</b> - <a target="_blank" href="https://github.com/VitorOriel">Profile</a>