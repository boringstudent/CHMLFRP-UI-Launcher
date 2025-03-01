import requests
import json

url = "http://api.cul.chmlfrp.com/"
response = requests.get(url)

if response.status_code == 200:
    data = response.json()
    print(data['version'])
else:
    print(f"请求失败，状态码: {response.status_code}")
