import requests

# 请求接口
url = "https://xn--6orp08a.xn--v6qw21h0gd43u.xn--fiqs8s/v1/blacklist/list/all"
response = requests.get(url)

# 检查请求是否成功
if response.status_code == 200:
    data = response.json()
    # 遍历列表，获取邮箱和原因
    for item in data['data']['list']:
        email = item['email']
        reason = item['reason']
        print(f"邮箱: {email}, 原因: {reason}")
else:
    print("请求失败，状态码:", response.status_code)
