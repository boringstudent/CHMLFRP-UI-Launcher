import requests
import json
import urllib3

# 禁用所有 urllib3 的警告
urllib3.disable_warnings()

def get_release_info():
    try:
        # 发送请求获取最新版本信息
        response = requests.get("https://api.github.com/repos/boringstudents/CHMLFRP-UI-Launcher/releases/latest", verify=False)
        response.raise_for_status()

        # 解析返回的 JSON 数据
        release_data = response.json()

        # 获取 tag_name
        tag_name = release_data.get("tag_name")
        print("tag_name:", tag_name)

        # 遍历 assets 获取 browser_download_url
        for asset in release_data.get("assets", []):
            browser_download_url = asset.get("browser_download_url")
            if browser_download_url:
                print("browser_download_url:", browser_download_url)

    except requests.exceptions.RequestException as e:
        print("请求失败：", e)

# 调用函数
get_release_info()
