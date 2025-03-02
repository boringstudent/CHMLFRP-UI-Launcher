# import requests
# from tqdm.auto import tqdm

# # 当前版本号（示例）
# current_version = "1.5.5"

# # API 请求
# api_url = "http://api.cul.chmlfrp.com/"
# response = requests.get(api_url)

# if response.status_code == 200:
#     data = response.json()
#     remote_version = data['version']
    
#     # 比较版本号
#     def compare_versions(current, remote):
#         current_parts = list(map(int, current.split('.')))
#         remote_parts = list(map(int, remote.split('.')))
#         for i in range(max(len(current_parts), len(remote_parts))):
#             cv = current_parts[i] if i < len(current_parts) else 0
#             rv = remote_parts[i] if i < len(remote_parts) else 0
#             if rv > cv:
#                 return True
#             elif rv < cv:
#                 return False
#         return False
    
#     if compare_versions(current_version, remote_version):
#         print(f"当前版本 {current_version} ，检测到新版本 {remote_version}，开始下载更新...")
        
#         # 获取下载链接列表
#         repositories = [
#             data['repository1'],
#             data['repository2'],
#             data['repository3'],
#             data['repository4'],
#             data['repository5']
#         ]
        
#         # 下载文件
#         downloaded = False
#         for repo in repositories:
#             download_url = repo.strip()
#             local_filename = download_url.split('/')[-1]
            
#             try:
#                 # 下载文件并显示进度条
#                 print(f"正在下载文件: {local_filename}")
#                 with requests.get(download_url, stream=True, timeout=10) as r:
#                     r.raise_for_status()
                    
#                     # 获取文件内容
#                     content = r.content
                    
#                     # 获取文件大小
#                     total_size = int(r.headers.get('content-length', 0))
                    
#                     # 显示进度条
#                     with tqdm(total=total_size, unit='B', unit_scale=True, unit_divisor=1024, desc=f"下载进度") as pbar:
#                         pbar.update(len(content))
                    
#                     # 保存文件
#                     with open(local_filename, 'wb') as f:
#                         f.write(content)
                    
#                     print(f"文件下载完成，保存为: {local_filename}")
#                     downloaded = True
#                     break  # 下载成功，退出循环
#             except Exception as e:
#                 print(f"下载失败，尝试下一个链接... 错误信息: {e}")
        
#         if not downloaded:
#             print("无法从任何下载链接获取更新文件，请稍后再试。")
#     else:
#         print(f"当前版本 {current_version} 是最新版本，无需更新。")
# else:
#     print(f"请求失败，状态码: {response.status_code}")

import requests
import urllib3
import socket
import re  # 用于版本号解析和比较
import os  # 用于文件操作

urllib3.disable_warnings()

dns_table = {
    "api.github.com": [
        "1.1.1.1",                # Cloudflare DNS
        "8.8.8.8",                # Google DNS
        "114.114.114.114",        # 阿里云 DNS
        "223.5.5.5",              # 阿里云
        "9.9.9.9"                # Quad9 DNS
    ]
}

def test_connectivity(ip, timeout=5):
    """
    测试 IP 地址的连通性
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, 443))
        sock.close()
        return result == 0
    except Exception as e:
        print(f"测试 {ip} 时出错: {e}")
        return False

def get_release_info(current_version):
    """
    获取最新版本信息并处理下载逻辑
    """
    try:
        # 目标域名
        target_domain = "api.github.com"
        for dns_server in dns_table[target_domain]:
            print(f"尝试使用 DNS 服务器 {dns_server} 解析 {target_domain}")
            # 获取目标域名的 IP 地址
            target_ip = socket.gethostbyname(target_domain)
            print(f"解析到的 IP 地址: {target_ip}")

            # 如果解析到回环地址，直接使用域名
            if target_ip in ["127.0.0.1", "0.0.0.0"]:
                url = f"https://{target_domain}/repos/boringstudents/CHMLFRP-UI-Launcher/releases/latest"
                break
            else:
                # 测试连通性
                if test_connectivity(target_ip):
                    print(f"IP 地址 {target_ip} 连接成功！")
                    url = f"https://{target_ip}/repos/boringstudents/CHMLFRP-UI-Launcher/releases/latest"
                    break
                else:
                    print(f"IP 地址 {target_ip} 连通性测试失败，尝试下一个 DNS 服务器。")
        else:
            raise Exception("所有 DNS 服务器解析的 IP 地址均无法连接！")

        # 设置请求头部，显式指定 Host
        headers = {
            "Host": target_domain
        }

        # 发送请求，跳过本地代理
        proxies = None
        response = requests.get(url, headers=headers, proxies=proxies, verify=False)
        response.raise_for_status()

        # 解析返回的 JSON 数据
        release_data = response.json()
        tag_name = release_data.get("tag_name")

        # 版本比较
        if compare_versions(current_version, tag_name):
            print(f"当前版本 {current_version} 需要升级到 {tag_name}")

            # 镜像前缀列表
            mirror_prefixes = [
                "gh.llkk.cc",
                "ghproxy.net",
                "gitproxy.click",
                "github.tbedu.top",
                "github.moeyy.xyz"
            ]

            # 遍历 assets 获取 browser_download_url 并生成不同前缀的镜像链接
            for asset in release_data.get("assets", []):
                original_url = asset.get("browser_download_url")
                if original_url:
                    # 生成所有镜像链接
                    mirror_urls = []
                    for prefix in mirror_prefixes:
                        mirror_url = f"https://{prefix}/{original_url}"
                        mirror_urls.append(mirror_url)

                    # 尝试下载各个镜像链接
                    download_success = False
                    new_filename = f"CUL{tag_name}.zip"  # 重命名的文件名
                    for url in mirror_urls:
                        try:
                            response = requests.get(url, stream=False, timeout=10)
                            response.raise_for_status()
                            with open(new_filename, "wb") as f:
                                f.write(response.content)
                            print(f"文件下载成功，已保存为 {new_filename}")
                            download_success = True
                            break
                        except Exception as e:
                            print(f"下载失败，尝试下一个镜像链接: {e}")
                    if download_success:
                        break
                    else:
                        print("所有镜像链接下载失败！")
                else:
                    print("未找到有效的下载链接")
        else:
            print(f"当前版本 {current_version} 已是最新版本，无需升级")

    except requests.exceptions.RequestException as e:
        print("请求失败：", e)

def compare_versions(current_version, latest_version):
    pattern = r"v?(\d+\.\d+\.\d+)"

    def parse_version(ver):
        match = re.match(pattern, ver)
        if match:
            return list(map(int, match.group(1).split(".")))
        else:
            return []

    current = parse_version(current_version)
    latest = parse_version(latest_version)

    if not current or not latest:
        print("版本号格式不正确")
        return False
    for c, l in zip(current, latest):
        if c < l:
            return True
        elif c > l:
            return False
    return len(current) < len(latest)

# 调用函数，假设当前版本是 1.5.5
get_release_info(current_version="1.5.5")
