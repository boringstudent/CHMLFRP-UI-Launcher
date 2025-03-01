import requests
import urllib3
import socket

urllib3.disable_warnings()

dns_table = {
    "api.github.com": [
        "1.1.1.1",                # Cloudflare DNS
        "8.8.8.8",                # Google DNS
        "208.67.222.222",         # OpenDNS
        "114.114.114.114",        # 阿里云 DNS
        "119.29.29.29",           # DNSPod
        "223.5.5.5",              # 阿里云 DNS（备用）
        "223.6.6.6",              # 阿里云 DNS（备用）
        "9.9.9.9",                # Quad9 DNS
        "94.140.14.14",           # AdGuard DNS
        "208.67.220.220",         # OpenDNS（备用）
        "1.0.0.1",                # Cloudflare DNS（备用）
        "8.8.4.4",                # Google DNS（备用）
        "114.114.115.115"         # 114DNS（备用）
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

def get_release_info():
    try:
        # 目标域名
        target_domain = "api.github.com"

        # 遍历 DNS 表中的 DNS 服务器，解析 IP 地址
        for dns_server in dns_table[target_domain]:
            print(f"尝试使用 DNS 服务器 {dns_server} 解析 {target_domain}")
            # 设置 DNS 服务器（需要手动设置 socket 的 DNS 服务器）
            resolver = socket.getaddrinfo(target_domain, 443, family=socket.AF_INET, type=socket.SOCK_STREAM)
            target_ip = resolver[0][4][0]  # 获取第一个解析结果的 IP 地址
            print(f"解析到的 IP 地址: {target_ip}")

            # 如果解析到回环地址，直接使用域名
            if target_ip in ["127.0.0.1", "0.0.0.0"]:
                print(f"解析到回环地址 {target_ip}，直接使用域名 {target_domain}")
                url = f"https://{target_domain}/repos/boringstudents/CHMLFRP-UI-Launcher/releases/latest"
                break
            else:
                # 测试连通性
                if test_connectivity(target_ip):
                    print(f"IP 地址 {target_ip} 连通性测试成功！")
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
        print("tag_name:", tag_name)

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
                for prefix in mirror_prefixes:
                    mirror_url = f"https://{prefix}/{original_url}"
                    print(mirror_url)

    except requests.exceptions.RequestException as e:
        print("请求失败：", e)

# 调用函数
get_release_info()
