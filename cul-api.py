import requests
import urllib3
import socket
import re
from tqdm import tqdm
from dns.resolver import Resolver, NoNameservers, NXDOMAIN, NoAnswer, Timeout

urllib3.disable_warnings()

# 全局配置
DNS_CONFIG = {
    "servers": [
        "1.1.1.1",  # Cloudflare
        "8.8.8.8",  # Google
        "114.114.114.114",  # 114DNS
        "223.5.5.5",  # AliDNS
        "9.9.9.9"  # Quad9
    ],
    "timeout": 5,
    "domain": "api.github.com"
}

MIRROR_PREFIXES = [

    "github.tbedu.top", #3mb
    "gitproxy.click", #2-3mb
    "github.moeyy.xyz", #5mb
    "ghproxy.net", #4mb
    "gh.llkk.cc", #3mb

]

DOWNLOAD_TIMEOUT = 10


def setup_dns_resolver():
    """配置自定义DNS解析器"""
    resolver = Resolver()
    resolver.nameservers = DNS_CONFIG["servers"]
    resolver.lifetime = DNS_CONFIG["timeout"]
    return resolver


def resolve_dns(resolver, domain):
    """使用自定义DNS解析域名"""
    try:
        answer = resolver.resolve(domain, 'A')
        return [str(r) for r in answer]
    except (NoNameservers, NXDOMAIN, NoAnswer, Timeout) as e:
        print(f"DNS解析失败: {type(e).__name__} - {str(e)}")
        return []


def test_connectivity(ip, port=443, timeout=5):
    """测试IP:Port连通性"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        return result == 0
    except Exception as e:
        print(f"连接测试失败 [{ip}]: {str(e)}")
        return False
    finally:
        try:
            sock.close()
        except:
            pass


def find_working_ip(domain):
    """寻找可用的IP地址"""
    resolver = setup_dns_resolver()
    ips = resolve_dns(resolver, domain)

    if not ips:
        print("所有DNS服务器均无法解析域名")
        return domain  # 回退到域名

    for ip in ips:
        if test_connectivity(ip):
            print(f"可用IP: {ip}")
            return ip

    print("所有IP均不可用，回退到域名")
    return domain


def build_request_url(endpoint):
    """构建请求URL"""
    if re.match(r"\d+\.\d+\.\d+\.\d+", endpoint):
        return (
            f"https://{endpoint}/repos/boringstudents/CHMLFRP-UI-Launcher/releases/latest",
            {"Host": DNS_CONFIG["domain"]}
        )
    return (
        f"https://{endpoint}/repos/boringstudents/CHMLFRP-UI-Launcher/releases/latest",
        {}
    )


def fetch_release_data(url, headers):
    """获取版本发布信息"""
    try:
        response = requests.get(
            url,
            headers=headers,
            proxies=None,
            verify=False,
            timeout=DNS_CONFIG["timeout"]
        )
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        print(f"请求失败: {str(e)}")
        raise


def parse_version(version_str):
    """解析版本号字符串"""
    match = re.match(r"v?(\d+)(?:\.(\d+))?(?:\.(\d+))?", version_str)
    if not match:
        return ()
    return tuple(int(x) if x else 0 for x in match.groups())


def is_newer_version(current, latest):
    """比较版本号"""
    current_ver = parse_version(current)
    latest_ver = parse_version(latest)
    return latest_ver > current_ver


def generate_mirror_urls(original_url):
    """生成镜像站URL列表"""
    return [f"https://{prefix}/{original_url}" for prefix in MIRROR_PREFIXES]


def download_with_tqdm(url, filename):
    """使用tqdm进度条下载文件"""
    try:
        response = requests.get(
            url,
            stream=True,
            timeout=DOWNLOAD_TIMEOUT,
            allow_redirects=True
        )
        response.raise_for_status()

        total_size = int(response.headers.get('content-length', 0))

        with open(filename, 'wb') as f:
            with tqdm(
                    total=total_size,
                    unit='B',
                    unit_scale=True,
                    unit_divisor=1024,
                    desc=f"下载 {filename}",
                    ncols=80,
                    miniters=1
            ) as pbar:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        pbar.update(len(chunk))

        return True
    except Exception as e:
        print(f"\n下载失败: {str(e)}")
        return False


def download_with_retry(urls, filename, max_retries=3):
    """带重试的下载功能"""
    for attempt in range(max_retries):
        for url in urls:
            try:
                print(f"尝试下载 [{attempt + 1}/{max_retries}]: {url}")
                if download_with_tqdm(url, filename):
                    print(f"下载成功: {filename}")
                    return True
            except Exception as e:
                print(f"下载失败: {str(e)}")
    return False


def process_update(current_version):
    """处理更新流程"""
    try:
        # 1. 解析可用端点
        endpoint = find_working_ip(DNS_CONFIG["domain"])

        # 2. 构建请求
        url, headers = build_request_url(endpoint)

        # 3. 获取发布信息
        release_data = fetch_release_data(url, headers)
        latest_version = release_data["tag_name"]

        # 4. 版本比较
        if not is_newer_version(current_version, latest_version):
            print(f"当前版本 {current_version} 已是最新")
            return False

        print(f"发现新版本: {latest_version}")

        # 5. 处理资源下载
        for asset in release_data.get("assets", []):
            if not asset.get("browser_download_url"):
                continue

            mirror_urls = generate_mirror_urls(asset["browser_download_url"])
            filename = f"CUL{latest_version}.zip"

            if download_with_retry(mirror_urls, filename):
                print("更新下载完成")
                return True

        print("所有下载尝试均失败")
        return False

    except Exception as e:
        print(f"更新流程异常: {str(e)}")
        return False


# 使用示例
if __name__ == "__main__":
    process_update("1.5.5")
