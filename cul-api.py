import requests
from tqdm.auto import tqdm

# 当前版本号（示例）
current_version = "1.5.5"

# API 请求
api_url = "http://api.cul.chmlfrp.com/"
response = requests.get(api_url)

if response.status_code == 200:
    data = response.json()
    remote_version = data['version']
    
    # 比较版本号
    def compare_versions(current, remote):
        current_parts = list(map(int, current.split('.')))
        remote_parts = list(map(int, remote.split('.')))
        for i in range(max(len(current_parts), len(remote_parts))):
            cv = current_parts[i] if i < len(current_parts) else 0
            rv = remote_parts[i] if i < len(remote_parts) else 0
            if rv > cv:
                return True
            elif rv < cv:
                return False
        return False
    
    if compare_versions(current_version, remote_version):
        print(f"当前版本 {current_version} ，检测到新版本 {remote_version}，开始下载更新...")
        
        # 获取下载链接列表
        repositories = [
            data['repository1'],
            data['repository2'],
            data['repository3'],
            data['repository4'],
            data['repository5']
        ]
        
        # 下载文件
        downloaded = False
        for repo in repositories:
            download_url = repo.strip()
            local_filename = download_url.split('/')[-1]
            
            try:
                # 下载文件并显示进度条
                print(f"正在下载文件: {local_filename}")
                with requests.get(download_url, stream=True, timeout=10) as r:
                    r.raise_for_status()
                    
                    # 获取文件内容
                    content = r.content
                    
                    # 获取文件大小
                    total_size = int(r.headers.get('content-length', 0))
                    
                    # 显示进度条
                    with tqdm(total=total_size, unit='B', unit_scale=True, unit_divisor=1024, desc=f"下载进度") as pbar:
                        pbar.update(len(content))
                    
                    # 保存文件
                    with open(local_filename, 'wb') as f:
                        f.write(content)
                    
                    print(f"文件下载完成，保存为: {local_filename}")
                    downloaded = True
                    break  # 下载成功，退出循环
            except Exception as e:
                print(f"下载失败，尝试下一个链接... 错误信息: {e}")
        
        if not downloaded:
            print("无法从任何下载链接获取更新文件，请稍后再试。")
    else:
        print(f"当前版本 {current_version} 是最新版本，无需更新。")
else:
    print(f"请求失败，状态码: {response.status_code}")
