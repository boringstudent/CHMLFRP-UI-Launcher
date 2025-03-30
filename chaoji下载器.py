import requests
import threading
import os
from tqdm import tqdm
from urllib.parse import urlparse, parse_qs

class ThreadSafeTqdm:
    def __init__(self, total):
        self.total = total
        self.progress = 0
        self.lock = threading.Lock()
        self.pbar = tqdm(total=total, unit='B', unit_scale=True)

    def update(self, increment):
        with self.lock:
            self.progress += increment
            self.pbar.update(increment)

    def close(self):
        self.pbar.close()

def download_block(url, start, end, progress_bar, file_name):
    headers = {'Range': f'bytes={start}-{end}'}
    response = requests.get(url, headers=headers, stream=True)
    with open(file_name, 'r+b') as f:
        f.seek(start)
        for chunk in response.iter_content(chunk_size=8192):
            if chunk:
                f.write(chunk)
                progress_bar.update(len(chunk))

def multi_thread_download(url, num_threads):
    try:
        response = requests.head(url)
        response.raise_for_status()  # 检查响应状态码是否为200
    except requests.RequestException as e:
        print(f"请求失败: {e}")
        return

    if 'Content-Length' not in response.headers:
        print("服务器未返回Content-Length头信息，无法进行分块下载。")
        return

    file_size = int(response.headers['Content-Length'])
    block_size = file_size // num_threads

    # 提取文件名
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    file_name = query_params.get('filename', [None])[0]
    if not file_name:
        file_name = os.path.basename(parsed_url.path)

    # 创建空文件
    with open(file_name, 'wb') as f:
        f.seek(file_size - 1)
        f.write(b'\0')

    # 创建线程安全的进度条
    progress_bar = ThreadSafeTqdm(total=file_size)

    threads = []
    for i in range(num_threads):
        start = i * block_size
        end = start + block_size - 1 if i < num_threads - 1 else file_size - 1
        thread = threading.Thread(target=download_block, args=(url, start, end, progress_bar, file_name))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    progress_bar.close()
    print(f"Download completed: {file_name}")

if __name__ == "__main__":
    url = input("请输入文件下载链接: ")
    num_threads = int(input("请输入线程数: "))
    multi_thread_download(url, num_threads)
