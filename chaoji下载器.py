import requests
import threading
import os
from tqdm import tqdm
from urllib.parse import urlparse, parse_qs
import time
import math
from concurrent.futures import ThreadPoolExecutor, as_completed


class ThreadSafeTqdm:
    def __init__(self, total):
        self.total = total
        self.progress = 0
        self.lock = threading.Lock()
        self.pbar = tqdm(total=total, unit='B', unit_scale=True, unit_divisor=1024)
        self.last_update_time = time.time()
        self.last_progress = 0
        self.speed = 0

    def update(self, increment):
        with self.lock:
            self.progress += increment
            self.pbar.update(increment)

            current_time = time.time()
            time_elapsed = current_time - self.last_update_time
            if time_elapsed >= 1.0:
                progress_diff = self.progress - self.last_progress
                self.speed = progress_diff / time_elapsed / (1024 * 1024)
                self.last_progress = self.progress
                self.last_update_time = current_time

    def close(self):
        self.pbar.close()


def download_block(url, start, end, progress_bar, file_name, retries=3):
    headers = {'Range': f'bytes={start}-{end}'}
    for attempt in range(retries):
        try:
            response = requests.get(url, headers=headers, stream=True, timeout=30)
            response.raise_for_status()

            # Check if server actually supports range requests
            if response.status_code == 206:  # Partial Content
                with open(file_name, 'r+b') as f:
                    f.seek(start)
                    for chunk in response.iter_content(chunk_size=64 * 1024):
                        if chunk:
                            f.write(chunk)
                            progress_bar.update(len(chunk))
                return True
            elif response.status_code == 200:  # Full Content
                # Server doesn't support range requests, fall back to single thread
                return False
            else:
                raise Exception(f"Unexpected status code: {response.status_code}")

        except Exception as e:
            if attempt == retries - 1:
                print(f"\n下载块 {start}-{end} 失败: {e}")
                return False
            time.sleep(2 ** attempt)
    return False


def multi_thread_download(url, initial_num_threads=10, max_threads=100):
    try:
        # 获取文件信息
        response = requests.head(url, allow_redirects=True, timeout=10)
        response.raise_for_status()

        if 'Content-Length' not in response.headers:
            print("服务器未返回Content-Length头信息，尝试单线程下载...")
            return single_thread_download(url)

        file_size = int(response.headers['Content-Length'])

        # 获取文件名
        content_disposition = response.headers.get('Content-Disposition', '')
        if 'filename=' in content_disposition:
            file_name = content_disposition.split('filename=')[1].strip('"\'')
        else:
            file_name = os.path.basename(urlparse(url).path)

        if not file_name:
            file_name = f"download_{int(time.time())}.bin"

        print(f"开始下载: {file_name} (大小: {file_size / 1024 / 1024:.2f} MB)")

        # 创建空文件
        with open(file_name, 'wb') as f:
            f.truncate(file_size)

        progress_bar = ThreadSafeTqdm(total=file_size)
        start_time = time.time()

        # 测试服务器是否支持范围请求
        test_response = requests.get(url, headers={'Range': 'bytes=0-1'}, stream=True)
        if test_response.status_code != 206:
            print("服务器不支持范围请求，转为单线程下载")
            return single_thread_download(url, file_name, progress_bar)

        # 动态调整线程数
        optimal_threads = min(initial_num_threads, max_threads, math.ceil(file_size / (1024 * 1024)))  # 每MB一个线程
        block_size = max(file_size // optimal_threads, 1 * 1024 * 1024)  # 每个块至少1MB

        with ThreadPoolExecutor(max_workers=optimal_threads) as executor:
            futures = {}
            for i in range(optimal_threads):
                start = i * block_size
                end = start + block_size - 1 if i < optimal_threads - 1 else file_size - 1
                futures[executor.submit(
                    download_block, url, start, end, progress_bar, file_name
                )] = (start, end)

            # 处理失败的块
            failed_blocks = []
            for future in as_completed(futures):
                start, end = futures[future]
                try:
                    if not future.result():
                        failed_blocks.append((start, end))
                except Exception as e:
                    print(f"下载块 {start}-{end} 出错: {e}")
                    failed_blocks.append((start, end))

            # 重试失败的块
            if failed_blocks:
                print(f"\n有 {len(failed_blocks)} 个块下载失败，尝试重新下载...")
                for start, end in failed_blocks:
                    if not download_block(url, start, end, progress_bar, file_name, retries=5):
                        print(f"无法下载块 {start}-{end}, 尝试单线程下载此范围")
                        single_thread_download_range(url, start, end, file_name, progress_bar)

        progress_bar.close()

        # 验证下载完整性
        if os.path.getsize(file_name) == file_size:
            elapsed = time.time() - start_time
            avg_speed = (file_size / (1024 * 1024)) / elapsed
            print(f"\n下载完成: {file_name}")
            print(f"平均速度: {avg_speed:.2f} MB/s, 用时: {elapsed:.2f}秒")
        else:
            print("\n警告: 下载文件大小不匹配，可能下载不完整")

    except Exception as e:
        print(f"\n下载过程中发生错误: {e}")
        if 'file_name' in locals():
            try:
                os.remove(file_name)
                print(f"已删除不完整的文件: {file_name}")
            except:
                pass


def single_thread_download(url, file_name=None, progress_bar=None):
    try:
        response = requests.get(url, stream=True)
        response.raise_for_status()

        if file_name is None:
            file_name = os.path.basename(urlparse(url).path) or f"download_{int(time.time())}.bin"

        file_size = int(response.headers.get('Content-Length', 0))

        if progress_bar is None:
            progress_bar = ThreadSafeTqdm(total=file_size)

        with open(file_name, 'wb') as f:
            for chunk in response.iter_content(chunk_size=64 * 1024):
                if chunk:
                    f.write(chunk)
                    progress_bar.update(len(chunk))

        progress_bar.close()
        print(f"\n单线程下载完成: {file_name}")
        return True

    except Exception as e:
        print(f"\n单线程下载失败: {e}")
        return False


def single_thread_download_range(url, start, end, file_name, progress_bar):
    headers = {'Range': f'bytes={start}-{end}'}
    try:
        response = requests.get(url, headers=headers, stream=True, timeout=30)
        response.raise_for_status()

        with open(file_name, 'r+b') as f:
            f.seek(start)
            for chunk in response.iter_content(chunk_size=64 * 1024):
                if chunk:
                    f.write(chunk)
                    progress_bar.update(len(chunk))
        return True
    except Exception as e:
        print(f"\n无法下载范围 {start}-{end}: {e}")
        return False


if __name__ == "__main__":
    url = input("请输入文件下载链接: ")
    initial_threads = int(input("请输入初始线程数: ") or 10)
    max_threads = int(input("请输入最大线程数: ") or 100)
    multi_thread_download(url, initial_threads, max_threads)
