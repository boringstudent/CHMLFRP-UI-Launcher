import requests
import threading
import os
from tqdm import tqdm
from urllib.parse import urlparse, parse_qs
import time
import math
from concurrent.futures import ThreadPoolExecutor, as_completed
import io
import collections
import statistics


class ThreadSafeTqdm:
    def __init__(self, total):
        self.total = total
        self.progress = 0
        self.lock = threading.Lock()
        self.pbar = tqdm(total=total, unit='B', unit_scale=True, unit_divisor=1024)
        self.last_update_time = time.time()
        self.last_progress = 0
        self.speed = 0
        self.speeds_history = collections.deque(maxlen=10)  # Keep last 10 speed measurements

    def update(self, increment):
        with self.lock:
            self.progress += increment
            self.pbar.update(increment)

            current_time = time.time()
            time_elapsed = current_time - self.last_update_time
            if time_elapsed >= 1.0:
                progress_diff = self.progress - self.last_progress
                current_speed = progress_diff / time_elapsed / (1024 * 1024)
                self.speeds_history.append(current_speed)
                self.speed = current_speed
                self.last_progress = self.progress
                self.last_update_time = current_time

                # Update progress bar description with speed
                self.pbar.set_description(f"Speed: {self.speed:.2f} MB/s")

    def get_average_speed(self):
        if not self.speeds_history:
            return 0
        return statistics.mean(self.speeds_history)

    def close(self):
        self.pbar.close()


class DownloadManager:
    def __init__(self, url, initial_threads=10, max_threads=100, min_block_size_mb=5):
        self.url = url
        self.initial_threads = initial_threads
        self.max_threads = max_threads
        self.min_block_size = min_block_size_mb * 1024 * 1024  # Convert MB to bytes
        self.session = requests.Session()  # Connection pooling
        self.session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})

        self.file_size = 0
        self.file_name = ""
        self.progress_bar = None
        self.start_time = 0
        self.active_threads = initial_threads

        self.thread_performance = {}  # Track performance of each thread
        self.thread_lock = threading.Lock()
        self.last_adjustment_time = 0
        self.last_speed = 0

        # Buffer settings
        self.buffer_size = 1024 * 1024  # 1MB write buffer
        self.write_queue = {}  # Queue for buffered writes
        self.write_lock = threading.Lock()

    def get_file_info(self):
        try:
            response = self.session.head(self.url, allow_redirects=True, timeout=10)
            response.raise_for_status()

            if 'Content-Length' not in response.headers:
                print("服务器未返回Content-Length头信息，尝试单线程下载...")
                return False

            self.file_size = int(response.headers['Content-Length'])

            # 获取文件名
            content_disposition = response.headers.get('Content-Disposition', '')
            if 'filename=' in content_disposition:
                self.file_name = content_disposition.split('filename=')[1].strip('"\'')
            else:
                self.file_name = os.path.basename(urlparse(self.url).path)

            if not self.file_name:
                self.file_name = f"download_{int(time.time())}.bin"

            print(f"开始下载: {self.file_name} (大小: {self.file_size / 1024 / 1024:.2f} MB)")
            return True

        except Exception as e:
            print(f"获取文件信息失败: {e}")
            return False

    def test_range_support(self):
        try:
            test_response = self.session.get(self.url, headers={'Range': 'bytes=0-1'}, stream=True)
            return test_response.status_code == 206
        except:
            return False

    def adjust_thread_count(self):
        current_time = time.time()
        if current_time - self.last_adjustment_time < 5:  # Only adjust every 5 seconds
            return

        current_speed = self.progress_bar.get_average_speed()

        # Check thread performance
        with self.thread_lock:
            # Remove threads that have been inactive
            current_time = time.time()
            inactive_threads = [thread_id for thread_id, data in self.thread_performance.items()
                                if current_time - data['last_update'] > 10]
            for thread_id in inactive_threads:
                del self.thread_performance[thread_id]

            # Find underperforming threads
            if self.thread_performance:
                avg_performance = statistics.mean(
                    [data['speed'] for data in self.thread_performance.values() if data['speed'] > 0])
                underperforming = [thread_id for thread_id, data in self.thread_performance.items()
                                   if data['speed'] > 0 and data['speed'] < avg_performance * 0.5]

                # Log if many threads are underperforming
                if len(underperforming) > len(self.thread_performance) * 0.3:
                    print(f"检测到 {len(underperforming)} 个线程性能不佳")

        # Adjust thread count based on speed
        if current_speed < self.last_speed * 0.8 and self.active_threads > 1:
            # Speed decreased, reduce threads
            self.active_threads = max(self.active_threads - 1, 1)
            print(f"下载速度下降，减少线程数至 {self.active_threads}")
        elif current_speed > self.last_speed * 1.2 and self.active_threads < self.max_threads:
            # Speed increased, add threads
            self.active_threads = min(self.active_threads + 1, self.max_threads)
            print(f"下载速度提升，增加线程数至 {self.active_threads}")

        self.last_speed = current_speed
        self.last_adjustment_time = current_time

    def buffered_write(self, file_obj, start, data):
        """Buffer writes to reduce disk I/O"""
        with self.write_lock:
            if start not in self.write_queue:
                self.write_queue[start] = io.BytesIO()

            # Add data to buffer
            self.write_queue[start].write(data)
            buffer_size = self.write_queue[start].tell()

            # If buffer is large enough or this is the end of a block, write to disk
            if buffer_size >= self.buffer_size:
                file_obj.seek(start)
                self.write_queue[start].seek(0)
                file_obj.write(self.write_queue[start].getvalue())
                del self.write_queue[start]

    def flush_buffers(self, file_obj):
        """Flush all write buffers to disk"""
        with self.write_lock:
            for start, buffer in self.write_queue.items():
                file_obj.seek(start)
                buffer.seek(0)
                file_obj.write(buffer.getvalue())
            self.write_queue.clear()

    def update_thread_performance(self, thread_id, bytes_downloaded, time_taken):
        """Track performance of individual threads"""
        with self.thread_lock:
            speed_mbps = (bytes_downloaded / (1024 * 1024)) / time_taken if time_taken > 0 else 0

            if thread_id not in self.thread_performance:
                self.thread_performance[thread_id] = {
                    'total_bytes': 0,
                    'speed': 0,
                    'last_update': time.time()
                }

            # Update with exponential moving average
            alpha = 0.3  # weight for new data
            old_speed = self.thread_performance[thread_id]['speed']
            new_speed = (alpha * speed_mbps) + ((1 - alpha) * old_speed)

            self.thread_performance[thread_id].update({
                'total_bytes': self.thread_performance[thread_id]['total_bytes'] + bytes_downloaded,
                'speed': new_speed,
                'last_update': time.time()
            })

    def download_block(self, start, end, file_obj, progress_bar, thread_id, retries=3):
        headers = {'Range': f'bytes={start}-{end}'}

        total_downloaded = 0
        block_start_time = time.time()

        for attempt in range(retries):
            try:
                response = self.session.get(self.url, headers=headers, stream=True, timeout=30)
                response.raise_for_status()

                if response.status_code == 206:  # Partial Content
                    current_position = start
                    for chunk in response.iter_content(chunk_size=64 * 1024):
                        if chunk:
                            chunk_time_start = time.time()

                            # Write to buffer
                            self.buffered_write(file_obj, current_position, chunk)

                            # Update progress and position
                            chunk_size = len(chunk)
                            current_position += chunk_size
                            total_downloaded += chunk_size
                            progress_bar.update(chunk_size)

                            # Update performance metrics
                            chunk_time = time.time() - chunk_time_start
                            self.update_thread_performance(thread_id, chunk_size, max(chunk_time, 0.001))

                    # Successful download
                    block_time = time.time() - block_start_time
                    self.update_thread_performance(thread_id, total_downloaded, block_time)
                    return True
                else:
                    raise Exception(f"意外的状态码: {response.status_code}")

            except Exception as e:
                if attempt == retries - 1:
                    print(f"\n下载块 {start}-{end} 失败: {e}")
                    return False
                time.sleep(2 ** attempt)

        return False

    def single_thread_download(self):
        """Fall back to single thread download if needed"""
        try:
            response = self.session.get(self.url, stream=True)
            response.raise_for_status()

            with open(self.file_name, 'wb') as f:
                for chunk in response.iter_content(chunk_size=64 * 1024):
                    if chunk:
                        f.write(chunk)
                        self.progress_bar.update(len(chunk))

            print(f"\n单线程下载完成: {self.file_name}")
            return True

        except Exception as e:
            print(f"\n单线程下载失败: {e}")
            return False

    def download(self):
        try:
            # Get file info
            if not self.get_file_info():
                return False

            # Create empty file
            with open(self.file_name, 'wb') as f:
                f.truncate(self.file_size)

            self.progress_bar = ThreadSafeTqdm(total=self.file_size)
            self.start_time = time.time()

            # Test if server supports range requests
            if not self.test_range_support():
                print("服务器不支持范围请求，转为单线程下载")
                self.single_thread_download()
                return True

            # Calculate optimal initial thread count and block size
            optimal_threads = min(self.initial_threads, self.max_threads,
                                  math.ceil(self.file_size / (5 * 1024 * 1024)))  # 每5MB一个线程
            block_size = max(self.file_size // optimal_threads, self.min_block_size)

            # Open file for shared access
            with open(self.file_name, 'r+b') as file_obj:
                # First pass: download blocks with adaptive thread management
                remaining_blocks = self.download_with_adaptive_threads(file_obj, block_size, optimal_threads)

                # Retry failed blocks immediately with higher priority
                if remaining_blocks:
                    self.retry_failed_blocks(file_obj, remaining_blocks)

                # Ensure all buffers are flushed
                self.flush_buffers(file_obj)

            self.progress_bar.close()

            # Verify download
            if os.path.getsize(self.file_name) == self.file_size:
                elapsed = time.time() - self.start_time
                avg_speed = (self.file_size / (1024 * 1024)) / elapsed
                print(f"\n下载完成: {self.file_name}")
                print(f"平均速度: {avg_speed:.2f} MB/s, 用时: {elapsed:.2f}秒")
                return True
            else:
                print("\n警告: 下载文件大小不匹配，可能下载不完整")
                return False

        except Exception as e:
            print(f"\n下载过程中发生错误: {e}")
            if hasattr(self, 'file_name') and os.path.exists(self.file_name):
                try:
                    os.remove(self.file_name)
                    print(f"已删除不完整的文件: {self.file_name}")
                except:
                    pass
            return False

    def download_with_adaptive_threads(self, file_obj, block_size, initial_threads):
        """Main download logic with adaptive thread management"""
        self.active_threads = initial_threads

        # Create blocks to download
        blocks = []
        for i in range(0, self.file_size, block_size):
            start = i
            end = min(i + block_size - 1, self.file_size - 1)
            blocks.append((start, end))

        pending_blocks = collections.deque(blocks)
        failed_blocks = []
        active_futures = {}

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            # Start initial threads
            for _ in range(min(self.active_threads, len(pending_blocks))):
                if not pending_blocks:
                    break
                start, end = pending_blocks.popleft()
                thread_id = id(threading.current_thread())
                future = executor.submit(
                    self.download_block, start, end, file_obj,
                    self.progress_bar, thread_id
                )
                active_futures[future] = (start, end, thread_id)

            # Process futures and adjust threads dynamically
            while active_futures:
                # Adjust thread count periodically
                self.adjust_thread_count()

                # Wait for any future to complete
                done, _ = threading.Event(), threading.Event()
                for future in as_completed(active_futures, timeout=1):
                    start, end, thread_id = active_futures.pop(future)
                    try:
                        if not future.result():
                            failed_blocks.append((start, end))
                    except Exception as e:
                        print(f"下载块 {start}-{end} 出错: {e}")
                        failed_blocks.append((start, end))

                    done.set()
                    break

                if not done.is_set():
                    # No future completed in this iteration
                    continue

                # Start new threads if needed
                while len(active_futures) < self.active_threads and pending_blocks:
                    start, end = pending_blocks.popleft()
                    thread_id = id(threading.current_thread())
                    future = executor.submit(
                        self.download_block, start, end, file_obj,
                        self.progress_bar, thread_id
                    )
                    active_futures[future] = (start, end, thread_id)

        return failed_blocks

    def retry_failed_blocks(self, file_obj, failed_blocks):
        """Retry failed blocks with higher priority"""
        if not failed_blocks:
            return

        print(f"\n有 {len(failed_blocks)} 个块下载失败，立即重试...")

        # Sort failed blocks by size (smallest first for quick wins)
        failed_blocks.sort(key=lambda x: x[1] - x[0])

        # Retry each failed block
        with ThreadPoolExecutor(max_workers=min(len(failed_blocks), 5)) as executor:
            futures = {}
            for start, end in failed_blocks:
                thread_id = id(threading.current_thread())
                future = executor.submit(
                    self.download_block, start, end, file_obj,
                    self.progress_bar, thread_id, retries=5
                )
                futures[future] = (start, end)

            # Handle results
            still_failed = []
            for future in as_completed(futures):
                start, end = futures[future]
                try:
                    if not future.result():
                        still_failed.append((start, end))
                except Exception as e:
                    print(f"重试下载块 {start}-{end} 出错: {e}")
                    still_failed.append((start, end))

            # For any still failed blocks, try single-thread approach
            for start, end in still_failed:
                print(f"最后尝试单线程下载块 {start}-{end}")
                self.download_single_block(start, end, file_obj)

    def download_single_block(self, start, end, file_obj):
        """Last resort: download a block in single thread mode"""
        headers = {'Range': f'bytes={start}-{end}'}
        try:
            response = self.session.get(self.url, headers=headers, stream=True, timeout=60)
            response.raise_for_status()

            if response.status_code == 206:
                current_pos = start
                for chunk in response.iter_content(chunk_size=64 * 1024):
                    if chunk:
                        file_obj.seek(current_pos)
                        file_obj.write(chunk)
                        current_pos += len(chunk)
                        self.progress_bar.update(len(chunk))
                return True
            return False
        except Exception as e:
            print(f"单线程下载块失败 {start}-{end}: {e}")
            return False


def main():
    url = input("请输入文件下载链接: ")
    initial_threads = int(input("请输入初始线程数 (默认10): ") or 10)
    max_threads = int(input("请输入最大线程数 (默认100): ") or 100)
    min_block_size = int(input("请输入最小块大小(MB) (默认5): ") or 5)

    downloader = DownloadManager(
        url=url,
        initial_threads=initial_threads,
        max_threads=max_threads,
        min_block_size_mb=min_block_size
    )
    downloader.download()


if __name__ == "__main__":
    main()