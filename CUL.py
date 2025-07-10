import re
import subprocess
import sys
import random
import string
import os
import threading
import time
from logging.handlers import RotatingFileHandler
from datetime import datetime, timedelta

from PyQt6.QtCore import *
from PyQt6.QtWidgets import *
from PyQt6.QtGui import *
from PyQt6.QtCharts import *
from qfluentwidgets import *
import logging
import requests
import winreg

REG_PATH = r"Software\ChmlFrp"
APP_NAME = "CUL"  # 程序名称
APP_VERSION = "2.0.0"  # 程序版本
PY_VERSION = "3.13.*"  # Python 版本
WINDOWS_VERSION = "Windows NT 10.0"  # 系统版本
USER_AGENT = f"{APP_NAME}/{APP_VERSION} (Python/{PY_VERSION}; {WINDOWS_VERSION})"  # 生成统一的 User-Agent
wide = 1050
high = 650

# 配置文件路径
CONFIG_FILE = "config.json"

def get_absolute_path(relative_path):
    return os.path.abspath(os.path.join(os.path.split(sys.argv[0])[0], relative_path))

def setup_logging():
    log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(module)s - %(message)s')
    file_handler = RotatingFileHandler(
        f'{APP_NAME}.log',
        maxBytes=1024 * 1024 * 5,  # 5MB
        backupCount=5,
        encoding='utf-8'
    )
    file_handler.setFormatter(log_formatter)
    file_handler.setLevel(logging.DEBUG)
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(log_formatter)
    console_handler.setLevel(logging.INFO)

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)
    logging.getLogger("urllib3").setLevel(logging.WARNING)

def getFromRegistry(key):
    try:
        registry_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_PATH, 0, winreg.KEY_READ)
        value, regtype = winreg.QueryValueEx(registry_key, key)
        winreg.CloseKey(registry_key)
        return value
    except WindowsError:
        return None

def deleteFromRegistry(key):
    try:
        registry_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_PATH, 0, winreg.KEY_WRITE)
        winreg.DeleteValue(registry_key, key)
        winreg.CloseKey(registry_key)
    except WindowsError:
        pass

class FileDownloadThread(QThread):
    """文件下载"""
    downloadProgress = pyqtSignal(int)
    downloadFinished = pyqtSignal(bool, str)
    downloadStarted = pyqtSignal()
    downloadSize = pyqtSignal(str)

    def __init__(self, url, file_path, thread_count=4):
        super().__init__()
        self.url = url
        self.file_path = file_path
        self.thread_count = min(thread_count, 8)
        self.is_cancelled = False
        self.download_threads = []
        self.download_progress = {}
        self.total_size = 0
        self.chunks_info = []

    def run(self):
        try:
            self.downloadStarted.emit()
            logging.info(f"开始多线程下载文件: {self.url} (线程数: {self.thread_count})")
            if not self.prepare_download():
                self.single_thread_download()
                return
            self.multi_thread_download()

        except Exception as e:
            logging.error(f"下载过程中发生错误: {e}")
            self.downloadFinished.emit(False, f"下载失败: {str(e)}")

    def prepare_download(self):
        try:
            head_response = requests.head(
                self.url,
                timeout=10,
                headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                },
                allow_redirects=True
            )

            if head_response.status_code not in [200, 206]:
                logging.warning(f"HEAD请求失败，状态码: {head_response.status_code}")
                return False

            content_length = head_response.headers.get('content-length')
            if not content_length:
                logging.warning("无法获取文件大小，回退到单线程下载")
                return False

            self.total_size = int(content_length)
            size_mb = self.total_size / (1024 * 1024)
            self.downloadSize.emit(f"文件大小: {size_mb:.1f} MB")
            logging.info(f"文件总大小: {self.total_size} 字节 ({size_mb:.1f} MB)")

            accept_ranges = head_response.headers.get('accept-ranges', '').lower()
            if accept_ranges != 'bytes':
                test_response = requests.get(
                    self.url,
                    headers={
                        'Range': 'bytes=0-1023',
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                    },
                    timeout=10
                )
                if test_response.status_code != 206:
                    logging.warning("服务器不支持Range请求，回退到单线程下载")
                    return False

            if self.total_size < 1024 * 1024:
                logging.info("文件较小，使用单线程下载")
                return False

            chunk_size = self.total_size // self.thread_count
            self.chunks_info = []

            for i in range(self.thread_count):
                start = i * chunk_size
                end = start + chunk_size - 1
                if i == self.thread_count - 1:
                    end = self.total_size - 1

                self.chunks_info.append({
                    'thread_id': i,
                    'start': start,
                    'end': end,
                    'size': end - start + 1
                })

                self.download_progress[i] = 0

            logging.info(f"文件分段完成，共{self.thread_count}个线程，每段约{chunk_size / (1024 * 1024):.1f}MB")
            return True

        except Exception as e:
            logging.warning(f"准备多线程下载失败: {e}，回退到单线程")
            return False

    def multi_thread_download(self):
        try:
            file_dir = os.path.dirname(self.file_path)
            if file_dir:
                os.makedirs(file_dir, exist_ok=True)

            temp_files = []
            self.download_threads = []

            for chunk_info in self.chunks_info:
                temp_file = f"{self.file_path}.part{chunk_info['thread_id']}"
                temp_files.append(temp_file)

                thread = threading.Thread(
                    target=self.download_chunk,
                    args=(chunk_info, temp_file)
                )
                thread.daemon = True
                self.download_threads.append(thread)
                thread.start()

            for thread in self.download_threads:
                thread.join()

            if self.is_cancelled:
                self.cleanup_temp_files(temp_files)
                self.downloadFinished.emit(False, "下载已取消")
                return

            success = self.merge_files(temp_files)
            if success:
                self.downloadProgress.emit(100)
                final_size = os.path.getsize(self.file_path)
                logging.info(f"多线程下载完成: {final_size} 字节")
                self.downloadFinished.emit(True, f"下载完成 ({final_size / (1024 * 1024):.1f} MB)")
            else:
                self.downloadFinished.emit(False, "文件合并失败")
        except Exception as e:
            logging.error(f"多线程下载失败: {e}")
            self.downloadFinished.emit(False, f"多线程下载失败: {str(e)}")

    def download_chunk(self, chunk_info, temp_file):
        """下载文件"""
        try:
            thread_id = chunk_info['thread_id']
            start = chunk_info['start']
            end = chunk_info['end']

            headers = {
                'Range': f'bytes={start}-{end}',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }

            response = requests.get(self.url, headers=headers, stream=True, timeout=30)
            response.raise_for_status()
            downloaded = 0
            chunk_size = 8192

            with open(temp_file, 'wb') as f:
                for data_chunk in response.iter_content(chunk_size=chunk_size):
                    if self.is_cancelled:
                        return

                    if data_chunk:
                        f.write(data_chunk)
                        downloaded += len(data_chunk)
                        self.download_progress[thread_id] = downloaded
                        self.update_total_progress()

            logging.debug(f"线程{thread_id}下载完成: {downloaded} 字节")
        except Exception as e:
            logging.error(f"线程{thread_id}下载失败: {e}")
            self.download_progress[thread_id] = -1  # 标记失败

    def update_total_progress(self):
        try:
            total_downloaded = sum(max(0, progress) for progress in self.download_progress.values())
            if self.total_size > 0:
                progress = min(int((total_downloaded * 100) / self.total_size), 99)
                self.downloadProgress.emit(progress)
        except Exception as e:
            logging.debug(f"更新进度失败: {e}")

    def merge_files(self, temp_files):
        try:
            logging.info("开始合并文件块...")
            for i, temp_file in enumerate(temp_files):
                if not os.path.exists(temp_file):
                    logging.error(f"临时文件{i}不存在: {temp_file}")
                    return False
                if self.download_progress.get(i, 0) < 0:
                    logging.error(f"线程{i}下载失败")
                    return False
            with open(self.file_path, 'wb') as outfile:
                for temp_file in temp_files:
                    with open(temp_file, 'rb') as infile:
                        outfile.write(infile.read())
            final_size = os.path.getsize(self.file_path)
            if final_size != self.total_size:
                logging.error(f"文件大小不匹配: 期望{self.total_size}, 实际{final_size}")
                return False
            self.cleanup_temp_files(temp_files)
            logging.info(f"文件合并成功: {final_size} 字节")
            return True

        except Exception as e:
            logging.error(f"文件合并失败: {e}")
            self.cleanup_temp_files(temp_files)
            return False

    def cleanup_temp_files(self, temp_files):
        """清理临时文件"""
        for temp_file in temp_files:
            try:
                if os.path.exists(temp_file):
                    os.remove(temp_file)
            except Exception as e:
                logging.warning(f"删除临时文件失败: {temp_file}, {e}")

    def single_thread_download(self):
        """单线程下载"""
        try:
            logging.info("使用单线程下载")

            response = requests.get(
                self.url,
                stream=True,
                timeout=30,
                headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                }
            )
            response.raise_for_status()

            if self.total_size <= 0:
                content_length = response.headers.get('content-length')
                if content_length:
                    self.total_size = int(content_length)
                    size_mb = self.total_size / (1024 * 1024)
                    self.downloadSize.emit(f"文件大小: {size_mb:.1f} MB (单线程下载)")

            downloaded_size = 0
            chunk_size = 8192
            last_progress = -1

            file_dir = os.path.dirname(self.file_path)
            if file_dir:
                os.makedirs(file_dir, exist_ok=True)
            with open(self.file_path, 'wb') as file:
                for chunk in response.iter_content(chunk_size=chunk_size):
                    if self.is_cancelled:
                        file.close()
                        if os.path.exists(self.file_path):
                            os.remove(self.file_path)
                        self.downloadFinished.emit(False, "下载已取消")
                        return

                    if chunk:
                        file.write(chunk)
                        downloaded_size += len(chunk)
                        if self.total_size > 0:
                            progress = min(int((downloaded_size * 100) / self.total_size), 100)
                            if progress != last_progress and progress >= 0:
                                self.downloadProgress.emit(progress)
                                last_progress = progress

            if 0 < self.total_size != downloaded_size:
                logging.warning(f"单线程下载大小不匹配: 期望 {self.total_size}, 实际 {downloaded_size}")
                self.downloadFinished.emit(False, f"下载不完整: {downloaded_size}/{self.total_size} 字节")
                return

            final_size = os.path.getsize(self.file_path)
            logging.info(f"单线程下载完成: {final_size} 字节")
            self.downloadProgress.emit(100)
            self.downloadFinished.emit(True, f"下载完成 ({final_size / (1024 * 1024):.1f} MB)")

        except Exception as e:
            logging.error(f"单线程下载失败: {e}")
            self.downloadFinished.emit(False, f"单线程下载失败: {str(e)}")

    def cancel_download(self):
        """取消下载"""
        self.is_cancelled = True
        logging.info("多线程下载取消信号已发送")

class FileChecker:
    """文件检查和下载"""
    def __init__(self, parent_window=None):
        self.parent_window = parent_window
        self.download_thread = None
        self.progress_dialog = None
        self.required_files = {
            'frpc.exe': {
                'path': get_absolute_path('frpc.exe'),
                'url': 'https://chmlfrp.cn/dw/windows/amd64/frpc.exe',
                'backup_urls': [
                    'https://mirror.ghproxy.com/https://github.com/TechCat-Team/ChmlFrp-Frp/releases/latest/download/frpc_windows_amd64.exe',
                    'https://github.com/TechCat-Team/ChmlFrp-Frp/releases/latest/download/frpc_windows_amd64.exe'
                ],
                'description': 'ChmlFrp客户端程序'
            }
        }

    def check_and_download_files(self, callback=None):
        """检查下载所需文件"""
        missing_files = self.get_missing_files()
        if not missing_files:
            logging.info("所有必需文件都已存在")
            if callback:
                callback(True, "所有文件检查完成")
            return
        logging.info(f"发现缺失文件: {list(missing_files.keys())}")
        self.show_download_confirmation(missing_files, callback)

    def get_missing_files(self):
        missing = {}
        for file_name, file_info in self.required_files.items():
            file_path = file_info['path']
            if not os.path.exists(file_path):
                missing[file_name] = file_info
                logging.info(f"文件缺失: {file_path}")
            elif os.path.getsize(file_path) == 0:
                missing[file_name] = file_info
                logging.info(f"文件为空: {file_path}")
            else:
                logging.info(f"文件存在: {file_path} ({os.path.getsize(file_path)} 字节)")
        return missing

    def show_download_confirmation(self, missing_files, callback):
        file_list = '\n'.join([f"• {info['description']} ({name})"
                               for name, info in missing_files.items()])
        dialog = MessageBox(
            "缺少必需文件",
            f"程序需要以下文件才能正常运行:\n\n{file_list}\n\n是否现在下载这些文件？\n\n注意: 下载过程将使用单线程，请保持网络连接稳定。",
            self.parent_window
        )

        def start_download():
            self.download_missing_files(missing_files, callback)
        def cancel_download():
            logging.info("用户取消文件下载")
            if callback:
                callback(False, "用户取消下载")

        dialog.yesButton.setText("开始下载")
        dialog.cancelButton.setText("稍后下载")
        dialog.yesButton.clicked.connect(start_download)
        dialog.cancelButton.clicked.connect(cancel_download)
        dialog.exec()

    def download_missing_files(self, missing_files, callback):
        first_file = list(missing_files.items())[0]
        file_name, file_info = first_file
        self.try_download_with_backup(file_name, file_info, callback)

    def try_download_with_backup(self, file_name, file_info, callback, url_index=0):
        urls = [file_info['url']] + file_info.get('backup_urls', [])

        if url_index >= len(urls):
            error_msg = f"所有下载地址都失败了，请检查网络连接或稍后重试"
            logging.error(error_msg)
            if callback:
                callback(False, error_msg)
            return

        current_url = urls[url_index]
        url_type = "主要下载地址" if url_index == 0 else f"备用地址 {url_index}"

        logging.info(f"尝试从 {url_type} 下载: {current_url}")

        self.create_progress_dialog(file_name, file_info['description'], url_type)
        self.download_thread = FileDownloadThread(current_url, file_info['path'])
        self.download_thread.downloadStarted.connect(self.on_download_started)
        self.download_thread.downloadProgress.connect(self.on_download_progress)
        self.download_thread.downloadSize.connect(self.on_download_size)
        self.download_thread.downloadFinished.connect(
            lambda success, msg: self.on_download_finished_with_backup(
                success, msg, callback, file_name, file_info, url_index
            )
        )
        self.download_thread.start()

    def on_download_finished_with_backup(self, success, message, callback, file_name, file_info, url_index):
        if self.progress_dialog:
            self.progress_dialog.close()
            self.progress_dialog = None

        if success:
            logging.info(f"文件下载成功: {message}")
            InfoBar.success(
                title="下载成功",
                content=f"文件下载完成: {message}",
                position=InfoBarPosition.TOP_RIGHT,
                duration=3000,
                parent=self.parent_window
            )
            if callback:
                callback(True, message)
        else:
            logging.warning(f"当前下载地址失败: {message}")
            urls = [file_info['url']] + file_info.get('backup_urls', [])
            if url_index + 1 < len(urls):
                InfoBar.info(
                    title="切换下载地址",
                    content="当前下载地址失败，正在尝试备用地址...",
                    position=InfoBarPosition.TOP_RIGHT,
                    duration=2000,
                    parent=self.parent_window
                )
                QTimer.singleShot(1000, lambda: self.try_download_with_backup(
                    file_name, file_info, callback, url_index + 1
                ))
            else:
                error_msg = f"所有下载地址都失败了: {message}"
                logging.error(error_msg)
                InfoBar.error(
                    title="下载失败",
                    content=error_msg,
                    position=InfoBarPosition.TOP_RIGHT,
                    duration=5000,
                    parent=self.parent_window
                )

                if callback:
                    callback(False, error_msg)
        if self.download_thread:
            if self.download_thread.isRunning():
                self.download_thread.wait(3000)
            self.download_thread.deleteLater()
            self.download_thread = None

    def create_progress_dialog(self, file_name, description, url_type="主要下载地址"):
        """创建进度对话框"""
        self.progress_dialog = MessageBox(
            "正在下载文件",
            f"正在从 {url_type} 下载 {description}...\n请稍候，这可能需要几分钟时间。",
            self.parent_window
        )
        self.progress_bar = ProgressBar(self.progress_dialog)
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setFixedHeight(20)
        self.status_label = BodyLabel("正在准备下载...", self.progress_dialog)
        self.size_label = BodyLabel("获取文件信息中...", self.progress_dialog)
        self.size_label.setTextColor("#666666", "#cccccc")
        self.progress_dialog.textLayout.addWidget(self.progress_bar)
        self.progress_dialog.textLayout.addWidget(self.status_label)
        self.progress_dialog.textLayout.addWidget(self.size_label)
        self.progress_dialog.yesButton.setText("取消下载")
        self.progress_dialog.yesButton.clicked.disconnect()
        self.progress_dialog.yesButton.clicked.connect(self.cancel_download)
        self.progress_dialog.cancelButton.hide()
        self.progress_dialog.setMinimumWidth(400)
        self.progress_dialog.show()

    def on_download_started(self):
        if self.status_label:
            self.status_label.setText("正在连接服务器...")
        logging.info("下载连接已建立")

    def on_download_size(self, size_text):
        if self.size_label:
            self.size_label.setText(size_text)

    def on_download_progress(self, progress):
        progress = max(0, min(100, progress))

        if self.progress_bar:
            self.progress_bar.setValue(progress)
        if self.status_label:
            if progress == 0:
                self.status_label.setText("开始下载...")
            elif progress < 100:
                self.status_label.setText(f"下载进度: {progress}%")
            else:
                self.status_label.setText("下载完成，正在验证文件...")

        logging.debug(f"下载进度更新: {progress}%")

    def on_download_finished(self, success, message, callback):
        if self.progress_dialog:
            self.progress_dialog.close()
            self.progress_dialog = None

        if success:
            logging.info(f"文件下载成功: {message}")
            InfoBar.success(
                title="下载成功",
                content=f"文件下载完成: {message}",
                position=InfoBarPosition.TOP_RIGHT,
                duration=3000,
                parent=self.parent_window
            )
        else:
            logging.error(f"文件下载失败: {message}")
            InfoBar.error(
                title="下载失败",
                content=f"文件下载失败: {message}",
                position=InfoBarPosition.TOP_RIGHT,
                duration=5000,
                parent=self.parent_window
            )

        if callback:
            callback(success, message)
        if self.download_thread:
            if self.download_thread.isRunning():
                self.download_thread.wait(3000)  # 3s
            self.download_thread.deleteLater()
            self.download_thread = None

    def cancel_download(self):
        """取消下载"""
        if self.download_thread and self.download_thread.isRunning():
            logging.info("用户请求取消下载")
            self.download_thread.cancel_download()
            if not self.download_thread.wait(3000):  # 等3秒
                logging.warning("下载线程未能及时响应取消请求")
                self.download_thread.terminate()

        if self.progress_dialog:
            self.progress_dialog.close()
            self.progress_dialog = None

    def get_frpc_path(self):
        return self.required_files['frpc.exe']['path']

    def is_frpc_available(self):
        frpc_path = self.get_frpc_path()
        return os.path.exists(frpc_path) and os.path.isfile(frpc_path)

class TunnelSelectionDialog(MessageBoxBase):
    """隧道选择对话框"""

    def __init__(self, selected_tunnel_ids=None, parent=None):
        super().__init__(parent)
        self.selected_tunnel_ids = selected_tunnel_ids or []
        self.available_tunnels = []
        self.tunnel_checkboxes = []
        self.setWindowTitle("选择自动启动的隧道")
        self.init_ui()
        QTimer.singleShot(100, self.load_tunnels)

    def init_ui(self):
        self.resize(1000, 600)
        self.yesButton.hide()
        self.cancelButton.hide()

        main_widget = QWidget()
        main_layout = QVBoxLayout(main_widget)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(15)

        info_label = BodyLabel("选择程序启动时自动启动的隧道：", self)
        info_label.setStyleSheet("font-weight: bold;")
        main_layout.addWidget(info_label)

        self.scroll_area = SingleDirectionScrollArea(orient=Qt.Orientation.Vertical)
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setMinimumSize(600, 400)
        self.scroll_content = QWidget()
        self.scroll_layout = QVBoxLayout(self.scroll_content)
        self.scroll_layout.setContentsMargins(0, 0, 0, 0)
        self.scroll_layout.setSpacing(10)
        self.loading_label = BodyLabel("正在加载隧道列表...", self)
        self.loading_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.scroll_layout.addWidget(self.loading_label)
        self.scroll_area.setWidget(self.scroll_content)
        self.scroll_area.enableTransparentBackground()
        main_layout.addWidget(self.scroll_area)

        self.viewLayout.addWidget(main_widget)

        while self.buttonLayout.count():
            item = self.buttonLayout.takeAt(0)
            if item.widget():
                item.widget().hide()

        self.select_all_btn = PushButton("全选", self)
        self.select_all_btn.clicked.connect(self.select_all)

        self.select_none_btn = PushButton("全不选", self)
        self.select_none_btn.clicked.connect(self.select_none)

        self.invert_selection_btn = PushButton("反选", self)
        self.invert_selection_btn.clicked.connect(self.invert_selection)

        self.confirm_btn = PrimaryPushButton("确定", self)
        self.confirm_btn.clicked.connect(self.accept_selection)

        self.cancel_btn = PushButton("取消", self)
        self.cancel_btn.clicked.connect(self.close)

        self.buttonLayout.addWidget(self.select_all_btn)
        self.buttonLayout.addWidget(self.select_none_btn)
        self.buttonLayout.addWidget(self.invert_selection_btn)
        self.buttonLayout.addStretch()
        self.buttonLayout.addWidget(self.confirm_btn)
        self.buttonLayout.addWidget(self.cancel_btn)

    def load_tunnels(self):
        token = token_manager.get_token()
        if not token:
            self.show_error("请先登录")
            return

        self.tunnel_thread = TunnelLoaderThread(token)
        self.tunnel_thread.dataLoaded.connect(self.on_tunnels_loaded)
        self.tunnel_thread.start()

    def invert_selection(self):
        """反选"""
        for checkbox in self.tunnel_checkboxes:
            checkbox.setChecked(not checkbox.isChecked())

    def on_tunnels_loaded(self, data):
        """隧道加载完成"""
        if data.get("code") == 200:
            self.available_tunnels = data.get("data", [])
            self.create_tunnel_checkboxes()
        else:
            self.show_error(data.get("msg", "加载隧道失败"))

    def create_tunnel_checkboxes(self):
        """创建隧道复选框"""
        self.loading_label.hide()

        if not self.available_tunnels:
            no_tunnels_label = BodyLabel("暂无隧道", self)
            no_tunnels_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.scroll_layout.addWidget(no_tunnels_label)
            return

        self.tunnel_checkboxes.clear()

        for tunnel in self.available_tunnels:
            tunnel_id = tunnel.get('id')
            tunnel_name = tunnel.get('name')
            tunnel_type = tunnel.get('type', '').upper()
            node_name = tunnel.get('node', '')
            local_port = tunnel.get('nport', '')

            tunnel_card = CardWidget(self.scroll_content)
            tunnel_card.setFixedHeight(80)

            card_layout = QHBoxLayout(tunnel_card)
            card_layout.setContentsMargins(15, 10, 15, 10)
            card_layout.setSpacing(15)

            checkbox = CheckBox(self.scroll_content)
            checkbox.setChecked(tunnel_id in self.selected_tunnel_ids)
            checkbox.tunnel_id = tunnel_id
            self.tunnel_checkboxes.append(checkbox)

            info_layout = QVBoxLayout()
            info_layout.setSpacing(3)

            title_label = BodyLabel(f"{tunnel_name} ({tunnel_type})", tunnel_card)
            title_label.setStyleSheet("font-weight: bold;")

            detail_text = f"节点: {node_name} | 本地端口: {local_port}"
            detail_label = CaptionLabel(detail_text, tunnel_card)
            detail_label.setTextColor("#666666", "#cccccc")

            info_layout.addWidget(title_label)
            info_layout.addWidget(detail_label)

            status_layout = QHBoxLayout()
            status_layout.setSpacing(5)

            node_state = tunnel.get('nodestate', 'unknown')
            if node_state == 'online':
                node_badge = InfoBadge.success("节点在线", tunnel_card)
            else:
                node_badge = InfoBadge.error("节点离线", tunnel_card)

            status_layout.addWidget(node_badge)
            status_layout.addStretch()

            card_layout.addWidget(checkbox, 0, Qt.AlignmentFlag.AlignCenter)
            card_layout.addLayout(info_layout, 1)
            card_layout.addLayout(status_layout, 0)

            self.scroll_layout.addWidget(tunnel_card)

        self.scroll_layout.addStretch()

    def select_all(self):
        """全选"""
        for checkbox in self.tunnel_checkboxes:
            checkbox.setChecked(True)

    def select_none(self):
        """全不选"""
        for checkbox in self.tunnel_checkboxes:
            checkbox.setChecked(False)

    def accept_selection(self):
        """确认选择"""
        selected_ids = []
        for checkbox in self.tunnel_checkboxes:
            if checkbox.isChecked():
                selected_ids.append(checkbox.tunnel_id)

        config_manager.set("auto_start_tunnels", selected_ids)
        InfoBar.success(
            title="设置已保存",
            content=f"已设置 {len(selected_ids)} 个隧道为自动启动",
            position=InfoBarPosition.TOP_RIGHT,
            duration=3000,
            parent=self.window()
        )
        self.close()

    def show_error(self, message):
        """显示错误信息"""
        self.loading_label.setText(f"错误: {message}")
        InfoBar.error(
            title="错误",
            content=message,
            position=InfoBarPosition.TOP_RIGHT,
            duration=3000,
            parent=self.window()
        )

class ConfigManager:
    def __init__(self):
        self.config_file = CONFIG_FILE
        self.default_config = {
            "theme": "auto",  # auto, light, dark
            "auto_start": False,
            "user_token": "",
            "username": "",
            "password": "",
            "auto_start_tunnels": [],
            "email_notifications": {
                "enabled": False,
                "email": "",
                "password": "",
                "login_notify": True,
                "tunnel_start": True,
                "tunnel_stop": True,
                "node_add": True,
                "node_remove": True,
                "node_online": True,
                "node_offline": True
            }
        }
        self.config = self.load_config()

    def load_config(self):
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    for key, value in self.default_config.items():
                        if key not in config:
                            config[key] = value
                    return config
            else:
                return self.default_config.copy()
        except Exception as e:
            logging.error(f"加载配置文件失败: {e}")
            return self.default_config.copy()

    def save_config(self):
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=4, ensure_ascii=False)
        except Exception as e:
            logging.error(f"保存配置文件失败: {e}")

    def get(self, key, default=None):
        return self.config.get(key, default)

    def set(self, key, value):
        self.config[key] = value
        self.save_config()

class TokenManager:
    _instance = None
    _token = None
    _username = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(TokenManager, cls).__new__(cls)
        return cls._instance

    def set_token(self, token):
        """设置token"""
        self._token = token
        config_manager.set("user_token", token)

    def get_token(self):
        """获取token"""
        if self._token:
            return self._token
        # 从配置文件获取
        token = config_manager.get("user_token", "")
        if token:
            self._token = token
        # 兜底从注册表获取
        if not token:
            token = getFromRegistry("usertoken")
            if token:
                self._token = token
                config_manager.set("user_token", token)
        return self._token

    def set_username(self, username):
        self._username = username
        config_manager.set("username", username)

    def get_username(self):
        return self._username or config_manager.get("username", "")

    def clear(self):
        self._token = None
        self._username = None
        config_manager.set("user_token", "")
        config_manager.set("username", "")
        config_manager.set("password", "")
        deleteFromRegistry("usertoken")
        deleteFromRegistry("username")
        deleteFromRegistry("password")

# 全局实例
config_manager = ConfigManager()
token_manager = TokenManager()

class AutoStartManager:
    """开机自启"""
    @staticmethod
    def set_auto_start(enabled):
        """设置开机自启"""
        try:
            app_path = sys.executable if getattr(sys, 'frozen', False) else __file__
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"

            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
                if enabled:
                    winreg.SetValueEx(key, APP_NAME, 0, winreg.REG_SZ, app_path)
                else:
                    try:
                        winreg.DeleteValue(key, APP_NAME)
                    except FileNotFoundError:
                        pass
            return True
        except Exception as e:
            logging.error(f"设置开机自启失败: {e}")
            return False

    @staticmethod
    def is_auto_start_enabled():
        """检查是否已启用开机自启"""
        try:
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ) as key:
                try:
                    winreg.QueryValueEx(key, APP_NAME)
                    return True
                except FileNotFoundError:
                    return False
        except Exception:
            return False

class SettingsPage(QWidget):
    """设置页面"""
    def __init__(self, parent=None):
        super().__init__(parent=parent)
        self.setObjectName("settingsPage")
        self.tunnel_config_description_label = None
        self.auto_tunnel_card = None
        self.init_ui()

    def init_ui(self):
        """初始化设置界面"""
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(15)
        scroll_area = SingleDirectionScrollArea(orient=Qt.Orientation.Vertical, parent=self)
        scroll_area.setWidgetResizable(True)
        scroll_area.setStyleSheet("QScrollArea{background: transparent; border: none}")

        scroll_widget = QWidget()
        scroll_widget.setStyleSheet("QWidget{background: transparent}")
        scroll_layout = QVBoxLayout(scroll_widget)
        scroll_layout.setContentsMargins(0, 0, 0, 0)
        scroll_layout.setSpacing(16)

        title_label = SubtitleLabel("设置", self)
        scroll_layout.addWidget(title_label)

        startup_card = self.create_startup_card()
        scroll_layout.addWidget(startup_card)

        self.auto_tunnel_card = self.create_auto_tunnel_card()
        scroll_layout.addWidget(self.auto_tunnel_card)

        other_card = self.create_other_card()
        scroll_layout.addWidget(other_card)

        scroll_layout.addStretch()
        scroll_area.setWidget(scroll_widget)
        main_layout.addWidget(scroll_area)
        scroll_area.enableTransparentBackground()


    def create_startup_card(self):
        """创建启动设置卡片"""
        startup_card = GroupHeaderCardWidget(self)
        startup_card.setBorderRadius(8)
        startup_card.setTitle("🚀 启动设置")
        # 开机自启
        self.auto_start_switch = SwitchButton()
        self.auto_start_switch.setChecked(config_manager.get("auto_start", False))
        self.auto_start_switch.checkedChanged.connect(self.on_auto_start_changed)

        startup_card.addGroup(
            FluentIcon.POWER_BUTTON,
            "开机自启",
            "开机时自动启动程序",
            self.auto_start_switch
        )
        return startup_card

    def on_auto_start_changed(self, checked):
        """开机自启更改事件"""
        config_manager.set("auto_start", checked)
        success = AutoStartManager.set_auto_start(checked)

        if success:
            InfoBar.success(
                title="设置已保存",
                content=f"开机自启已{'启用' if checked else '禁用'}",
                position=InfoBarPosition.TOP_RIGHT,
                duration=2000,
                parent=self.window()
            )
        else:
            self.auto_start_switch.setChecked(not checked)
            config_manager.set("auto_start", not checked)
            InfoBar.error(
                title="设置失败",
                content="无法更改开机自启设置",
                position=InfoBarPosition.TOP_RIGHT,
                duration=3000,
                parent=self.window()
            )

    def clear_cache(self):
        """清除缓存"""
        try:
            InfoBar.success(
                title="清除成功",
                content="缓存已清除",
                position=InfoBarPosition.TOP_RIGHT,
                duration=2000,
                parent=self.window()
            )
        except Exception as e:
            InfoBar.error(
                title="清除失败",
                content=f"清除缓存时发生错误: {str(e)}",
                position=InfoBarPosition.TOP_RIGHT,
                duration=3000,
                parent=self.window()
            )

    def reset_settings(self):
        """重置设置"""
        def confirm_reset():
            try:
                config_manager.config = config_manager.default_config.copy()
                config_manager.save_config()

                self.theme_combo.setCurrentIndex(0)
                self.auto_start_switch.setChecked(False)
                AutoStartManager.set_auto_start(False)

                InfoBar.success(
                    title="重置成功",
                    content="所有设置已重置为默认值",
                    position=InfoBarPosition.TOP_RIGHT,
                    duration=3000,
                    parent=self.window()
                )
            except Exception as e:
                InfoBar.error(
                    title="重置失败",
                    content=f"重置设置时发生错误: {str(e)}",
                    position=InfoBarPosition.TOP_RIGHT,
                    duration=3000,
                    parent=self.window()
                )
        dialog = MessageBox(
            "确认重置",
            "确定要将所有设置重置为默认值吗？此操作不可撤销。",
            self.window()
        )
        dialog.yesButton.clicked.connect(confirm_reset)
        dialog.exec()

    def create_other_card(self):
        """创建其他设置卡片"""
        other_card = GroupHeaderCardWidget(self)
        other_card.setBorderRadius(8)
        other_card.setTitle("⚙️ 其他设置")

        clear_cache_button = PushButton("清除缓存")
        clear_cache_button.clicked.connect(self.clear_cache)

        other_card.addGroup(
            FluentIcon.DELETE,
            "清除缓存",
            "清除应用程序缓存数据",
            clear_cache_button
        )

        reset_settings_button = PushButton("重置设置")
        reset_settings_button.clicked.connect(self.reset_settings)

        other_card.addGroup(
            FluentIcon.CANCEL,
            "重置设置",
            "将所有设置恢复为默认值",
            reset_settings_button
        )

        return other_card

    def create_auto_tunnel_card(self):
        """创建自动启动隧道设置卡片"""
        auto_tunnel_card = GroupHeaderCardWidget(self)
        auto_tunnel_card.setBorderRadius(8)
        auto_tunnel_card.setTitle("🚀 自动启动隧道")

        self.auto_tunnel_switch = SwitchButton()
        current_tunnels = config_manager.get("auto_start_tunnels", [])
        self.auto_tunnel_switch.setChecked(len(current_tunnels) > 0)
        self.auto_tunnel_switch.checkedChanged.connect(self.on_auto_tunnel_switch_changed)

        auto_tunnel_card.addGroup(
            FluentIcon.PLAY,
            "启用自动启动隧道",
            "程序启动时自动启动选定的隧道",
            self.auto_tunnel_switch
        )

        self.config_tunnels_button = PushButton("配置隧道")
        self.config_tunnels_button.clicked.connect(self.configure_auto_start_tunnels)

        tunnel_count = len(current_tunnels)
        initial_description = self.get_tunnel_config_description(tunnel_count)

        config_group = auto_tunnel_card.addGroup(
            FluentIcon.SETTING,
            "配置自动启动的隧道",
            initial_description,
            self.config_tunnels_button
        )
        self.find_and_store_description_label(config_group)

        return auto_tunnel_card

    def find_and_store_description_label(self, group_widget):
        """查找并保存配置描述标签的引用"""
        try:
            # 遍历组件的子组件，找到描述标签
            for child in group_widget.findChildren(QLabel):
                # 通过文本内容识别描述标签
                if "配置" in child.text() or "隧道" in child.text():
                    if "配置自动启动的隧道" not in child.text():  # 排除标题标签
                        self.tunnel_config_description_label = child
                        break

            # 如果上面的方法没找到，尝试另一种方法
            if self.tunnel_config_description_label is None:
                # 查找 CaptionLabel 类型的标签
                for child in group_widget.findChildren(CaptionLabel):
                    if hasattr(child, 'text') and callable(child.text):
                        text = child.text()
                        if "配置" in text or "隧道" in text or "未配置" in text:
                            self.tunnel_config_description_label = child
                            break

        except Exception as e:
            logging.warning(f"查找描述标签失败: {e}")
            self.tunnel_config_description_label = None

    def get_tunnel_config_description(self, tunnel_count, tunnel_names=None):
        """获取隧道配置描述文本"""
        if tunnel_count == 0:
            return "未配置任何隧道"
        elif tunnel_count == 1:
            if tunnel_names and len(tunnel_names) > 0:
                return f"已配置 1 个隧道: {tunnel_names[0]}"
            else:
                return "已配置 1 个隧道"
        elif tunnel_count <= 3:
            if tunnel_names and len(tunnel_names) >= tunnel_count:
                tunnel_list = ", ".join(tunnel_names[:tunnel_count])
                return f"已配置 {tunnel_count} 个隧道: {tunnel_list}"
            else:
                return f"已配置 {tunnel_count} 个隧道"
        else:
            if tunnel_names and len(tunnel_names) >= 3:
                tunnel_list = ", ".join(tunnel_names[:3])
                return f"已配置 {tunnel_count} 个隧道: {tunnel_list}..."
            else:
                return f"已配置 {tunnel_count} 个隧道"

    def update_tunnel_config_display(self):
        """更新隧道配置显示"""
        try:
            current_tunnel_ids = config_manager.get("auto_start_tunnels", [])
            tunnel_count = len(current_tunnel_ids)

            # 更新开关状态
            self.auto_tunnel_switch.setChecked(tunnel_count > 0)

            # 获取隧道名称（如果可能的话）
            tunnel_names = self.get_tunnel_names_by_ids(current_tunnel_ids)

            # 更新描述文本
            new_description = self.get_tunnel_config_description(tunnel_count, tunnel_names)

            if self.tunnel_config_description_label is not None:
                try:
                    # 更新标签文本
                    self.tunnel_config_description_label.setText(new_description)
                    logging.info(f"隧道配置显示已更新: {new_description}")
                except Exception as e:
                    logging.warning(f"更新描述标签失败: {e}")
                    # 如果直接更新失败，重新创建卡片
                    self.recreate_auto_tunnel_card()
            else:
                # 如果没有找到描述标签，重新创建卡片
                logging.warning("未找到描述标签，重新创建自动隧道卡片")
                self.recreate_auto_tunnel_card()

            # 显示更新提示
            if tunnel_count > 0:
                InfoBar.success(
                    title="配置已更新",
                    content=f"已配置 {tunnel_count} 个隧道为自动启动",
                    position=InfoBarPosition.TOP_RIGHT,
                    duration=2000,
                    parent=self.window()
                )
            else:
                InfoBar.info(
                    title="配置已清空",
                    content="已清空自动启动隧道配置",
                    position=InfoBarPosition.TOP_RIGHT,
                    duration=2000,
                    parent=self.window()
                )

        except Exception as e:
            logging.error(f"更新隧道配置显示失败: {e}")
            InfoBar.error(
                title="更新失败",
                content="更新隧道配置显示时发生错误",
                position=InfoBarPosition.TOP_RIGHT,
                duration=3000,
                parent=self.window()
            )

    def get_tunnel_names_by_ids(self, tunnel_ids):
        """根据隧道ID获取隧道名称"""
        if not tunnel_ids:
            return []

        tunnel_names = []
        try:
            # 尝试从主窗口的隧道管理页面获取隧道信息
            main_window = self.window()
            if hasattr(main_window, 'tunnelManagementPage'):
                tunnel_page = main_window.tunnelManagementPage
                if hasattr(tunnel_page, 'tunnel_cards'):
                    for card in tunnel_page.tunnel_cards:
                        tunnel_info = getattr(card, 'tunnel_info', {})
                        tunnel_id = tunnel_info.get('id')
                        tunnel_name = tunnel_info.get('name')

                        if tunnel_id in tunnel_ids and tunnel_name:
                            tunnel_names.append(tunnel_name)

        except Exception as e:
            logging.warning(f"获取隧道名称失败: {e}")

        return tunnel_names

    def recreate_auto_tunnel_card(self):
        """重新创建自动启动隧道卡片"""
        try:
            # 找到卡片在布局中的位置
            parent_layout = self.auto_tunnel_card.parent().layout()
            if parent_layout is None:
                logging.error("无法找到父布局")
                return

            # 找到卡片的索引位置
            card_index = -1
            for i in range(parent_layout.count()):
                item = parent_layout.itemAt(i)
                if item and item.widget() == self.auto_tunnel_card:
                    card_index = i
                    break

            if card_index == -1:
                logging.error("无法找到卡片在布局中的位置")
                return

            # 移除旧卡片
            parent_layout.removeWidget(self.auto_tunnel_card)
            self.auto_tunnel_card.deleteLater()

            # 创建新卡片
            self.auto_tunnel_card = self.create_auto_tunnel_card()

            # 插入到原来的位置
            parent_layout.insertWidget(card_index, self.auto_tunnel_card)

            logging.info("自动隧道卡片重新创建成功")

        except Exception as e:
            logging.error(f"重新创建自动隧道卡片失败: {e}")

    def on_auto_tunnel_switch_changed(self, checked):
        """自动启动隧道开关改变事件"""
        if not checked:
            # 如果关闭，清空自动启动列表
            config_manager.set("auto_start_tunnels", [])
            self.update_tunnel_config_display()

    def configure_auto_start_tunnels(self):
        """配置自动启动的隧道"""
        # 检查是否已登录
        if not token_manager.get_token():
            InfoBar.warning(
                title="未登录",
                content="请先登录后再配置自动启动隧道",
                position=InfoBarPosition.TOP_RIGHT,
                duration=3000,
                parent=self.window()
            )
            return

        # 获取当前配置的隧道ID
        current_tunnels = config_manager.get("auto_start_tunnels", [])

        # 打开隧道选择对话框
        dialog = TunnelSelectionDialog(current_tunnels, self)

        # 连接对话框完成信号到更新显示方法
        dialog.finished.connect(lambda: QTimer.singleShot(100, self.update_tunnel_config_display))

        dialog.exec()

    # ... 保留原有的其他方法 (create_theme_card, create_startup_card, create_other_card 等)

class TunnelConfigInfoDialog(MessageBoxBase):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("自动启动隧道配置")
        self.init_ui()
        self.load_config_info()

    def init_ui(self):
        """初始化界面"""
        self.resize(600, 400)
        self.yesButton.hide()
        self.cancelButton.hide()

        main_widget = QWidget()
        main_layout = QVBoxLayout(main_widget)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(15)

        title_label = SubtitleLabel("当前自动启动隧道配置", self)
        main_layout.addWidget(title_label)

        self.info_scroll_area = SingleDirectionScrollArea(orient=Qt.Orientation.Vertical)
        self.info_scroll_area.setWidgetResizable(True)
        self.info_content = QWidget()
        self.info_layout = QVBoxLayout(self.info_content)
        self.info_layout.setContentsMargins(0, 0, 0, 0)
        self.info_layout.setSpacing(10)

        self.info_scroll_area.setWidget(self.info_content)
        self.info_scroll_area.enableTransparentBackground()
        main_layout.addWidget(self.info_scroll_area)

        button_layout = QHBoxLayout()
        button_layout.addStretch()

        self.close_btn = PrimaryPushButton("关闭", self)
        self.close_btn.clicked.connect(self.close)
        button_layout.addWidget(self.close_btn)

        main_layout.addLayout(button_layout)

        self.viewLayout.addWidget(main_widget)

    def load_config_info(self):
        """加载配置信息"""
        tunnel_ids = config_manager.get("auto_start_tunnels", [])

        if not tunnel_ids:
            no_config_label = BodyLabel("暂无配置的自动启动隧道", self)
            no_config_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.info_layout.addWidget(no_config_label)
            return

        for tunnel_id in tunnel_ids:
            tunnel_card = CardWidget(self.info_content)
            tunnel_card.setFixedHeight(60)

            card_layout = QHBoxLayout(tunnel_card)
            card_layout.setContentsMargins(15, 10, 15, 10)

            id_label = BodyLabel(f"隧道ID: {tunnel_id}", tunnel_card)
            card_layout.addWidget(id_label)
            card_layout.addStretch()

            self.info_layout.addWidget(tunnel_card)

        self.info_layout.addStretch()

class TunnelCard(CardWidget):
    """隧道卡片"""
    selectionChanged = pyqtSignal(bool)

    def __init__(self, tunnel_info, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.tunnel_info = tunnel_info
        self.init_ui()

    def init_ui(self):
        """初始化界面"""
        self.setFixedSize(470, 150)  # 固定尺寸

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(12, 10, 12, 10)
        main_layout.setSpacing(6)

        title_layout = QHBoxLayout()
        title_layout.setContentsMargins(0, 0, 0, 0)
        title_layout.setSpacing(8)

        self.checkbox = CheckBox(self)
        self.checkbox.stateChanged.connect(self.on_selection_changed)
        title_layout.addWidget(self.checkbox)

        title_label = BodyLabel(self.tunnel_info['name'], self)
        title_label.setStyleSheet("font-weight: bold; font-size: 13px;")
        title_layout.addWidget(title_label)

        self.status_indicator = StatusIndicator(self)
        self.status_indicator.setFixedSize(12, 12)
        title_layout.addWidget(self.status_indicator)

        title_layout.addStretch()

        node_state = self.tunnel_info.get('nodestate', 'unknown')
        if node_state == 'online':
            node_badge = InfoBadge.success("节点在线", self)
        else:
            node_badge = InfoBadge.error("节点离线", self)
        node_badge.setFixedSize(52, 16)
        title_layout.addWidget(node_badge)

        self.copy_button = TransparentToolButton(FluentIcon.COPY, self)
        self.copy_button.setFixedSize(24, 24)
        self.copy_button.setToolTip("复制连接地址")
        self.copy_button.clicked.connect(self.copy_connection_address)
        title_layout.addWidget(self.copy_button)

        self.menu_button = TransparentToolButton(FluentIcon.MORE, self)
        self.menu_button.setFixedSize(24, 24)
        self.menu_button.clicked.connect(self.show_menu)
        title_layout.addWidget(self.menu_button)

        main_layout.addLayout(title_layout)

        info_layout = QGridLayout()
        info_layout.setContentsMargins(0, 2, 0, 2)
        info_layout.setHorizontalSpacing(15)
        info_layout.setVerticalSpacing(3)

        info_items = [
            ("类型", self.tunnel_info['type'].upper()),
            ("本地", f"{self.tunnel_info['localip']}:{self.tunnel_info['nport']}"),
            ("节点", self.tunnel_info['node']),
            ("绑定", self.tunnel_info['dorp'] if self.tunnel_info['type'] in ['http', 'https', 'tcp', 'udp'] else ""),
            ("上传", f"{self.tunnel_info['today_traffic_out'] / 1024 / 1024:.1f}MB"),
            ("下载", f"{self.tunnel_info['today_traffic_in'] / 1024 / 1024:.1f}MB"),
            ("连接", str(self.tunnel_info['cur_conns'])),
            ("外部检测是否启动", self.tunnel_info['client_version']),
        ]

        row, col = 0, 0
        for label, value in info_items:
            if value:
                label_widget = CaptionLabel(f"{label}:", self)
                label_widget.setTextColor("#666666", "#cccccc")
                value_widget = CaptionLabel(str(value), self)

                info_layout.addWidget(label_widget, row, col * 2)
                info_layout.addWidget(value_widget, row, col * 2 + 1)

                col += 1
                if col >= 2:
                    col = 0
                    row += 1

        main_layout.addLayout(info_layout)
        main_layout.addStretch()

        status_layout = QHBoxLayout()
        status_layout.setContentsMargins(0, 0, 0, 0)

        if self.tunnel_info['encryption'] == 'True':
            encrypt_badge = InfoBadge.info("加密", self)
            encrypt_badge.setFixedSize(30, 14)
            status_layout.addWidget(encrypt_badge)

        if self.tunnel_info['compression'] == 'True':
            compress_badge = InfoBadge.info("压缩", self)
            compress_badge.setFixedSize(30, 14)
            status_layout.addWidget(compress_badge)

        status_layout.addStretch()
        main_layout.addLayout(status_layout)

        self.update_status(self.tunnel_info.get('state') == 'true')

    def on_selection_changed(self, state):
        """复选框状态变化"""
        self.selectionChanged.emit(state == Qt.CheckState.Checked.value)

    def is_selected(self):
        """获取选择状态"""
        return self.checkbox.isChecked()

    def set_selected(self, selected):
        """设置选择状态"""
        self.checkbox.setChecked(selected)

    def show_menu(self):
        """显示操作菜单"""
        menu = RoundMenu(parent=self)
        with QMutexLocker(self.parent.process_lock):
            is_running = (self.tunnel_info['name'] in self.parent.tunnel_processes and
                         self.parent.tunnel_processes[self.tunnel_info['name']].poll() is None)

        if not is_running:
            start_action = Action(FluentIcon.PLAY, '启动隧道')
            start_action.triggered.connect(lambda: self.parent.start_tunnel(self))
            menu.addAction(start_action)
        else:
            stop_action = Action(FluentIcon.PAUSE, '停止隧道')
            stop_action.triggered.connect(lambda: self.parent.stop_tunnel(self))
            menu.addAction(stop_action)

        log_action = Action(FluentIcon.DOCUMENT, '查看日志')
        log_action.triggered.connect(lambda: self.parent.show_tunnel_log(self))
        menu.addAction(log_action)
        menu.addSeparator()

        copy_action = Action(FluentIcon.COPY, '复制连接地址')
        copy_action.triggered.connect(lambda: self.copy_connection_address())
        menu.addAction(copy_action)

        if not is_running:
            edit_action = Action(FluentIcon.EDIT, '编辑隧道')
            edit_action.triggered.connect(lambda: self.parent.edit_tunnel(self))
            menu.addAction(edit_action)

            delete_action = Action(FluentIcon.DELETE, '删除隧道')
            delete_action.triggered.connect(lambda: self.parent.delete_tunnel(self))
            menu.addAction(delete_action)

        menu.exec(self.menu_button.mapToGlobal(self.menu_button.rect().bottomLeft()))

    def update_status(self, is_running):
        """更新隧道状态显示"""
        self.status_indicator.setRunning(is_running)

    def copy_connection_address(self):
        """复制连接地址"""
        tunnel_type = self.tunnel_info.get('type', '').lower()

        if tunnel_type in ['tcp', 'udp']:
            # TCP/UDP隧道：需要获取节点域名
            node_name = self.tunnel_info.get('node', '')
            external_port = self.tunnel_info.get('dorp', '')

            # 显示正在获取域名的提示
            InfoBar.info(
                title="正在获取",
                content="正在获取节点连接信息...",
                position=InfoBarPosition.TOP_RIGHT,
                duration=1000,
                parent=self.window()
            )

            # 尝试从父窗口获取节点域名
            node_domain = self.get_node_domain(node_name)

            if node_domain:
                connection_address = f"{node_domain}:{external_port}"
                message = f"连接地址已复制: {connection_address}"
            else:
                # 如果获取不到域名，使用节点名称构造默认域名
                connection_address = f"{node_name.lower()}.chmlfrp.cn:{external_port}"
                message = f"连接地址已复制（可能需要验证）: {connection_address}"

        elif tunnel_type in ['http', 'https']:
            # HTTP/HTTPS隧道：直接使用绑定的域名
            domain = self.tunnel_info.get('dorp', '')
            if tunnel_type == 'https':
                connection_address = f"https://{domain}"
            else:
                connection_address = f"http://{domain}"
            message = f"连接地址已复制: {connection_address}"
        else:
            InfoBar.error(
                title="错误",
                content="未知的隧道类型",
                position=InfoBarPosition.TOP_RIGHT,
                duration=3000,
                parent=self.window()
            )
            return

        # 复制到剪贴板
        QApplication.clipboard().setText(connection_address)
        InfoBar.success(
            title="成功",
            content=message,
            position=InfoBarPosition.TOP_RIGHT,
            duration=3000,
            parent=self.window()
        )

    def get_node_domain(self, node_name):
        """获取节点域名"""
        try:
            # 先尝试从缓存中获取
            if hasattr(self.parent, 'node_domain_cache') and node_name in self.parent.node_domain_cache:
                return self.parent.node_domain_cache[node_name]

            # 获取token
            token = token_manager.get_token()
            if not token:
                logging.warning("未登录，无法获取节点详细信息")
                return None

            # 调用nodeinfo API获取节点详细信息
            url = f"http://cf-v2.uapis.cn/nodeinfo?token={token}&node={node_name}"
            response = requests.get(url, timeout=5)

            if response.status_code == 200:
                data = response.json()
                if data.get("code") == 200:
                    node_data = data.get("data", {})
                    # 使用ip字段作为域名
                    domain = node_data.get('ip', '')

                    if domain:
                        # 缓存域名
                        if not hasattr(self.parent, 'node_domain_cache'):
                            self.parent.node_domain_cache = {}
                        self.parent.node_domain_cache[node_name] = domain
                        logging.info(f"成功获取节点 {node_name} 的域名: {domain}")
                        return domain
                    else:
                        logging.warning(f"节点 {node_name} 没有域名信息")

            # 如果获取失败，返回None
            logging.error(f"无法获取节点 {node_name} 的域名信息")
            return None

        except Exception as e:
            logging.error(f"获取节点域名失败: {e}")
            return None

class TunnelLoaderThread(QThread):
    dataLoaded = pyqtSignal(dict)

    def __init__(self, token):
        super().__init__()
        self.token = token

    def run(self):
        try:
            url = f"http://cf-v2.uapis.cn/tunnel?token={self.token}"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                self.dataLoaded.emit(data)
            else:
                self.dataLoaded.emit({"code": response.status_code, "msg": "请求失败"})
        except Exception as e:
            self.dataLoaded.emit({"code": 500, "msg": f"网络错误: {str(e)}"})
        finally:
            self.quit()

class TunnelDeleteThread(QThread):
    """隧道删除线程"""
    deleteFinished = pyqtSignal(bool, str)

    def __init__(self, token, tunnel_id):
        super().__init__()
        self.token = token
        self.tunnel_id = tunnel_id

    def run(self):
        try:
            url = f"http://cf-v2.uapis.cn/delete_tunnel?token={self.token}&tunnelid={self.tunnel_id}"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                if data.get("code") == 200:
                    self.deleteFinished.emit(True, data.get("msg", "删除成功"))
                else:
                    self.deleteFinished.emit(False, data.get("msg", "删除失败"))
            else:
                self.deleteFinished.emit(False, "请求失败")
        except Exception as e:
            self.deleteFinished.emit(False, f"网络错误: {str(e)}")
        finally:
            self.quit()

class TunnelOutputThread(QThread):
    def __init__(self, process, tunnel_name, parent):
        super().__init__()
        self.process = process
        self.tunnel_name = tunnel_name
        self.parent = parent
        self.running = True

    def run(self):
        try:
            def read_output():
                try:
                    buffer = b''
                    while self.running and self.process.poll() is None:
                        try:
                            chunk = self.process.stdout.read(1024)
                            if chunk:
                                buffer += chunk
                                while b'\n' in buffer:
                                    line, buffer = buffer.split(b'\n', 1)
                                    text = line.decode('utf-8', errors='replace').strip()
                                    if text:
                                        self.process_output_line(text)
                            else:
                                time.sleep(0.01)
                        except Exception as e:
                            logging.debug(f"Read chunk error: {e}")
                            time.sleep(0.1)
                    if buffer:
                        text = buffer.decode('utf-8', errors='replace').strip()
                        if text:
                            self.process_output_line(text)

                except Exception as e:
                    error_msg = f"输出读取错误: {str(e)}"
                    self.process_output_line(error_msg, is_error=True)

            output_thread = threading.Thread(target=read_output, daemon=True)
            output_thread.start()

            while self.running and self.process.poll() is None:
                time.sleep(0.1)

            self.running = False
            output_thread.join(timeout=2)

            exit_code = self.process.returncode
            self.process_output_line(f"进程已结束，退出代码: {exit_code}", is_system=True)

        except Exception as e:
            error_msg = f"输出捕获线程错误: {str(e)}"
            self.process_output_line(error_msg, is_error=True)
            logging.error(f"TunnelOutputThread error: {e}")
        finally:
            self.quit()

    def process_output_line(self, text, is_error=False, is_system=False):
        """处理单行输出"""
        try:
            if not text.strip():
                return

            safe_text = self.obfuscate_sensitive_data(text)
            timestamp = datetime.now().strftime('%H:%M:%S')

            if is_system:
                html_line = f"<span style='color: #ff9800;'>[{timestamp}] [SYS] {safe_text}</span><br>"
            elif is_error:
                html_line = f"<span style='color: #d32f2f;'>[{timestamp}] [ERR] {safe_text}</span><br>"
            else:
                html_line = f"<span style='color: #2e7d32;'>[{timestamp}] [OUT] {safe_text}</span><br>"

            with QMutexLocker(self.parent.output_mutex):
                if self.tunnel_name in self.parent.tunnel_outputs:
                    self.parent.tunnel_outputs[self.tunnel_name]['output'] += html_line

        except Exception as e:
            logging.error(f"Process output line error: {e}")

    def obfuscate_sensitive_data(self, text):
        """混淆敏感数据"""
        try:
            token = token_manager.get_token() or ""
            if token and len(token) > 10:
                text = text.replace(token, '*******Token*******')

            text = re.sub(r'\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b',
                          r'\1.***.***.\4', text)

            text = re.sub(r'\x1b\[[0-9;]*m', '', text)

            return text
        except Exception as e:
            logging.error(f"Error obfuscating data: {e}")
            return text

    def stop(self):
        """停止线程"""
        self.running = False

class TunnelUpdateThread(QThread):
    """隧道更新"""
    updateFinished = pyqtSignal(bool, str)

    def __init__(self, token, tunnel_id, tunnel_data):
        super().__init__()
        self.token = token
        self.tunnel_id = tunnel_id
        self.tunnel_data = tunnel_data

    def run(self):
        try:
            params = {
                'token': self.token,
                'tunnelid': self.tunnel_id,
                'tunnelname': self.tunnel_data['tunnelname'],
                'node': self.tunnel_data['node'],
                'localip': self.tunnel_data.get('localip', '127.0.0.1'),
                'porttype': self.tunnel_data['porttype'],
                'localport': self.tunnel_data['localport'],
                'encryption': str(self.tunnel_data['encryption']).lower(),
                'compression': str(self.tunnel_data['compression']).lower()
            }

            if self.tunnel_data['porttype'].lower() in ['tcp', 'udp']:
                params['remoteport'] = self.tunnel_data['remoteport']
            elif self.tunnel_data['porttype'].lower() in ['http', 'https']:
                params['banddomain'] = self.tunnel_data['banddomain']

            url = "https://cf-v2.uapis.cn/update_tunnel"
            headers = {
                'Content-Type': 'application/json',
                'User-Agent': USER_AGENT
            }

            response = requests.post(url, json=params, headers=headers, timeout=15)

            if response.status_code == 200:
                data = response.json()
                if data.get("code") == 200:
                    self.updateFinished.emit(True, data.get("msg", "隧道更新成功"))
                else:
                    self.updateFinished.emit(False, data.get("msg", "隧道更新失败"))
            else:
                self.updateFinished.emit(False, f"请求失败: HTTP {response.status_code}")

        except Exception as e:
            self.updateFinished.emit(False, f"网络错误: {str(e)}")
        finally:
            self.quit()

class TunnelEditDialog(MessageBoxBase):
    """隧道编辑对话框"""
    def __init__(self, tunnel_info, parent=None):
        super().__init__(parent)
        self.tunnel_info = tunnel_info
        self.nodes_list = []
        self.user_data = None
        self.selected_node_data = None
        self.setWindowTitle("编辑隧道")
        self.init_ui()
        QTimer.singleShot(100, self.load_user_info)

    def init_ui(self):
        """初始化界面"""
        self.resize(1000, 600)
        self.yesButton.hide()
        self.cancelButton.hide()

        main_widget = QWidget()
        main_layout = QHBoxLayout(main_widget)
        main_layout.setContentsMargins(0, 10, 0, 10)
        main_layout.setSpacing(20)

        left_widget = QWidget()
        left_widget.setFixedWidth(350)
        form_layout = QFormLayout(left_widget)
        form_layout.setContentsMargins(0, 0, 0, 0)
        form_layout.setSpacing(15)

        self.tunnel_name_edit = LineEdit()
        self.tunnel_name_edit.setText(self.tunnel_info.get('name', ''))
        self.tunnel_name_edit.setPlaceholderText("隧道名称（8位随机字符）")

        name_layout = QHBoxLayout()
        name_layout.addWidget(self.tunnel_name_edit)
        self.generate_name_btn = PushButton("变!")
        self.generate_name_btn.setFixedSize(42, 32)
        self.generate_name_btn.setToolTip("生成新的隧道名称")
        self.generate_name_btn.clicked.connect(self.regenerate_tunnel_name)
        name_layout.addWidget(self.generate_name_btn)

        name_widget = QWidget()
        name_widget.setLayout(name_layout)
        form_layout.addRow("隧道名称:", name_widget)

        self.node_combo = ComboBox()
        self.node_combo.setPlaceholderText("正在加载节点列表...")
        self.node_combo.currentIndexChanged.connect(self.on_node_selection_changed)
        form_layout.addRow("节点:", self.node_combo)

        self.local_ip_edit = LineEdit()
        self.local_ip_edit.setText(self.tunnel_info.get('localip', '127.0.0.1'))
        self.local_ip_edit.setPlaceholderText("本地IP地址")
        form_layout.addRow("本地IP:", self.local_ip_edit)

        self.port_type_combo = ComboBox()
        self.port_type_combo.addItems(["TCP", "UDP", "HTTP", "HTTPS"])
        current_type = self.tunnel_info.get('type', 'tcp').upper()
        self.port_type_combo.setCurrentText(current_type)
        self.port_type_combo.currentTextChanged.connect(self.on_port_type_changed)
        form_layout.addRow("端口类型:", self.port_type_combo)

        self.local_port_edit = SpinBox()
        self.local_port_edit.setRange(1, 65535)
        self.local_port_edit.setValue(int(self.tunnel_info.get('nport', 80)))
        form_layout.addRow("本地端口:", self.local_port_edit)

        self.remote_port_edit = SpinBox()
        self.remote_port_edit.setRange(1, 65535)

        if current_type in ['TCP', 'UDP']:
            remote_port = self.tunnel_info.get('dorp', '10000')
            try:
                self.remote_port_edit.setValue(int(remote_port))
            except:
                self.remote_port_edit.setValue(10000)

        remote_port_layout = QHBoxLayout()
        remote_port_layout.addWidget(self.remote_port_edit)
        self.generate_port_btn = PushButton("变!")
        self.generate_port_btn.setFixedSize(42, 32)
        self.generate_port_btn.setToolTip("随机生成远程端口")
        self.generate_port_btn.clicked.connect(self.randomize_remote_port)
        remote_port_layout.addWidget(self.generate_port_btn)

        remote_port_widget = QWidget()
        remote_port_widget.setLayout(remote_port_layout)

        self.remote_port_row_label = QLabel("远程端口:")
        form_layout.addRow(self.remote_port_row_label, remote_port_widget)

        self.domain_edit = LineEdit()
        if current_type in ['HTTP', 'HTTPS']:
            self.domain_edit.setText(self.tunnel_info.get('dorp', ''))
        self.domain_edit.setPlaceholderText("例如: example.chmlfrp.com")
        self.domain_row_label = QLabel("绑定域名:")
        form_layout.addRow(self.domain_row_label, self.domain_edit)

        self.encryption_switch = SwitchButton()
        self.encryption_switch.setChecked(self.tunnel_info.get('encryption', 'False') == 'True')
        form_layout.addRow("数据加密:", self.encryption_switch)

        self.compression_switch = SwitchButton()
        self.compression_switch.setChecked(self.tunnel_info.get('compression', 'False') == 'True')
        form_layout.addRow("数据压缩:", self.compression_switch)

        self.right_widget = QWidget()
        self.right_widget.setFixedWidth(450)
        self.init_node_detail_area()

        main_layout.addWidget(left_widget)
        main_layout.addWidget(self.right_widget)

        self.viewLayout.addWidget(main_widget)

        self.update_button = PrimaryPushButton("更新隧道")
        self.update_button.clicked.connect(self.update_tunnel)
        self.update_button.setEnabled(False)

        self.cancel_button = PushButton("取消")
        self.cancel_button.clicked.connect(self.close)

        while self.buttonLayout.count():
            item = self.buttonLayout.takeAt(0)
            if item.widget():
                item.widget().hide()

        self.buttonLayout.addStretch()
        self.buttonLayout.addWidget(self.update_button)
        self.buttonLayout.addWidget(self.cancel_button)
        self.buttonLayout.addStretch()

        self.on_port_type_changed(current_type)

    def randomize_remote_port(self):
        """随机生成远程端口"""
        min_port = self.remote_port_edit.minimum()
        max_port = self.remote_port_edit.maximum()
        random_port = random.randint(min_port, max_port)
        self.remote_port_edit.setValue(random_port)

        InfoBar.success(
            title="随机端口",
            content=f"已随机生成端口: {random_port}",
            position=InfoBarPosition.TOP_RIGHT,
            duration=1500,
            parent=self.window()
        )

    def generate_tunnel_name(self):
        """生成8位随机隧道名称"""
        characters = string.ascii_letters + string.digits
        return ''.join(random.choice(characters) for _ in range(8))

    def regenerate_tunnel_name(self):
        """重新生成隧道名称"""
        self.tunnel_name_edit.setText(self.generate_tunnel_name())

    def load_user_info(self):
        """加载用户信息"""
        token = token_manager.get_token()
        if not token:
            self.show_info_bar("error", "未登录", "请先登录后再编辑隧道")
            self.close()
            return

        try:
            url = f"http://cf-v2.uapis.cn/userinfo?token={token}"
            response = requests.get(url, timeout=10)

            if response.status_code == 200:
                data = response.json()
                if data.get("code") == 200:
                    self.user_data = data.get("data", {})
                    # 用户信息获取成功后加载节点
                    self.load_nodes()
                else:
                    self.show_info_bar("error", "获取用户信息失败", data.get("msg", "未知错误"))
                    self.close()
            else:
                self.show_info_bar("error", "网络错误", "无法获取用户信息")
                self.close()
        except Exception as e:
            self.show_info_bar("error", "网络错误", f"获取用户信息失败: {str(e)}")
            self.close()

    def init_node_detail_area(self):
        """初始化节点详情区域"""
        detail_layout = QVBoxLayout(self.right_widget)
        detail_layout.setContentsMargins(0, 0, 0, 0)
        detail_layout.setSpacing(15)

        title_label = SubtitleLabel("节点详情", self.right_widget)
        detail_layout.addWidget(title_label)

        self.node_detail_card = CardWidget(self.right_widget)
        self.node_detail_card.setBorderRadius(8)
        self.node_detail_card.setMinimumHeight(500)

        self.detail_content_layout = QVBoxLayout(self.node_detail_card)
        self.detail_content_layout.setContentsMargins(20, 20, 20, 20)
        self.detail_content_layout.setSpacing(10)

        self.show_default_tip()

        detail_layout.addWidget(self.node_detail_card)

    def show_default_tip(self):
        """显示默认提示"""
        self.clear_node_detail()
        no_selection_label = BodyLabel("当前节点详情将在加载完成后显示", self.node_detail_card)
        no_selection_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        no_selection_label.setTextColor("#666666", "#cccccc")
        self.detail_content_layout.addWidget(no_selection_label)

    def load_nodes(self):
        """加载节点列表"""
        self.node_combo.clear()
        self.node_combo.addItem("正在加载节点列表...")
        self.node_combo.setEnabled(False)
        self.update_button.setEnabled(False)

        self.node_thread = NodeListThread()
        self.node_thread.nodeListLoaded.connect(self.on_nodes_loaded)
        self.node_thread.loadError.connect(self.on_nodes_load_error)
        self.node_thread.start()

    def on_nodes_loaded(self, nodes):
        """节点列表加载完成"""
        self.nodes_list = nodes
        self.node_combo.clear()
        self.node_combo.setEnabled(True)

        if not nodes:
            self.node_combo.addItem("暂无可用节点")
            self.update_button.setEnabled(False)
            self.show_info_bar("warning", "警告", "暂无在线节点，无法编辑隧道")
            return

        user_group = self.user_data.get("usergroup", "free") if self.user_data else "free"
        filtered_nodes = []

        for node in nodes:
            if user_group == "免费用户" and node.get("nodegroup") == "vip":
                continue
            filtered_nodes.append(node)

        if not filtered_nodes:
            self.node_combo.addItem("您的权限组无可用节点")
            self.update_button.setEnabled(False)
            self.show_info_bar("warning", "权限不足", "您当前的权限组没有可用的节点")
            return

        sorted_nodes = sorted(filtered_nodes, key=lambda x: (
            0 if x.get("nodegroup") == "vip" else 1,
            x.get("area", "")
        ))

        self.node_map = {}

        for node in sorted_nodes:
            node_name = node.get("name", "未知节点")
            self.node_combo.addItem(node_name, node_name)
            # 保存节点名称到节点数据的映射
            self.node_map[node_name] = node

        current_node = self.tunnel_info.get('node', '')
        index = self.node_combo.findText(current_node)
        if index >= 0:
            self.node_combo.setCurrentIndex(index)
        else:
            self.node_combo.insertItem(0, f"原节点: {current_node} (不可用)")
            self.node_combo.setCurrentIndex(0)

        self.show_info_bar("success", "加载成功", f"成功加载 {len(filtered_nodes)} 个节点", 2000)

    def on_nodes_load_error(self, error_message):
        """节点加载失败处理"""
        self.node_combo.clear()
        self.node_combo.addItem("加载失败，点击重试")
        self.node_combo.setEnabled(True)
        self.update_button.setEnabled(False)
        self.show_info_bar("error", "加载失败", error_message, 5000)

    def on_node_selection_changed(self, index):
        """节点选择改变事件"""
        if index < 0:
            self.selected_node_data = None
            self.update_button.setEnabled(False)
            return

        node_name = self.node_combo.currentText()

        if node_name in ["正在加载节点列表...", "暂无可用节点", "您的权限组无可用节点"] or node_name.startswith(
                "原节点:"):
            self.selected_node_data = None
            self.update_button.setEnabled(True)
            return

        if node_name and hasattr(self, 'node_map') and node_name in self.node_map:
            node_data = self.node_map[node_name]
            self.display_basic_node_info(node_data)
            self.load_node_detail(node_name)
            self.update_button.setEnabled(True)
        else:
            self.selected_node_data = None
            self.update_button.setEnabled(True)  # 允许更新

    def load_node_detail(self, node_name):
        """加载节点详细信息"""
        token = token_manager.get_token()
        if not token:
            return

        self.node_detail_thread = NodeDetailThread(token, node_name)
        self.node_detail_thread.nodeDetailLoaded.connect(self.on_node_detail_loaded)
        self.node_detail_thread.loadError.connect(self.on_node_detail_error)
        self.node_detail_thread.start()

    def display_basic_node_info(self, node_data):
        self.clear_node_detail()

        name_label = TitleLabel(node_data.get("name", "未知节点"), self.node_detail_card)
        name_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.detail_content_layout.addWidget(name_label)

        loading_label = BodyLabel("正在加载详细信息...", self.node_detail_card)
        loading_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        loading_label.setTextColor("#666666", "#cccccc")
        self.detail_content_layout.addWidget(loading_label)

        basic_widget = QWidget()
        basic_layout = QVBoxLayout(basic_widget)
        basic_layout.setSpacing(5)

        if node_data.get("area"):
            area_label = CaptionLabel(f"地区: {node_data.get('area')}", basic_widget)
            basic_layout.addWidget(area_label)
        if node_data.get("nodegroup") == "vip":
            vip_label = CaptionLabel("节点类型: VIP", basic_widget)
            vip_label.setStyleSheet("color: #FF9800;")
            basic_layout.addWidget(vip_label)
        else:
            free_label = CaptionLabel("节点类型: 免费", basic_widget)
            basic_layout.addWidget(free_label)

        self.detail_content_layout.addWidget(basic_widget)
        self.detail_content_layout.addStretch()

    def clear_node_detail(self):
        """清空节点详情显示"""
        while self.detail_content_layout.count():
            item = self.detail_content_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

    def on_node_detail_loaded(self, node_data):
        """节点详情加载完成"""
        self.selected_node_data = node_data
        self.update_button.setEnabled(True)
        self.display_node_detail(node_data)

    def on_node_detail_error(self, error_message):
        """节点详情加载失败"""
        self.update_button.setEnabled(True)
        self.clear_node_detail()

        error_widget = QWidget()
        error_layout = QVBoxLayout(error_widget)

        node_name = self.node_combo.currentText()
        name_label = TitleLabel(node_name, error_widget)
        name_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        error_layout.addWidget(name_label)

        error_label = BodyLabel(f"加载节点详情失败: {error_message}", error_widget)
        error_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        error_label.setTextColor("#e74c3c", "#e74c3c")
        error_label.setWordWrap(True)
        error_layout.addWidget(error_label)

        tip_label = CaptionLabel("您仍然可以更新隧道", error_widget)
        tip_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        tip_label.setTextColor("#666666", "#cccccc")
        error_layout.addWidget(tip_label)

        self.detail_content_layout.addWidget(error_widget)
        self.detail_content_layout.addStretch()

    def display_node_detail(self, node_data):
        """显示节点详细信息"""
        self.clear_node_detail()

        name_label = TitleLabel(node_data.get("name", "未知节点"), self.node_detail_card)
        name_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.detail_content_layout.addWidget(name_label)

        status_widget = self.create_status_widget(node_data)
        self.detail_content_layout.addWidget(status_widget)

        basic_info_widget = self.create_basic_info_widget(node_data)
        self.detail_content_layout.addWidget(basic_info_widget)

        port_info_widget = self.create_port_info_widget(node_data)
        self.detail_content_layout.addWidget(port_info_widget)

        self.update_port_range(node_data)
        self.detail_content_layout.addStretch()

    def create_status_widget(self, node_data):
        """创建状态信息组件"""
        status_widget = QWidget()
        status_layout = QHBoxLayout(status_widget)
        status_layout.setContentsMargins(0, 10, 0, 10)
        status_layout.setSpacing(10)

        if node_data.get("state") == "online":
            status_badge = InfoBadge.success("在线", status_widget)
        else:
            status_badge = InfoBadge.error("离线", status_widget)

        if node_data.get("nodegroup") == "vip":
            type_badge = InfoBadge.custom("VIP", "#FF9800", "#FFF3E0", status_widget)
        else:
            type_badge = InfoBadge.info("免费", status_widget)

        if str(node_data.get("udp")).lower() == "true":
            udp_badge = InfoBadge.info("UDP", status_widget)
            status_layout.addWidget(udp_badge)

        if str(node_data.get("web")).lower() == "yes":
            web_badge = InfoBadge.success("Web", status_widget)
            status_layout.addWidget(web_badge)

        status_layout.addWidget(status_badge)
        status_layout.addWidget(type_badge)
        status_layout.addStretch()

        return status_widget

    def create_basic_info_widget(self, node_data):
        """创建基本信息组件"""
        info_widget = QWidget()
        info_layout = QVBoxLayout(info_widget)
        info_layout.setContentsMargins(0, 10, 0, 10)
        info_layout.setSpacing(8)

        info_title = StrongBodyLabel("基本信息", info_widget)
        info_layout.addWidget(info_title)

        info_items = [
            ("地区", node_data.get("area", "未知")),
            ("IP地址", node_data.get("ip", "未知")),
            ("端口", str(node_data.get("port", "未知"))),
            ("版本", node_data.get("version", "未知")),
        ]

        for label, value in info_items:
            item_layout = QHBoxLayout()
            label_widget = CaptionLabel(f"{label}:", info_widget)
            label_widget.setTextColor("#666666", "#cccccc")
            value_widget = BodyLabel(str(value), info_widget)

            item_layout.addWidget(label_widget)
            item_layout.addWidget(value_widget)
            item_layout.addStretch()
            info_layout.addLayout(item_layout)

        return info_widget

    def create_port_info_widget(self, node_data):
        """创建端口信息组件"""
        port_widget = QWidget()
        port_layout = QVBoxLayout(port_widget)
        port_layout.setContentsMargins(0, 10, 0, 10)
        port_layout.setSpacing(8)

        port_title = StrongBodyLabel("端口配置", port_widget)
        port_layout.addWidget(port_title)

        rport = node_data.get("rport", "未知")
        if rport != "未知" and "-" in str(rport):
            try:
                start_port, end_port = map(int, str(rport).split("-"))
                port_range_text = f"{start_port} - {end_port} (共 {end_port - start_port + 1} 个端口)"
            except:
                port_range_text = str(rport)
        else:
            port_range_text = str(rport)

        port_info_layout = QHBoxLayout()
        port_label = CaptionLabel("外部端口范围:", port_widget)
        port_label.setTextColor("#666666", "#cccccc")
        port_value = BodyLabel(port_range_text, port_widget)

        port_info_layout.addWidget(port_label)
        port_info_layout.addWidget(port_value)
        port_info_layout.addStretch()

        port_layout.addLayout(port_info_layout)

        return port_widget

    def update_port_range(self, node_data):
        """根据节点信息更新端口范围"""
        rport = node_data.get("rport", "")
        if rport and "-" in str(rport):
            try:
                start_port, end_port = map(int, str(rport).split("-"))
                self.remote_port_edit.setRange(start_port, end_port)
            except ValueError:
                self.remote_port_edit.setRange(1, 65535)
        else:
            self.remote_port_edit.setRange(1, 65535)

    def on_port_type_changed(self, port_type):
        """端口类型改变时的处理"""
        if port_type.upper() in ["TCP", "UDP"]:
            self.remote_port_edit.show()
            self.generate_port_btn.show()
            self.remote_port_row_label.show()
            self.domain_edit.hide()
            self.domain_row_label.hide()
        else:
            self.remote_port_edit.hide()
            self.generate_port_btn.hide()
            self.remote_port_row_label.hide()
            self.domain_edit.show()
            self.domain_row_label.show()

    def validate_input(self):
        """验证输入"""
        tunnel_name = self.tunnel_name_edit.text().strip()
        if not tunnel_name:
            return False, "请输入隧道名称"

        if len(tunnel_name) != 8:
            return False, "隧道名称必须为8位字符"

        if not re.match(r'^[a-zA-Z0-9]+$', tunnel_name):
            return False, "隧道名称只能包含字母和数字"

        node_text = self.node_combo.currentText()
        if not node_text or node_text.startswith("原节点:") or node_text in ["正在加载节点列表...", "暂无可用节点",
                                                                             "您的权限组无可用节点"]:
            return False, "请选择一个有效的节点"

        local_ip = self.local_ip_edit.text().strip()
        if not local_ip:
            return False, "请输入本地IP"

        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if not re.match(ip_pattern, local_ip):
            return False, "请输入有效的IP地址"

        port_type = self.port_type_combo.currentText().upper()

        if port_type in ["TCP", "UDP"]:
            remote_port = self.remote_port_edit.value()
            if remote_port < 1 or remote_port > 65535:
                return False, "远程端口必须在1-65535之间"
        else:
            domain = self.domain_edit.text().strip()
            if not domain:
                return False, "请输入绑定域名"

            domain_pattern = r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(domain_pattern, domain):
                return False, "请输入有效的域名格式"

        return True, ""

    def update_tunnel(self):
        """更新隧道"""
        is_valid, error_msg = self.validate_input()
        if not is_valid:
            self.show_info_bar("error", "输入错误", error_msg)
            return

        token = token_manager.get_token()
        if not token:
            self.show_info_bar("error", "未登录", "请先登录后再更新隧道")
            return

        tunnel_data = {
            'tunnelname': self.tunnel_name_edit.text().strip(),
            'node': self.node_combo.currentText(),
            'localip': self.local_ip_edit.text().strip(),
            'porttype': self.port_type_combo.currentText().lower(),
            'localport': self.local_port_edit.value(),
            'encryption': self.encryption_switch.isChecked(),
            'compression': self.compression_switch.isChecked()
        }

        if tunnel_data['porttype'] in ['tcp', 'udp']:
            tunnel_data['remoteport'] = self.remote_port_edit.value()
        else:
            tunnel_data['banddomain'] = self.domain_edit.text().strip()

        self.update_button.setText("更新中...")
        self.update_button.setEnabled(False)

        self.update_thread = TunnelUpdateThread(token, self.tunnel_info['id'], tunnel_data)
        self.update_thread.updateFinished.connect(self.on_update_finished)
        self.update_thread.start()

    def on_update_finished(self, success, message):
        """隧道更新完成"""
        self.update_button.setText("更新隧道")
        self.update_button.setEnabled(True)

        if success:
            main_window = self
            while main_window.parent():
                main_window = main_window.parent()

            InfoBar.success(
                title="更新成功",
                content=message,
                position=InfoBarPosition.TOP_RIGHT,
                duration=3000,
                parent=main_window
            )
            self.close()

            if hasattr(self.parent(), 'load_tunnels'):
                QTimer.singleShot(1000, self.parent().load_tunnels)
        else:
            self.show_info_bar("error", "更新失败", message, 5000)

        if hasattr(self, 'update_thread'):
            self.update_thread.deleteLater()
            del self.update_thread

    def show_info_bar(self, bar_type, title, content, duration=3000):
        """统一的信息条显示方法"""
        main_window = self
        while main_window.parent():
            main_window = main_window.parent()

        if bar_type == "success":
            InfoBar.success(
                title=title,
                content=content,
                position=InfoBarPosition.TOP_RIGHT,
                duration=duration,
                parent=main_window
            )
        elif bar_type == "error":
            InfoBar.error(
                title=title,
                content=content,
                position=InfoBarPosition.TOP_RIGHT,
                duration=duration,
                parent=main_window
            )
        elif bar_type == "warning":
            InfoBar.warning(
                title=title,
                content=content,
                position=InfoBarPosition.TOP_RIGHT,
                duration=duration,
                parent=main_window
            )
        elif bar_type == "info":
            InfoBar.info(
                title=title,
                content=content,
                position=InfoBarPosition.TOP_RIGHT,
                duration=duration,
                parent=main_window
            )

class TunnelLogDialog(MessageBoxBase):
    """隧道日志对话框"""
    def __init__(self, tunnel_name, initial_output, run_number, parent=None):
        super().__init__(parent)
        self.tunnel_name = tunnel_name
        self.run_number = run_number
        self.parent_widget = parent
        self.last_output_length = 0

        self.init_ui()
        self.add_output(tunnel_name, initial_output, run_number)

        self.update_timer = QTimer(self)
        self.update_timer.timeout.connect(self.refresh_log)
        self.update_timer.start(500)  # 500ms

    def init_ui(self):
        """初始化界面"""
        self.setWindowTitle(f"隧道 {self.tunnel_name} 运行日志")
        self.resize(wide, high)
        self.setMinimumSize(800, 600)

        self.log_browser = QTextBrowser(self)
        self.log_browser.setOpenExternalLinks(True)
        self.log_browser.setStyleSheet("""
            QTextBrowser {
                background-color: #f8f9fa;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 11px;
                line-height: 1.4;
                padding: 10px;
                border: 1px solid #dee2e6;
                border-radius: 4px;
            }
        """)

        self.log_browser.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOn)
        self.viewLayout.addWidget(self.log_browser)
        self.status_layout = QHBoxLayout()
        self.status_label = CaptionLabel(f"运行 #{self.run_number} | 实时日志", self)
        self.status_label.setTextColor("#666666", "#cccccc")

        self.auto_scroll_switch = SwitchButton(self)
        self.auto_scroll_switch.setChecked(True)

        self.status_layout.addWidget(self.status_label)
        self.status_layout.addStretch()
        self.status_layout.addWidget(QLabel("自动滚动:"))
        self.status_layout.addWidget(self.auto_scroll_switch)

        self.viewLayout.addLayout(self.status_layout)

        self.clear_button = PushButton("清除日志", self)
        self.clear_button.setIcon(FluentIcon.DELETE)
        self.clear_button.clicked.connect(self.clear_log)

        self.copy_button = PushButton("复制全部", self)
        self.copy_button.setIcon(FluentIcon.COPY)
        self.copy_button.clicked.connect(self.copy_log)

        self.save_button = PushButton("保存日志", self)
        self.save_button.setIcon(FluentIcon.SAVE)
        self.save_button.clicked.connect(self.save_log)

        self.refresh_button = PushButton("刷新", self)
        self.refresh_button.setIcon(FluentIcon.SYNC)
        self.refresh_button.clicked.connect(self.force_refresh)

        self.buttonLayout.addWidget(self.clear_button, 0, Qt.AlignmentFlag.AlignCenter)
        self.buttonLayout.addWidget(self.copy_button, 0, Qt.AlignmentFlag.AlignCenter)
        self.buttonLayout.addWidget(self.save_button, 0, Qt.AlignmentFlag.AlignCenter)
        self.buttonLayout.addWidget(self.refresh_button, 0, Qt.AlignmentFlag.AlignCenter)
        self.buttonLayout.addStretch(1)
        self.buttonLayout.addWidget(self.clear_button, 0, Qt.AlignmentFlag.AlignCenter)

        self.cancelButton.hide()

    def refresh_log(self):
        """定时刷新日志内容"""
        if not self.parent_widget:
            return

        try:
            with QMutexLocker(self.parent_widget.output_mutex):
                if self.tunnel_name in self.parent_widget.tunnel_outputs:
                    tunnel_output = self.parent_widget.tunnel_outputs[self.tunnel_name]
                    current_output = tunnel_output.get('output', '')
                    current_run_number = tunnel_output.get('run_number', 0)

                    if current_run_number != self.run_number:
                        self.run_number = current_run_number
                        self.status_label.setText(f"运行 #{self.run_number} | 实时日志")
                        self.setWindowTitle(f"隧道 {self.tunnel_name} 运行日志 (运行 #{self.run_number})")

                    if len(current_output) != self.last_output_length:
                        self.last_output_length = len(current_output)
                        self.log_browser.setHtml(current_output)

                        if self.auto_scroll_switch.isChecked():
                            scrollbar = self.log_browser.verticalScrollBar()
                            scrollbar.setValue(scrollbar.maximum())
        except Exception as e:
            logging.error(f"刷新日志失败: {e}")

    def add_output(self, tunnel_name, output, run_number=None):
        """添加输出内容"""
        if tunnel_name == self.tunnel_name:
            if run_number is not None and run_number != self.run_number:
                self.run_number = run_number
                self.status_label.setText(f"运行 #{self.run_number} | 实时日志")
                self.setWindowTitle(f"隧道 {self.tunnel_name} 运行日志 (运行 #{self.run_number})")

            self.log_browser.setHtml(output)
            self.last_output_length = len(output)

            if self.auto_scroll_switch.isChecked():
                scrollbar = self.log_browser.verticalScrollBar()
                scrollbar.setValue(scrollbar.maximum())

    def force_refresh(self):
        """强制刷新日志"""
        self.refresh_log()
        InfoBar.success(
            title="刷新完成",
            content="日志已刷新",
            position=InfoBarPosition.TOP_RIGHT,
            duration=1000,
            parent=self
        )

    def clear_log(self):
        """清除日志"""
        self.log_browser.clear()
        self.last_output_length = 0

        if self.parent_widget:
            with QMutexLocker(self.parent_widget.output_mutex):
                if self.tunnel_name in self.parent_widget.tunnel_outputs:
                    self.parent_widget.tunnel_outputs[self.tunnel_name][
                        'output'] = f"<b>===== 日志已清除 ({datetime.now().strftime('%H:%M:%S')}) =====</b><br>"

        InfoBar.success(
            title="清除成功",
            content="日志已清除",
            position=InfoBarPosition.TOP_RIGHT,
            duration=1000,
            parent=self
        )

    def copy_log(self):
        """复制日志内容"""
        plain_text = self.log_browser.toPlainText()

        token = token_manager.get_token() or ""
        if token and len(token) > 10:
            plain_text = plain_text.replace(token, '*******Token*******')

        plain_text = re.sub(r'\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b',
                            r'\1.***.***.\4', plain_text)

        QApplication.clipboard().setText(plain_text)
        InfoBar.success(
            title="复制成功",
            content="日志内容已复制到剪贴板",
            position=InfoBarPosition.TOP_RIGHT,
            duration=2000,
            parent=self
        )

    def save_log(self):
        """保存日志到文件"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            default_filename = f"tunnel_{self.tunnel_name}_{timestamp}.txt"

            file_path, _ = QFileDialog.getSaveFileName(
                self,
                "保存日志文件",
                default_filename,
                "文本文件 (*.txt);;HTML文件 (*.html);;所有文件 (*.*)"
            )

            if file_path:
                if file_path.lower().endswith('.html'):
                    content = self.log_browser.toHtml()
                else:
                    content = self.log_browser.toPlainText()

                token = token_manager.get_token() or ""
                if token and len(token) > 10:
                    content = content.replace(token, '*******Token*******')

                content = re.sub(r'\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b',
                                 r'\1.***.***.\4', content)

                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)

                InfoBar.success(
                    title="保存成功",
                    content=f"日志已保存到: {file_path}",
                    position=InfoBarPosition.TOP_RIGHT,
                    duration=3000,
                    parent=self
                )
        except Exception as e:
            InfoBar.error(
                title="保存失败",
                content=f"保存日志时发生错误: {str(e)}",
                position=InfoBarPosition.TOP_RIGHT,
                duration=3000,
                parent=self
            )

    def closeEvent(self, event):
        """窗口关闭事件"""
        if self.loader_thread and self.loader_thread.isRunning():
            self.loader_thread.terminate()
            self.loader_thread.wait(1000)
        if hasattr(self, 'status_timer'):
            self.status_timer.stop()
        with QMutexLocker(self.process_lock):
            for process in self.tunnel_processes.values():
                try:
                    process.terminate()
                except:
                    pass
        event.accept()

    def close(self):
        """关闭对话框"""
        if hasattr(self, 'update_timer'):
            self.update_timer.stop()

        if self.parent_widget:
            with QMutexLocker(self.parent_widget.output_mutex):
                if self.tunnel_name in self.parent_widget.tunnel_outputs:
                    self.parent_widget.tunnel_outputs[self.tunnel_name]['dialog'] = None
        super().close()

class StatusIndicator(QWidget):
    """状态指示器组件 - 圆形LED灯效果"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.is_running = False
        self._opacity = 1.0

        self.animation = QPropertyAnimation(self, b"opacity")
        self.animation.setDuration(1000)
        self.animation.setStartValue(0.3)
        self.animation.setEndValue(1.0)
        self.animation.setLoopCount(-1)

    def setRunning(self, running):
        """设置运行状态"""
        self.is_running = running
        if running:
            self.animation.start()
            self.setToolTip("隧道运行中")
        else:
            self.animation.stop()
            self._opacity = 1.0
            self.setToolTip("隧道已停止")
        self.update()

    @pyqtProperty(float)
    def opacity(self):
        return self._opacity

    @opacity.setter
    def opacity(self, value):
        self._opacity = value
        self.update()

    def paintEvent(self, event):
        """绘制状态指示器"""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        pen = QPen()
        pen.setWidth(1)

        if self.is_running:
            # 运行中 - 绿色
            base_color = QColor(46, 204, 113)  # #2ecc71
            pen.setColor(QColor(39, 174, 96))  # #27ae60
        else:
            # 已停止 - 红色
            base_color = QColor(231, 76, 60)  # #e74c3c
            pen.setColor(QColor(192, 57, 43))  # #c0392b

        painter.setPen(pen)

        if self.is_running:
            base_color.setAlphaF(self._opacity)

        painter.setBrush(QBrush(base_color))

        rect = self.rect()
        size = min(rect.width(), rect.height()) - 2
        x = (rect.width() - size) // 2
        y = (rect.height() - size) // 2

        painter.drawEllipse(x, y, size, size)

        if self.is_running:
            highlight_color = QColor(255, 255, 255, int(60 * self._opacity))
        else:
            highlight_color = QColor(255, 255, 255, 30)

        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QBrush(highlight_color))
        painter.drawEllipse(x + size // 4, y + size // 4, size // 3, size // 3)

class TunnelCreateThread(QThread):
    """隧道创建线程"""
    createFinished = pyqtSignal(bool, str)

    def __init__(self, token, tunnel_data):
        super().__init__()
        self.token = token
        self.tunnel_data = tunnel_data

    def run(self):
        try:
            # 构建请求参数
            params = {
                'token': self.token,
                'tunnelname': self.tunnel_data['tunnelname'],
                'node': self.tunnel_data['node'],
                'localip': self.tunnel_data.get('localip', '127.0.0.1'),
                'porttype': self.tunnel_data['porttype'],
                'localport': self.tunnel_data['localport'],
                'encryption': str(self.tunnel_data['encryption']).lower(),
                'compression': str(self.tunnel_data['compression']).lower()
            }

            if self.tunnel_data['porttype'].lower() in ['tcp', 'udp']:
                params['remoteport'] = self.tunnel_data['remoteport']
            elif self.tunnel_data['porttype'].lower() in ['http', 'https']:
                params['banddomain'] = self.tunnel_data['banddomain']

            url = "http://cf-v2.uapis.cn/create_tunnel"
            headers = {
                'Content-Type': 'application/json',
                'User-Agent': USER_AGENT
            }

            response = requests.post(url, json=params, headers=headers, timeout=15)

            if response.status_code == 200:
                data = response.json()
                if data.get("code") == 200:
                    self.createFinished.emit(True, data.get("msg", "隧道创建成功"))
                else:
                    self.createFinished.emit(False, data.get("msg", "隧道创建失败"))
            else:
                self.createFinished.emit(False, f"请求失败: HTTP {response.status_code}")

        except Exception as e:
            self.createFinished.emit(False, f"网络错误: {str(e)}")
        finally:
            self.quit()

class NodeListThread(QThread):
    """节点列表获取线程"""
    nodeListLoaded = pyqtSignal(list)
    loadError = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.api_url = "http://cf-v2.uapis.cn/node"
        self.timeout = 10  # 10秒超时

    def run(self):
        """在子线程中执行网络请求"""
        try:
            response = requests.get(
                self.api_url,
                timeout=self.timeout,
                headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                }
            )

            if response.status_code != 200:
                self.loadError.emit(f"HTTP错误: {response.status_code}")
                return

            try:
                data = response.json()
            except json.JSONDecodeError as e:
                self.loadError.emit(f"JSON解析错误: {str(e)}")
                return

            if not isinstance(data, dict):
                self.loadError.emit("API响应格式错误: 不是有效的JSON对象")
                return

            if data.get("code") != 200:
                error_msg = data.get("msg", "未知错误")
                self.loadError.emit(f"API错误: {error_msg}")
                return

            nodes = data.get("data", [])
            if not isinstance(nodes, list):
                self.loadError.emit("节点数据格式错误: data字段不是数组")
                return

            valid_nodes = []
            for node in nodes:
                if self.validate_node(node):
                    valid_nodes.append(node)

            self.nodeListLoaded.emit(valid_nodes)

        except requests.exceptions.Timeout:
            self.loadError.emit("请求超时，请检查网络连接")
        except requests.exceptions.ConnectionError:
            self.loadError.emit("网络连接错误，无法访问API")
        except requests.exceptions.RequestException as e:
            self.loadError.emit(f"网络请求错误: {str(e)}")
        except Exception as e:
            self.loadError.emit(f"未知错误: {str(e)}")

    def validate_node(self, node):
        """验证节点数据格式"""
        if not isinstance(node, dict):
            return False
        required_fields = ["id", "name", "area", "nodegroup"]
        for field in required_fields:
            if field not in node:
                return False

        return True

class TunnelAddDialog(MessageBoxBase):
    """隧道添加对话框"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.nodes_list = []
        self.user_data = None
        self.selected_node_data = None
        self.setWindowTitle("添加隧道")
        self.init_ui()
        QTimer.singleShot(100, self.load_user_info)

    def init_ui(self):
        """初始化界面"""
        self.resize(1000, 600)

        self.yesButton.hide()
        self.cancelButton.hide()

        main_widget = QWidget()
        main_layout = QHBoxLayout(main_widget)
        main_layout.setContentsMargins(0, 10, 0, 10)
        main_layout.setSpacing(20)

        left_widget = QWidget()
        left_widget.setFixedWidth(350)
        form_layout = QFormLayout(left_widget)
        form_layout.setContentsMargins(0, 0, 0, 0)
        form_layout.setSpacing(15)

        self.tunnel_name_edit = LineEdit()
        self.tunnel_name_edit.setText(self.generate_tunnel_name())
        self.tunnel_name_edit.setPlaceholderText("隧道名称（8位随机字符）")

        name_layout = QHBoxLayout()
        name_layout.addWidget(self.tunnel_name_edit)
        self.generate_name_btn = PushButton("变!")
        self.generate_name_btn.setFixedSize(42, 32)
        self.generate_name_btn.setToolTip("生成新的隧道名称")
        self.generate_name_btn.clicked.connect(self.regenerate_tunnel_name)
        name_layout.addWidget(self.generate_name_btn)

        name_widget = QWidget()
        name_widget.setLayout(name_layout)
        form_layout.addRow("隧道名称:", name_widget)

        self.node_combo = ComboBox()
        self.node_combo.setPlaceholderText("正在加载节点列表...")
        self.node_combo.currentIndexChanged.connect(self.on_node_selection_changed)
        form_layout.addRow("节点:", self.node_combo)

        self.local_ip_edit = LineEdit()
        self.local_ip_edit.setText("127.0.0.1")
        self.local_ip_edit.setPlaceholderText("本地IP地址")
        form_layout.addRow("本地IP:", self.local_ip_edit)

        self.port_type_combo = ComboBox()
        self.port_type_combo.addItems(["TCP", "UDP", "HTTP", "HTTPS"])
        self.port_type_combo.setCurrentText("TCP")
        self.port_type_combo.currentTextChanged.connect(self.on_port_type_changed)
        form_layout.addRow("端口类型:", self.port_type_combo)

        self.local_port_edit = SpinBox()
        self.local_port_edit.setRange(1, 65535)
        self.local_port_edit.setValue(80)
        form_layout.addRow("本地端口:", self.local_port_edit)

        self.remote_port_edit = SpinBox()
        self.remote_port_edit.setRange(1, 65535)
        self.remote_port_edit.setValue(10000)

        remote_port_layout = QHBoxLayout()
        remote_port_layout.addWidget(self.remote_port_edit)
        self.generate_port_btn = PushButton("变!")
        self.generate_port_btn.setFixedSize(42, 32)
        self.generate_port_btn.setToolTip("随机生成远程端口")
        self.generate_port_btn.clicked.connect(self.randomize_remote_port)
        remote_port_layout.addWidget(self.generate_port_btn)

        remote_port_widget = QWidget()
        remote_port_widget.setLayout(remote_port_layout)

        self.remote_port_row_label = QLabel("远程端口:")
        form_layout.addRow(self.remote_port_row_label, remote_port_widget)

        self.domain_edit = LineEdit()
        self.domain_edit.setPlaceholderText("例如: example.chmlfrp.com")
        self.domain_row_label = QLabel("绑定域名:")
        form_layout.addRow(self.domain_row_label, self.domain_edit)

        self.encryption_switch = SwitchButton()
        self.encryption_switch.setChecked(False)
        form_layout.addRow("数据加密:", self.encryption_switch)

        self.compression_switch = SwitchButton()
        self.compression_switch.setChecked(False)
        form_layout.addRow("数据压缩:", self.compression_switch)

        self.right_widget = QWidget()
        self.right_widget.setFixedWidth(450)
        self.init_node_detail_area()

        main_layout.addWidget(left_widget)
        main_layout.addWidget(self.right_widget)

        self.viewLayout.addWidget(main_widget)

        self.create_button = PrimaryPushButton("创建隧道")
        self.create_button.clicked.connect(self.create_tunnel)
        self.create_button.setEnabled(False)

        self.cancel_button = PushButton("取消")
        self.cancel_button.clicked.connect(self.close)

        while self.buttonLayout.count():
            item = self.buttonLayout.takeAt(0)
            if item.widget():
                item.widget().hide()

        self.buttonLayout.addStretch()
        self.buttonLayout.addWidget(self.create_button)
        self.buttonLayout.addWidget(self.cancel_button)
        self.buttonLayout.addStretch()

        self.on_port_type_changed("TCP")

    def randomize_remote_port(self):
        """随机生成远程端口"""
        min_port = self.remote_port_edit.minimum()
        max_port = self.remote_port_edit.maximum()

        random_port = random.randint(min_port, max_port)
        self.remote_port_edit.setValue(random_port)

        InfoBar.success(
            title="随机端口",
            content=f"已随机生成端口: {random_port}",
            position=InfoBarPosition.TOP_RIGHT,
            duration=1500,
            parent=self.window()
        )

    def load_user_info(self):
        """加载用户信息"""
        token = token_manager.get_token()
        if not token:
            self.show_info_bar("error", "未登录", "请先登录后再创建隧道")
            self.close()
            return

        try:
            url = f"http://cf-v2.uapis.cn/userinfo?token={token}"
            response = requests.get(url, timeout=10)

            if response.status_code == 200:
                data = response.json()
                if data.get("code") == 200:
                    self.user_data = data.get("data", {})
                    # 用户信息获取成功后加载节点
                    self.load_nodes()
                else:
                    self.show_info_bar("error", "获取用户信息失败", data.get("msg", "未知错误"))
                    self.close()
            else:
                self.show_info_bar("error", "网络错误", "无法获取用户信息")
                self.close()
        except Exception as e:
            self.show_info_bar("error", "网络错误", f"获取用户信息失败: {str(e)}")
            self.close()

    def init_node_detail_area(self):
        """初始化节点详情区域"""
        detail_layout = QVBoxLayout(self.right_widget)
        detail_layout.setContentsMargins(0, 0, 0, 0)
        detail_layout.setSpacing(15)

        title_label = SubtitleLabel("节点详情", self.right_widget)
        detail_layout.addWidget(title_label)

        self.node_detail_card = CardWidget(self.right_widget)
        self.node_detail_card.setBorderRadius(8)
        self.node_detail_card.setMinimumHeight(500)

        self.detail_content_layout = QVBoxLayout(self.node_detail_card)
        self.detail_content_layout.setContentsMargins(20, 20, 20, 20)
        self.detail_content_layout.setSpacing(10)

        self.show_default_tip()

        detail_layout.addWidget(self.node_detail_card)

    def show_default_tip(self):
        """显示默认提示"""
        self.clear_node_detail()
        no_selection_label = BodyLabel("请先选择一个节点", self.node_detail_card)
        no_selection_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        no_selection_label.setTextColor("#666666", "#cccccc")
        self.detail_content_layout.addWidget(no_selection_label)

    def generate_tunnel_name(self):
        """生成8位随机隧道名称"""
        characters = string.ascii_letters + string.digits
        return ''.join(random.choice(characters) for _ in range(8))

    def regenerate_tunnel_name(self):
        """重新生成隧道名称"""
        self.tunnel_name_edit.setText(self.generate_tunnel_name())

    def load_nodes(self):
        """加载节点列表"""
        self.node_combo.clear()
        self.node_combo.addItem("正在加载节点列表...")
        self.node_combo.setEnabled(False)
        self.create_button.setEnabled(False)

        self.node_thread = NodeListThread()
        self.node_thread.nodeListLoaded.connect(self.on_nodes_loaded)
        self.node_thread.loadError.connect(self.on_nodes_load_error)
        self.node_thread.start()
    def on_nodes_load_error(self, error_message):
        """节点加载失败"""
        self.node_combo.clear()
        self.node_combo.addItem("加载失败，点击重试")
        self.node_combo.setEnabled(True)
        self.create_button.setEnabled(False)

        self.show_info_bar("error", "加载失败", error_message, 5000)

    def show_info_bar(self, bar_type, title, content, duration=3000):
        main_window = self
        while main_window.parent():
            main_window = main_window.parent()

        if bar_type == "success":
            InfoBar.success(
                title=title,
                content=content,
                position=InfoBarPosition.TOP_RIGHT,
                duration=duration,
                parent=main_window
            )
        elif bar_type == "error":
            InfoBar.error(
                title=title,
                content=content,
                position=InfoBarPosition.TOP_RIGHT,
                duration=duration,
                parent=main_window
            )
        elif bar_type == "warning":
            InfoBar.warning(
                title=title,
                content=content,
                position=InfoBarPosition.TOP_RIGHT,
                duration=duration,
                parent=main_window
            )
        elif bar_type == "info":
            InfoBar.info(
                title=title,
                content=content,
                position=InfoBarPosition.TOP_RIGHT,
                duration=duration,
                parent=main_window
            )

    def on_nodes_loaded(self, nodes):
        """节点列表加载完成"""
        self.nodes_list = nodes
        self.node_combo.clear()
        self.node_combo.setEnabled(True)

        if not nodes:
            self.node_combo.addItem("暂无可用节点")
            self.create_button.setEnabled(False)
            self.show_info_bar("warning", "警告", "暂无在线节点，无法创建隧道")
            return

        user_group = self.user_data.get("usergroup", "free") if self.user_data else "free"
        filtered_nodes = []

        for node in nodes:
            if user_group == "免费用户" and node.get("nodegroup") == "vip":
                continue
            filtered_nodes.append(node)

        if not filtered_nodes:
            self.node_combo.addItem("您的权限组无可用节点")
            self.create_button.setEnabled(False)
            self.show_info_bar("warning", "权限不足", "您当前的权限组没有可用的节点")
            return

        sorted_nodes = sorted(filtered_nodes, key=lambda x: (
            0 if x.get("nodegroup") == "vip" else 1,
            x.get("area", "")
        ))

        self.node_combo.addItem("请选择节点", None)
        self.node_map = {}

        for node in sorted_nodes:
            node_name = node.get("name", "未知节点")
            self.node_combo.addItem(node_name, node_name)
            self.node_map[node_name] = node
        self.show_info_bar("success", "加载成功", f"成功加载 {len(filtered_nodes)} 个节点", 2000)

    def on_node_selection_changed(self, index):
        """节点选择改变事件"""
        if index <= 0:
            self.selected_node_data = None
            self.create_button.setEnabled(False)
            self.show_default_tip()
            return

        node_name = self.node_combo.currentText()

        if node_name in ["正在加载节点列表...", "暂无可用节点", "您的权限组无可用节点", "请选择节点"]:
            self.selected_node_data = None
            self.create_button.setEnabled(False)
            self.show_default_tip()
            return

        if node_name and hasattr(self, 'node_map') and node_name in self.node_map:
            node_data = self.node_map[node_name]
            self.display_basic_node_info(node_data)
            self.load_node_detail(node_name)
            self.create_button.setEnabled(True)
        else:
            self.selected_node_data = None
            self.create_button.setEnabled(False)
            self.show_default_tip()


    def load_node_detail(self, node_name):
        """加载节点详细信息"""
        token = token_manager.get_token()
        if not token:
            return
        self.node_detail_thread = NodeDetailThread(token, node_name)
        self.node_detail_thread.nodeDetailLoaded.connect(self.on_node_detail_loaded)
        self.node_detail_thread.loadError.connect(self.on_node_detail_error)
        self.node_detail_thread.start()

    def display_basic_node_info(self, node_data):
        """显示节点基础信息（从节点列表获取的）"""
        self.clear_node_detail()

        name_label = TitleLabel(node_data.get("name", "未知节点"), self.node_detail_card)
        name_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.detail_content_layout.addWidget(name_label)

        loading_label = BodyLabel("正在加载详细信息...", self.node_detail_card)
        loading_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        loading_label.setTextColor("#666666", "#cccccc")
        self.detail_content_layout.addWidget(loading_label)

        basic_widget = QWidget()
        basic_layout = QVBoxLayout(basic_widget)
        basic_layout.setSpacing(5)

        if node_data.get("area"):
            area_label = CaptionLabel(f"地区: {node_data.get('area')}", basic_widget)
            basic_layout.addWidget(area_label)

        if node_data.get("nodegroup") == "vip":
            vip_label = CaptionLabel("节点类型: VIP", basic_widget)
            vip_label.setStyleSheet("color: #FF9800;")
            basic_layout.addWidget(vip_label)
        else:
            free_label = CaptionLabel("节点类型: 免费", basic_widget)
            basic_layout.addWidget(free_label)

        self.detail_content_layout.addWidget(basic_widget)
        self.detail_content_layout.addStretch()

    def show_loading_detail(self):
        """显示节点详情加载状态"""
        self.clear_node_detail()

        loading_label = BodyLabel("正在加载节点详情...", self.node_detail_card)
        loading_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        loading_label.setTextColor("#666666", "#cccccc")
        self.detail_content_layout.addWidget(loading_label)

    def clear_node_detail(self):
        """清空节点详情显示"""
        while self.detail_content_layout.count():
            item = self.detail_content_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

    def on_node_detail_loaded(self, node_data):
        """节点详情加载完成"""
        self.selected_node_data = node_data
        self.create_button.setEnabled(True)
        self.display_node_detail(node_data)

    def on_node_detail_error(self, error_message):
        """节点详情加载失败"""
        self.create_button.setEnabled(True)
        self.clear_node_detail()

        error_widget = QWidget()
        error_layout = QVBoxLayout(error_widget)

        node_name = self.node_combo.currentText()
        name_label = TitleLabel(node_name, error_widget)
        name_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        error_layout.addWidget(name_label)

        error_label = BodyLabel(f"加载节点详情失败: {error_message}", error_widget)
        error_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        error_label.setTextColor("#e74c3c", "#e74c3c")
        error_label.setWordWrap(True)
        error_layout.addWidget(error_label)

        tip_label = CaptionLabel("您仍然可以创建隧道", error_widget)
        tip_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        tip_label.setTextColor("#666666", "#cccccc")
        error_layout.addWidget(tip_label)

        self.detail_content_layout.addWidget(error_widget)
        self.detail_content_layout.addStretch()

    def display_node_detail(self, node_data):
        """显示节点详细信息"""
        self.clear_node_detail()

        name_label = TitleLabel(node_data.get("name", "未知节点"), self.node_detail_card)
        name_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.detail_content_layout.addWidget(name_label)

        status_widget = self.create_status_widget(node_data)
        self.detail_content_layout.addWidget(status_widget)

        basic_info_widget = self.create_basic_info_widget(node_data)
        self.detail_content_layout.addWidget(basic_info_widget)

        port_info_widget = self.create_port_info_widget(node_data)
        self.detail_content_layout.addWidget(port_info_widget)

        self.update_port_range(node_data)
        self.detail_content_layout.addStretch()

    def create_status_widget(self, node_data):
        """创建状态信息组件"""
        status_widget = QWidget()
        status_layout = QHBoxLayout(status_widget)
        status_layout.setContentsMargins(0, 10, 0, 10)
        status_layout.setSpacing(10)

        if node_data.get("state") == "online":
            status_badge = InfoBadge.success("在线", status_widget)
        else:
            status_badge = InfoBadge.error("离线", status_widget)

        if node_data.get("nodegroup") == "vip":
            type_badge = InfoBadge.custom("VIP", "#FF9800", "#FFF3E0", status_widget)
        else:
            type_badge = InfoBadge.info("免费", status_widget)

        if str(node_data.get("udp")).lower() == "true":
            udp_badge = InfoBadge.info("UDP", status_widget)
            status_layout.addWidget(udp_badge)

        if str(node_data.get("web")).lower() == "yes":
            web_badge = InfoBadge.success("Web", status_widget)
            status_layout.addWidget(web_badge)

        status_layout.addWidget(status_badge)
        status_layout.addWidget(type_badge)
        status_layout.addStretch()

        return status_widget

    def create_basic_info_widget(self, node_data):
        """创建基本信息组件"""
        info_widget = QWidget()
        info_layout = QVBoxLayout(info_widget)
        info_layout.setContentsMargins(0, 10, 0, 10)
        info_layout.setSpacing(8)

        info_title = StrongBodyLabel("基本信息", info_widget)
        info_layout.addWidget(info_title)
        info_items = [
            ("地区", node_data.get("area", "未知")),
            ("IP地址", node_data.get("ip", "未知")),
            ("端口", str(node_data.get("port", "未知"))),
            ("版本", node_data.get("version", "未知")),
        ]

        for label, value in info_items:
            item_layout = QHBoxLayout()
            label_widget = CaptionLabel(f"{label}:", info_widget)
            label_widget.setTextColor("#666666", "#cccccc")
            value_widget = BodyLabel(str(value), info_widget)

            item_layout.addWidget(label_widget)
            item_layout.addWidget(value_widget)
            item_layout.addStretch()

            info_layout.addLayout(item_layout)

        return info_widget

    def create_port_info_widget(self, node_data):
        """创建端口信息组件"""
        port_widget = QWidget()
        port_layout = QVBoxLayout(port_widget)
        port_layout.setContentsMargins(0, 10, 0, 10)
        port_layout.setSpacing(8)

        port_title = StrongBodyLabel("端口配置", port_widget)
        port_layout.addWidget(port_title)

        rport = node_data.get("rport", "未知")
        if rport != "未知" and "-" in str(rport):
            try:
                start_port, end_port = map(int, str(rport).split("-"))
                port_range_text = f"{start_port} - {end_port} (共 {end_port - start_port + 1} 个端口)"
            except:
                port_range_text = str(rport)
        else:
            port_range_text = str(rport)

        port_info_layout = QHBoxLayout()
        port_label = CaptionLabel("外部端口范围:", port_widget)
        port_label.setTextColor("#666666", "#cccccc")
        port_value = BodyLabel(port_range_text, port_widget)

        port_info_layout.addWidget(port_label)
        port_info_layout.addWidget(port_value)
        port_info_layout.addStretch()

        port_layout.addLayout(port_info_layout)

        return port_widget

    def update_port_range(self, node_data):
        """根据节点信息更新端口范围并自动随机选择端口"""
        rport = node_data.get("rport", "")
        if rport and "-" in str(rport):
            try:
                start_port, end_port = map(int, str(rport).split("-"))
                self.remote_port_edit.setRange(start_port, end_port)

                random_port = random.randint(start_port, end_port)
                self.remote_port_edit.setValue(random_port)

                InfoBar.info(
                    title="端口自动分配",
                    content=f"端口范围: {start_port}-{end_port}，已自动选择: {random_port}",
                    position=InfoBarPosition.TOP_RIGHT,
                    duration=2000,
                    parent=self.window()
                )

            except ValueError:
                self.remote_port_edit.setRange(1, 65535)
                self.remote_port_edit.setValue(10000)
        else:
            self.remote_port_edit.setRange(1, 65535)
            self.remote_port_edit.setValue(10000)

    def on_port_type_changed(self, port_type):
        """端口类型改变时的处理"""
        if port_type.upper() in ["TCP", "UDP"]:
            self.remote_port_edit.show()
            self.generate_port_btn.show()
            self.remote_port_row_label.show()
            self.domain_edit.hide()
            self.domain_row_label.hide()
        else:
            self.remote_port_edit.hide()
            self.generate_port_btn.hide()
            self.remote_port_row_label.hide()
            self.domain_edit.show()
            self.domain_row_label.show()

            if port_type.upper() == "HTTP":
                self.local_port_edit.setValue(80)
            elif port_type.upper() == "HTTPS":
                self.local_port_edit.setValue(443)

    def validate_input(self):
        """验证输入"""
        tunnel_name = self.tunnel_name_edit.text().strip()
        if not tunnel_name:
            return False, "请输入隧道名称"

        if len(tunnel_name) != 8:
            return False, "隧道名称必须为8位字符"

        if not re.match(r'^[a-zA-Z0-9]+$', tunnel_name):
            return False, "隧道名称只能包含字母和数字"

        if self.node_combo.currentIndex() <= 0:
            return False, "请选择一个节点"

        local_ip = self.local_ip_edit.text().strip()
        if not local_ip:
            return False, "请输入本地IP"

        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if not re.match(ip_pattern, local_ip):
            return False, "请输入有效的IP地址"

        port_type = self.port_type_combo.currentText().upper()

        if port_type in ["TCP", "UDP"]:
            remote_port = self.remote_port_edit.value()
            if remote_port < 1 or remote_port > 65535:
                return False, "远程端口必须在1-65535之间"
        else:
            domain = self.domain_edit.text().strip()
            if not domain:
                return False, "请输入绑定域名"

            domain_pattern = r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(domain_pattern, domain):
                return False, "请输入有效的域名格式"

        return True, ""

    def create_tunnel(self):
        """创建隧道"""
        is_valid, error_msg = self.validate_input()
        if not is_valid:
            self.show_info_bar("error", "输入错误", error_msg)
            return

        token = token_manager.get_token()
        if not token:
            self.show_info_bar("error", "未登录", "请先登录后再创建隧道")
            return

        tunnel_data = {
            'tunnelname': self.tunnel_name_edit.text().strip(),
            'node': self.node_combo.currentText(),  # 使用 currentText 而不是 currentData
            'localip': self.local_ip_edit.text().strip(),
            'porttype': self.port_type_combo.currentText().lower(),
            'localport': self.local_port_edit.value(),
            'encryption': self.encryption_switch.isChecked(),
            'compression': self.compression_switch.isChecked()
        }

        if tunnel_data['porttype'] in ['tcp', 'udp']:
            tunnel_data['remoteport'] = self.remote_port_edit.value()
        else:
            tunnel_data['banddomain'] = self.domain_edit.text().strip()

        self.create_button.setText("创建中...")
        self.create_button.setEnabled(False)

        self.create_thread = TunnelCreateThread(token, tunnel_data)
        self.create_thread.createFinished.connect(self.on_create_finished)
        self.create_thread.start()

    def on_create_finished(self, success, message):
        """隧道创建完成"""
        self.create_button.setText("创建隧道")
        self.create_button.setEnabled(True)

        if success:
            main_window = self
            while main_window.parent():
                main_window = main_window.parent()

            InfoBar.success(
                title="创建成功",
                content=message,
                position=InfoBarPosition.TOP_RIGHT,
                duration=3000,
                parent=main_window
            )
            self.close()

            if hasattr(self.parent(), 'load_tunnels'):
                QTimer.singleShot(1000, self.parent().load_tunnels)
        else:
            self.show_info_bar("error", "创建失败", message, 5000)

        if hasattr(self, 'create_thread'):
            self.create_thread.deleteLater()
            del self.create_thread

    def show_info_bar(self, bar_type, title, content, duration=3000):
        """统一的信息条显示方法"""
        main_window = self
        while main_window.parent():
            main_window = main_window.parent()

        if bar_type == "success":
            InfoBar.success(
                title=title,
                content=content,
                position=InfoBarPosition.TOP_RIGHT,
                duration=duration,
                parent=main_window
            )
        elif bar_type == "error":
            InfoBar.error(
                title=title,
                content=content,
                position=InfoBarPosition.TOP_RIGHT,
                duration=duration,
                parent=main_window
            )
        elif bar_type == "warning":
            InfoBar.warning(
                title=title,
                content=content,
                position=InfoBarPosition.TOP_RIGHT,
                duration=duration,
                parent=main_window
            )
        elif bar_type == "info":
            InfoBar.info(
                title=title,
                content=content,
                position=InfoBarPosition.TOP_RIGHT,
                duration=duration,
                parent=main_window
            )

    def retry_load_nodes(self):
        """重试加载节点"""
        if hasattr(self, 'retry_button'):
            self.retry_button.setText("重新加载中...")
            self.retry_button.setEnabled(False)

        self.load_nodes()

class BatchEditDialog(MessageBoxBase):
    """批量编辑对话框"""

    def __init__(self, selected_cards, parent=None):
        super().__init__(parent)
        self.selected_cards = selected_cards
        self.parent_widget = parent
        self.nodes_list = []
        self.user_data = None
        self.setWindowTitle("批量编辑隧道")
        self.init_ui()
        QTimer.singleShot(100, self.load_user_info)

    def init_ui(self):
        """初始化界面"""
        self.resize(1000, 600)
        self.yesButton.hide()
        self.cancelButton.hide()

        main_widget = QWidget()
        form_layout = QFormLayout(main_widget)
        form_layout.setContentsMargins(20, 20, 20, 20)
        form_layout.setSpacing(20)

        info_text = f"已选择 {len(self.selected_cards)} 个隧道进行批量编辑"
        info_label = BodyLabel(info_text, self)
        info_label.setStyleSheet("font-weight: bold; color: #2e7d32;")
        form_layout.addRow(info_label)

        separator = QFrame()
        separator.setFrameShape(QFrame.Shape.HLine)
        separator.setStyleSheet("color: #e0e0e0;")
        form_layout.addRow(separator)

        node_layout = QHBoxLayout()
        self.enable_node_edit = CheckBox("修改节点", self)
        self.node_combo = ComboBox()
        self.node_combo.setPlaceholderText("正在加载节点列表...")
        self.node_combo.setEnabled(False)

        node_layout.addWidget(self.enable_node_edit)
        node_layout.addWidget(self.node_combo, 1)
        form_layout.addRow(node_layout)

        port_layout = QHBoxLayout()
        self.enable_port_edit = CheckBox("修改本地端口", self)
        self.local_port_edit = SpinBox()
        self.local_port_edit.setRange(1, 65535)
        self.local_port_edit.setValue(80)
        self.local_port_edit.setEnabled(False)

        port_layout.addWidget(self.enable_port_edit)
        port_layout.addWidget(self.local_port_edit, 1)
        form_layout.addRow(port_layout)

        encryption_layout = QHBoxLayout()
        self.enable_encryption_edit = CheckBox("修改数据加密", self)
        self.encryption_switch = SwitchButton()
        self.encryption_switch.setChecked(False)
        self.encryption_switch.setEnabled(False)

        encryption_layout.addWidget(self.enable_encryption_edit)
        encryption_layout.addWidget(self.encryption_switch, 1)
        form_layout.addRow(encryption_layout)

        compression_layout = QHBoxLayout()
        self.enable_compression_edit = CheckBox("修改数据压缩", self)
        self.compression_switch = SwitchButton()
        self.compression_switch.setChecked(False)
        self.compression_switch.setEnabled(False)

        compression_layout.addWidget(self.enable_compression_edit)
        compression_layout.addWidget(self.compression_switch, 1)
        form_layout.addRow(compression_layout)

        self.enable_node_edit.stateChanged.connect(
            lambda state: self.node_combo.setEnabled(state == Qt.CheckState.Checked.value))
        self.enable_port_edit.stateChanged.connect(
            lambda state: self.local_port_edit.setEnabled(state == Qt.CheckState.Checked.value))
        self.enable_encryption_edit.stateChanged.connect(
            lambda state: self.encryption_switch.setEnabled(state == Qt.CheckState.Checked.value))
        self.enable_compression_edit.stateChanged.connect(
            lambda state: self.compression_switch.setEnabled(state == Qt.CheckState.Checked.value))

        self.viewLayout.addWidget(main_widget)

        self.apply_button = PrimaryPushButton("应用更改")
        self.apply_button.clicked.connect(self.apply_batch_edit)
        self.apply_button.setEnabled(False)

        self.cancel_button = PushButton("取消")
        self.cancel_button.clicked.connect(self.close)

        while self.buttonLayout.count():
            item = self.buttonLayout.takeAt(0)
            if item.widget():
                item.widget().hide()

        self.buttonLayout.addStretch()
        self.buttonLayout.addWidget(self.apply_button)
        self.buttonLayout.addWidget(self.cancel_button)
        self.buttonLayout.addStretch()

    def load_user_info(self):
        """加载用户信息"""
        token = token_manager.get_token()
        if not token:
            self.show_info_bar("error", "未登录", "请先登录后再编辑隧道")
            self.close()
            return

        try:
            url = f"http://cf-v2.uapis.cn/userinfo?token={token}"
            response = requests.get(url, timeout=10)

            if response.status_code == 200:
                data = response.json()
                if data.get("code") == 200:
                    self.user_data = data.get("data", {})
                    self.load_nodes()
                else:
                    self.show_info_bar("error", "获取用户信息失败", data.get("msg", "未知错误"))
                    self.close()
            else:
                self.show_info_bar("error", "网络错误", "无法获取用户信息")
                self.close()
        except Exception as e:
            self.show_info_bar("error", "网络错误", f"获取用户信息失败: {str(e)}")
            self.close()

    def load_nodes(self):
        """加载节点列表"""
        self.node_combo.clear()
        self.node_combo.addItem("正在加载节点列表...")
        self.apply_button.setEnabled(False)

        self.node_thread = NodeListThread()
        self.node_thread.nodeListLoaded.connect(self.on_nodes_loaded)
        self.node_thread.loadError.connect(self.on_nodes_load_error)
        self.node_thread.start()

    def on_nodes_loaded(self, nodes):
        """节点列表加载完成"""
        self.nodes_list = nodes
        self.node_combo.clear()

        if not nodes:
            self.node_combo.addItem("暂无可用节点")
            self.apply_button.setEnabled(True)
            return

        user_group = self.user_data.get("usergroup", "free") if self.user_data else "free"
        filtered_nodes = []

        for node in nodes:
            if user_group == "免费用户" and node.get("nodegroup") == "vip":
                continue
            filtered_nodes.append(node)

        if not filtered_nodes:
            self.node_combo.addItem("您的权限组无可用节点")
            self.apply_button.setEnabled(True)
            return

        sorted_nodes = sorted(filtered_nodes, key=lambda x: (
            0 if x.get("nodegroup") == "vip" else 1,
            x.get("area", "")
        ))

        for node in sorted_nodes:
            node_name = node.get("name", "未知节点")
            self.node_combo.addItem(node_name, node_name)

        self.apply_button.setEnabled(True)

    def on_nodes_load_error(self, error_message):
        """节点加载失败处理"""
        self.node_combo.clear()
        self.node_combo.addItem("加载失败")
        self.apply_button.setEnabled(True)

    def apply_batch_edit(self):
        """应用批量编辑"""
        if not any([
            self.enable_node_edit.isChecked(),
            self.enable_port_edit.isChecked(),
            self.enable_encryption_edit.isChecked(),
            self.enable_compression_edit.isChecked()
        ]):
            self.show_info_bar("warning", "未选择", "请至少选择一个要修改的项目")
            return

        update_data = {}

        if self.enable_node_edit.isChecked():
            node_text = self.node_combo.currentText()
            if node_text and node_text not in ["正在加载节点列表...", "暂无可用节点", "您的权限组无可用节点",
                                               "加载失败"]:
                update_data['node'] = node_text

        if self.enable_port_edit.isChecked():
            update_data['localport'] = self.local_port_edit.value()

        if self.enable_encryption_edit.isChecked():
            update_data['encryption'] = self.encryption_switch.isChecked()

        if self.enable_compression_edit.isChecked():
            update_data['compression'] = self.compression_switch.isChecked()

        changes_text = []
        if 'node' in update_data:
            changes_text.append(f"节点: {update_data['node']}")
        if 'localport' in update_data:
            changes_text.append(f"本地端口: {update_data['localport']}")
        if 'encryption' in update_data:
            changes_text.append(f"数据加密: {'启用' if update_data['encryption'] else '禁用'}")
        if 'compression' in update_data:
            changes_text.append(f"数据压缩: {'启用' if update_data['compression'] else '禁用'}")

        tunnel_names = [card.tunnel_info['name'] for card in self.selected_cards]

        dialog = MessageBox(
            "确认批量编辑",
            f"确定要对以下 {len(self.selected_cards)} 个隧道应用更改吗？\n\n"
            f"隧道: {', '.join(tunnel_names[:3])}{'...' if len(tunnel_names) > 3 else ''}\n\n"
            f"更改内容:\n{chr(10).join(changes_text)}",
            self.window()
        )

        def confirm_batch_edit():
            self.perform_batch_edit(update_data)

        dialog.yesButton.clicked.connect(confirm_batch_edit)
        dialog.exec()

    def perform_batch_edit(self, update_data):
        """执行批量编辑"""
        self.apply_button.setText("更新中...")
        self.apply_button.setEnabled(False)

        self.batch_update_thread = BatchUpdateThread(self.selected_cards, update_data)
        self.batch_update_thread.updateFinished.connect(self.on_batch_update_finished)
        self.batch_update_thread.start()

    def on_batch_update_finished(self, success_count, failed_count, error_messages):
        """批量更新完成"""
        self.apply_button.setText("应用更改")
        self.apply_button.setEnabled(True)

        if success_count > 0:
            main_window = self
            while main_window.parent():
                main_window = main_window.parent()

            InfoBar.success(
                title="批量编辑完成",
                content=f"成功更新 {success_count} 个隧道",
                position=InfoBarPosition.TOP_RIGHT,
                duration=3000,
                parent=main_window
            )

            if hasattr(self.parent_widget, 'load_tunnels'):
                QTimer.singleShot(1000, self.parent_widget.load_tunnels)

        if failed_count > 0:
            InfoBar.error(
                title="部分更新失败",
                content=f"{failed_count} 个隧道更新失败",
                position=InfoBarPosition.TOP_RIGHT,
                duration=5000,
                parent=self.window()
            )

        if success_count > 0:
            self.close()

        if hasattr(self, 'batch_update_thread'):
            self.batch_update_thread.deleteLater()
            del self.batch_update_thread

    def show_info_bar(self, bar_type, title, content, duration=3000):
        """统一的信息条显示方法"""
        main_window = self
        while main_window.parent():
            main_window = main_window.parent()

        if bar_type == "success":
            InfoBar.success(
                title=title,
                content=content,
                position=InfoBarPosition.TOP_RIGHT,
                duration=duration,
                parent=main_window
            )
        elif bar_type == "error":
            InfoBar.error(
                title=title,
                content=content,
                position=InfoBarPosition.TOP_RIGHT,
                duration=duration,
                parent=main_window
            )
        elif bar_type == "warning":
            InfoBar.warning(
                title=title,
                content=content,
                position=InfoBarPosition.TOP_RIGHT,
                duration=duration,
                parent=main_window
            )

class BatchUpdateThread(QThread):
    """批量更新线程"""
    updateFinished = pyqtSignal(int, int, list)  # 成功数量，失败数量，错误消息列表

    def __init__(self, selected_cards, update_data):
        super().__init__()
        self.selected_cards = selected_cards
        self.update_data = update_data

    def run(self):
        """执行批量更新"""
        token = token_manager.get_token()
        if not token:
            self.updateFinished.emit(0, len(self.selected_cards), ["未登录"])
            return

        success_count = 0
        failed_count = 0
        error_messages = []

        for card in self.selected_cards:
            try:
                tunnel_info = card.tunnel_info
                tunnel_id = tunnel_info['id']

                tunnel_data = {
                    'tunnelname': tunnel_info['name'],
                    'localip': tunnel_info.get('localip', '127.0.0.1'),
                    'porttype': tunnel_info['type'].lower(),
                    'encryption': str(tunnel_info.get('encryption', 'False')).lower(),
                    'compression': str(tunnel_info.get('compression', 'False')).lower()
                }

                if 'node' in self.update_data:
                    tunnel_data['node'] = self.update_data['node']
                else:
                    tunnel_data['node'] = tunnel_info['node']

                if 'localport' in self.update_data:
                    tunnel_data['localport'] = self.update_data['localport']
                else:
                    tunnel_data['localport'] = int(tunnel_info.get('nport', 80))

                if 'encryption' in self.update_data:
                    tunnel_data['encryption'] = str(self.update_data['encryption']).lower()

                if 'compression' in self.update_data:
                    tunnel_data['compression'] = str(self.update_data['compression']).lower()

                if tunnel_data['porttype'] in ['tcp', 'udp']:
                    tunnel_data['remoteport'] = tunnel_info.get('dorp', '10000')
                elif tunnel_data['porttype'] in ['http', 'https']:
                    tunnel_data['banddomain'] = tunnel_info.get('dorp', '')

                params = {
                    'token': token,
                    'tunnelid': tunnel_id,
                    **tunnel_data
                }

                url = "https://cf-v2.uapis.cn/update_tunnel"
                headers = {
                    'Content-Type': 'application/json',
                    'User-Agent': USER_AGENT
                }

                response = requests.post(url, json=params, headers=headers, timeout=15)

                if response.status_code == 200:
                    data = response.json()
                    if data.get("code") == 200:
                        success_count += 1
                    else:
                        failed_count += 1
                        error_messages.append(f"{tunnel_info['name']}: {data.get('msg', '更新失败')}")
                else:
                    failed_count += 1
                    error_messages.append(f"{tunnel_info['name']}: HTTP {response.status_code}")

            except Exception as e:
                failed_count += 1
                error_messages.append(f"{tunnel_info['name']}: {str(e)}")

        self.updateFinished.emit(success_count, failed_count, error_messages)
        self.quit()

class TunnelManagementPage(QWidget):
    """隧道管理页面 - 支持批量操作"""

    def __init__(self, parent=None):
        super().__init__(parent=parent)
        self.setObjectName("tunnelManagementPage")

        self.tunnel_processes = {}
        self.process_lock = QMutex()
        self.output_mutex = QMutex()
        self.tunnel_outputs = {}
        self.tunnel_cards = []
        self.loader_thread = None
        self.node_domain_cache = {}  # 添加：节点域名缓存
        self.nodes_list = []  # 添加：节点列表缓存

        self.init_ui()
        self.load_tunnels()
        self.load_nodes_info()

        self.status_timer = QTimer(self)
        self.status_timer.timeout.connect(self.check_all_tunnels_status)
        self.status_timer.start(5000)

        QTimer.singleShot(3000, self.auto_start_configured_tunnels)

    def init_ui(self):
        """初始化界面"""
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(15)

        top_bar = self.create_top_bar()
        main_layout.addWidget(top_bar)

        batch_bar = self.create_batch_bar()
        main_layout.addWidget(batch_bar)

        self.scroll_area = SingleDirectionScrollArea(orient=Qt.Orientation.Vertical)
        self.scroll_area.setWidgetResizable(True)
        self.scroll_content = QWidget()
        self.scroll_area.setWidget(self.scroll_content)
        self.scroll_area.enableTransparentBackground()
        self.scroll_content.setStyleSheet("background: transparent;")

        self.grid_layout = QGridLayout(self.scroll_content)
        self.grid_layout.setContentsMargins(0, 0, 0, 0)
        self.grid_layout.setSpacing(15)
        self.grid_layout.setColumnStretch(0, 1)
        self.grid_layout.setColumnStretch(1, 1)

        self.loading_label = BodyLabel("正在加载隧道列表...", self)
        self.loading_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.grid_layout.addWidget(self.loading_label, 0, 0, 1, 2)

        main_layout.addWidget(self.scroll_area)

    def auto_start_configured_tunnels(self):
        """自动启动配置的隧道"""
        auto_start_tunnel_ids = config_manager.get("auto_start_tunnels", [])

        if not auto_start_tunnel_ids:
            logging.info("没有配置自动启动的隧道")
            return

        if not token_manager.get_token():
            logging.warning("未登录，无法自动启动隧道")
            InfoBar.warning(
                title="自动启动失败",
                content="未登录，无法自动启动配置的隧道",
                position=InfoBarPosition.TOP_RIGHT,
                duration=3000,
                parent=self.window()
            )
            return

        logging.info(f"开始自动启动 {len(auto_start_tunnel_ids)} 个隧道")

        if not self.tunnel_cards:
            QTimer.singleShot(2000, self.auto_start_configured_tunnels)
            return

        started_count = 0
        failed_count = 0

        for tunnel_card in self.tunnel_cards:
            tunnel_id = tunnel_card.tunnel_info.get('id')
            tunnel_name = tunnel_card.tunnel_info.get('name')

            if tunnel_id in auto_start_tunnel_ids:
                try:
                    if tunnel_card.tunnel_info.get('nodestate') != "online":
                        logging.warning(f"隧道 {tunnel_name} 的节点不在线，跳过自动启动")
                        failed_count += 1
                        continue

                    with QMutexLocker(self.process_lock):
                        if tunnel_name in self.tunnel_processes:
                            logging.info(f"隧道 {tunnel_name} 已在运行，跳过")
                            continue

                    self.start_tunnel(tunnel_card)
                    started_count += 1
                    logging.info(f"自动启动隧道: {tunnel_name}")

                    QTimer.singleShot(1000 * started_count, lambda: None)

                except Exception as e:
                    logging.error(f"自动启动隧道 {tunnel_name} 失败: {e}")
                    failed_count += 1

        if started_count > 0 or failed_count > 0:
            if failed_count == 0:
                InfoBar.success(
                    title="自动启动完成",
                    content=f"成功自动启动 {started_count} 个隧道",
                    position=InfoBarPosition.TOP_RIGHT,
                    duration=3000,
                    parent=self.window()
                )
            else:
                InfoBar.warning(
                    title="自动启动部分完成",
                    content=f"成功启动 {started_count} 个，失败 {failed_count} 个隧道",
                    position=InfoBarPosition.TOP_RIGHT,
                    duration=4000,
                    parent=self.window()
                )

    def load_nodes_info(self):
        """加载节点信息用于域名解析"""
        try:
            response = requests.get("http://cf-v2.uapis.cn/node", timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get("code") == 200:
                    self.nodes_list = data.get("data", [])
                    logging.info(f"成功加载 {len(self.nodes_list)} 个节点信息")
        except Exception as e:
            logging.error(f"加载节点信息失败: {e}")
            self.nodes_list = []

    def create_top_bar(self):
        """创建顶部操作栏"""
        top_bar = QWidget(self)
        top_layout = QHBoxLayout(top_bar)
        top_layout.setContentsMargins(0, 0, 0, 0)

        self.refresh_btn = PushButton("刷新", self)
        self.refresh_btn.setIcon(FluentIcon.SYNC)
        self.refresh_btn.clicked.connect(self.load_tunnels)

        self.kill_all_btn = PushButton("关闭所有frpc", self)
        self.kill_all_btn.setIcon(FluentIcon.CLOSE)
        self.kill_all_btn.clicked.connect(self.kill_all_frpc)

        self.add_tunnel_btn = PrimaryPushButton("添加隧道", self)
        self.add_tunnel_btn.setIcon(FluentIcon.ADD)
        self.add_tunnel_btn.clicked.connect(self.add_tunnel)

        top_layout.addWidget(self.refresh_btn)
        top_layout.addWidget(self.kill_all_btn)
        top_layout.addStretch()
        top_layout.addWidget(self.add_tunnel_btn)

        return top_bar

    def create_batch_bar(self):
        """创建批量操作栏"""
        batch_bar = QWidget(self)
        batch_layout = QHBoxLayout(batch_bar)
        batch_layout.setContentsMargins(0, 0, 0, 0)
        batch_layout.setSpacing(10)

        self.select_all_btn = PushButton("全选", self)
        self.select_all_btn.setIcon(FluentIcon.CHECKBOX)
        self.select_all_btn.clicked.connect(self.select_all)

        self.select_none_btn = PushButton("取消全选", self)
        self.select_none_btn.setIcon(FluentIcon.CANCEL)
        self.select_none_btn.clicked.connect(self.select_none)

        self.select_inverse_btn = PushButton("反选", self)
        self.select_inverse_btn.setIcon(FluentIcon.SYNC)
        self.select_inverse_btn.clicked.connect(self.select_inverse)

        self.batch_edit_btn = PushButton("批量编辑", self)
        self.batch_edit_btn.setIcon(FluentIcon.EDIT)
        self.batch_edit_btn.clicked.connect(self.batch_edit)

        self.batch_delete_btn = PushButton("批量删除", self)
        self.batch_delete_btn.setIcon(FluentIcon.DELETE)
        self.batch_delete_btn.clicked.connect(self.batch_delete)

        self.selection_label = CaptionLabel("未选择任何隧道", self)
        self.selection_label.setTextColor("#666666", "#cccccc")

        batch_layout.addWidget(self.select_all_btn)
        batch_layout.addWidget(self.select_none_btn)
        batch_layout.addWidget(self.select_inverse_btn)
        batch_layout.addWidget(QFrame())
        batch_layout.addWidget(self.batch_edit_btn)
        batch_layout.addWidget(self.batch_delete_btn)
        batch_layout.addStretch()
        batch_layout.addWidget(self.selection_label)

        return batch_bar

    def batch_edit(self):
        """批量编辑"""
        selected_cards = [card for card in self.tunnel_cards if card.is_selected()]

        if not selected_cards:
            InfoBar.warning(
                title="警告",
                content="请先选择要编辑的隧道",
                position=InfoBarPosition.TOP_RIGHT,
                duration=3000,
                parent=self.window()
            )
            return

        running_tunnels = []
        for card in selected_cards:
            tunnel_name = card.tunnel_info['name']
            with QMutexLocker(self.process_lock):
                if tunnel_name in self.tunnel_processes:
                    running_tunnels.append(tunnel_name)

        if running_tunnels:
            InfoBar.warning(
                title="警告",
                content=f"以下隧道正在运行，请先停止：{', '.join(running_tunnels)}",
                position=InfoBarPosition.TOP_RIGHT,
                duration=5000,
                parent=self.window()
            )
            return

        dialog = BatchEditDialog(selected_cards, self)
        dialog.exec()

    def load_tunnels(self):
        """加载隧道列表"""
        if self.loader_thread and self.loader_thread.isRunning():
            self.loader_thread.terminate()
            self.loader_thread.wait(1000)  # 等待最多1秒

        try:
            if hasattr(self, 'loading_label') and self.loading_label:
                self.loading_label.setText("正在加载隧道列表...")
                self.loading_label.show()
        except RuntimeError:
            self.loading_label = BodyLabel("正在加载隧道列表...", self)
            self.loading_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.grid_layout.addWidget(self.loading_label, 0, 0, 1, 3)

        self.clear_tunnel_cards()

        self.load_nodes_info()
        self.loader_thread = TunnelLoaderThread(token_manager.get_token())

        self.loader_thread = TunnelLoaderThread(token_manager.get_token())
        self.loader_thread.dataLoaded.connect(self.handle_tunnels_data)
        self.loader_thread.start()

    def clear_tunnel_cards(self):
        """清空隧道卡片"""
        self.tunnel_cards.clear()

        items_to_remove = []
        for i in range(self.grid_layout.count()):
            item = self.grid_layout.itemAt(i)
            if item and item.widget() and item.widget() != self.loading_label:
                items_to_remove.append(item.widget())

        for widget in items_to_remove:
            self.grid_layout.removeWidget(widget)
            widget.deleteLater()

    def handle_tunnels_data(self, data):
        """处理获取到的隧道数据"""
        try:
            if data.get("code") == 200:
                tunnels = data.get("data", [])
                try:
                    if hasattr(self, 'loading_label') and self.loading_label:
                        if not tunnels:
                            self.loading_label.setText("暂无隧道，请点击添加隧道按钮创建")
                            return
                        else:
                            self.loading_label.hide()
                except RuntimeError:
                    pass

                if not tunnels:
                    try:
                        if not hasattr(self, 'loading_label') or not self.loading_label:
                            self.loading_label = BodyLabel("暂无隧道，请点击添加隧道按钮创建", self)
                            self.loading_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
                        else:
                            self.loading_label.setText("暂无隧道，请点击添加隧道按钮创建")
                            self.loading_label.show()
                        self.grid_layout.addWidget(self.loading_label, 0, 0, 1, 2)  # 跨2列 (修改这里)
                    except RuntimeError:
                        pass
                    return

                row = 0
                col = 0
                for tunnel in tunnels:
                    tunnel_card = TunnelCard(tunnel, self)
                    tunnel_card.selectionChanged.connect(self.update_selection_status)
                    self.tunnel_cards.append(tunnel_card)

                    self.grid_layout.addWidget(tunnel_card, row, col)

                    col += 1
                    if col >= 2:
                        col = 0
                        row += 1

                # 检查隧道状态
                self.check_all_tunnels_status()
                self.update_selection_status()
            else:
                error_msg = data.get("msg", "未知错误")
                try:
                    if hasattr(self, 'loading_label') and self.loading_label:
                        self.loading_label.setText(f"加载失败: {error_msg}")
                        self.loading_label.show()
                    else:
                        self.loading_label = BodyLabel(f"加载失败: {error_msg}", self)
                        self.loading_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
                    self.grid_layout.addWidget(self.loading_label, 0, 0, 1, 2)  # 跨2列 (修改这里)
                except RuntimeError:
                    pass

                InfoBar.error(
                    title="加载失败",
                    content=error_msg,
                    position=InfoBarPosition.TOP_RIGHT,
                    duration=3000,
                    parent=self.window()
                )
        except Exception as e:
            logging.error(f"处理隧道数据时出错: {e}")
            InfoBar.error(
                title="错误",
                content=f"处理数据时发生错误: {str(e)}",
                position=InfoBarPosition.TOP_RIGHT,
                duration=3000,
                parent=self.window()
            )
        finally:
            if hasattr(self, 'loader_thread'):
                self.loader_thread = None

    def select_all(self):
        """全选"""
        for card in self.tunnel_cards:
            card.set_selected(True)
        self.update_selection_status()

    def select_none(self):
        """取消全选"""
        for card in self.tunnel_cards:
            card.set_selected(False)
        self.update_selection_status()

    def select_inverse(self):
        """反选"""
        for card in self.tunnel_cards:
            card.set_selected(not card.is_selected())
        self.update_selection_status()

    def update_selection_status(self):
        """更新选择状态标签"""
        selected_count = sum(1 for card in self.tunnel_cards if card.is_selected())
        total_count = len(self.tunnel_cards)

        if selected_count == 0:
            self.selection_label.setText("未选择任何隧道")
        else:
            self.selection_label.setText(f"已选择 {selected_count} / {total_count} 个隧道")

    def batch_delete(self):
        """批量删除"""
        selected_cards = [card for card in self.tunnel_cards if card.is_selected()]

        if not selected_cards:
            InfoBar.warning(
                title="警告",
                content="请先选择要删除的隧道",
                position=InfoBarPosition.TOP_RIGHT,
                duration=3000,
                parent=self.window()
            )
            return

        running_tunnels = []
        for card in selected_cards:
            tunnel_name = card.tunnel_info['name']
            with QMutexLocker(self.process_lock):
                if tunnel_name in self.tunnel_processes:
                    running_tunnels.append(tunnel_name)

        if running_tunnels:
            InfoBar.warning(
                title="警告",
                content=f"以下隧道正在运行，请先停止：{', '.join(running_tunnels)}",
                position=InfoBarPosition.TOP_RIGHT,
                duration=5000,
                parent=self.window()
            )
            return

        tunnel_names = [card.tunnel_info['name'] for card in selected_cards]
        dialog = MessageBox(
            "确认批量删除",
            f"确定要删除以下 {len(selected_cards)} 个隧道吗？\n\n{', '.join(tunnel_names)}\n\n此操作不可撤销。",
            self.window()
        )

        def confirm_batch_delete():
            # 执行批量删除
            self.perform_batch_delete(selected_cards)

        dialog.yesButton.clicked.connect(confirm_batch_delete)
        dialog.exec()

    def perform_batch_delete(self, cards_to_delete):
        """执行批量删除"""
        delete_count = 0
        failed_deletions = []

        for card in cards_to_delete:
            tunnel_id = card.tunnel_info['id']
            tunnel_name = card.tunnel_info['name']

            try:
                url = f"http://cf-v2.uapis.cn/delete_tunnel?token={token_manager.get_token()}&tunnelid={tunnel_id}"
                response = requests.get(url, timeout=10)

                if response.status_code == 200:
                    data = response.json()
                    if data.get("code") == 200:
                        self.grid_layout.removeWidget(card)
                        card.deleteLater()
                        if card in self.tunnel_cards:
                            self.tunnel_cards.remove(card)
                        delete_count += 1
                    else:
                        failed_deletions.append(f"{tunnel_name}: {data.get('msg', '删除失败')}")
                else:
                    failed_deletions.append(f"{tunnel_name}: 请求失败")

            except Exception as e:
                failed_deletions.append(f"{tunnel_name}: {str(e)}")

        self.reorganize_grid_layout()
        self.update_selection_status()

        if delete_count > 0:
            InfoBar.success(
                title="批量删除完成",
                content=f"成功删除 {delete_count} 个隧道",
                position=InfoBarPosition.TOP_RIGHT,
                duration=3000,
                parent=self.window()
            )

        if failed_deletions:
            InfoBar.error(
                title="部分删除失败",
                content=f"以下隧道删除失败：\n{chr(10).join(failed_deletions[:3])}{'...' if len(failed_deletions) > 3 else ''}",
                position=InfoBarPosition.TOP_RIGHT,
                duration=5000,
                parent=self.window()
            )

    def reorganize_grid_layout(self):
        """重新整理网格布局"""
        cards = []
        for card in self.tunnel_cards:
            self.grid_layout.removeWidget(card)
            cards.append(card)

        row = 0
        col = 0
        for card in cards:
            self.grid_layout.addWidget(card, row, col)
            col += 1
            if col >= 2:
                col = 0
                row += 1

    def add_tunnel(self):
        """添加新隧道"""
        if not token_manager.get_token():
            InfoBar.warning(
                title="未登录",
                content="请先登录后再操作",
                position=InfoBarPosition.TOP_RIGHT,
                duration=3000,
                parent=self.window()
            )
            return

        dialog = TunnelAddDialog(self)
        dialog.exec()

    def kill_all_frpc(self):
        """关闭所有frpc进程"""
        dialog = MessageBox(
            "确认关闭",
            "确定要关闭所有frpc进程吗？\n这将停止所有正在运行的隧道。",
            self.window()
        )

        def confirm_kill():
            try:
                with QMutexLocker(self.process_lock):
                    for tunnel_name, process in list(self.tunnel_processes.items()):
                        try:
                            process.terminate()
                        except:
                            pass
                    self.tunnel_processes.clear()
                result = subprocess.run(
                    ['taskkill', '/F', '/IM', 'frpc.exe'],
                    capture_output=True,
                    text=True,
                    shell=True
                )

                if result.returncode == 0:
                    InfoBar.success(
                        title="成功",
                        content="已关闭所有frpc进程",
                        position=InfoBarPosition.TOP_RIGHT,
                        duration=3000,
                        parent=self.window()
                    )

                    # 更新所有隧道卡片的状态
                    for card in self.tunnel_cards:
                        card.update_status(False)

                    # 清空输出缓存
                    with QMutexLocker(self.output_mutex):
                        for tunnel_name in self.tunnel_outputs:
                            self.tunnel_outputs[tunnel_name]['output'] += \
                                f"<br><span style='color: #ff9800;'>[{datetime.now().strftime('%H:%M:%S')}] [SYS] 所有frpc进程已被强制关闭</span><br>"
                else:
                    if "not found" in result.stderr.lower():
                        InfoBar.info(
                            title="提示",
                            content="没有找到正在运行的frpc进程",
                            position=InfoBarPosition.TOP_RIGHT,
                            duration=2000,
                            parent=self.window()
                        )
                    else:
                        InfoBar.warning(
                            title="部分成功",
                            content=f"关闭进程时遇到问题: {result.stderr}",
                            position=InfoBarPosition.TOP_RIGHT,
                            duration=3000,
                            parent=self.window()
                        )
            except Exception as e:
                logging.error(f"关闭frpc进程失败: {str(e)}")
                InfoBar.error(
                    title="错误",
                    content=f"关闭进程失败: {str(e)}",
                    position=InfoBarPosition.TOP_RIGHT,
                    duration=3000,
                    parent=self.window()
                )

        dialog.yesButton.clicked.connect(confirm_kill)
        dialog.exec()

    def check_all_tunnels_status(self):
        """检查所有隧道的状态"""
        for card in self.tunnel_cards:
            self.check_tunnel_status(card.tunnel_info['name'])

    def check_tunnel_status(self, tunnel_name):
        """检查特定隧道的状态"""
        with QMutexLocker(self.process_lock):
            is_running = tunnel_name in self.tunnel_processes and self.tunnel_processes[tunnel_name].poll() is None

        for card in self.tunnel_cards:
            if card.tunnel_info['name'] == tunnel_name:
                card.update_status(is_running)
                break

    def start_tunnel(self, tunnel_card):
        """启动隧道"""
        tunnel_info = tunnel_card.tunnel_info

        if tunnel_info.get('nodestate') != "online":
            InfoBar.warning(
                title="节点离线",
                content=f"节点 {tunnel_info['node']} 当前不在线，无法启动隧道",
                position=InfoBarPosition.TOP_RIGHT,
                duration=3000,
                parent=self.window()
            )
            return

        try:
            with QMutexLocker(self.process_lock):
                if tunnel_info['name'] in self.tunnel_processes:
                    InfoBar.info(
                        title="提示",
                        content=f"隧道 {tunnel_info['name']} 已在运行",
                        position=InfoBarPosition.TOP_RIGHT,
                        duration=2000,
                        parent=self.window()
                    )
                    return

                frpc_path = None
                main_window = self.window()

                if hasattr(main_window, 'get_frpc_path') and hasattr(main_window, 'is_frpc_available'):
                    frpc_path = main_window.get_frpc_path()

                    if not main_window.is_frpc_available():
                        InfoBar.error(
                            title="错误",
                            content="frpc.exe文件不存在，请重新启动程序进行下载",
                            position=InfoBarPosition.TOP_RIGHT,
                            duration=3000,
                            parent=self.window()
                        )
                        return
                else:
                    if getattr(sys, 'frozen', False):
                        frpc_path = os.path.join(os.path.dirname(sys.executable), "frpc.exe")
                    else:
                        frpc_path = os.path.join(os.path.dirname(__file__), "frpc.exe")

                    if not os.path.exists(frpc_path):
                        InfoBar.error(
                            title="错误",
                            content="找不到frpc.exe文件，请确保程序完整",
                            position=InfoBarPosition.TOP_RIGHT,
                            duration=3000,
                            parent=self.window()
                        )
                        return

                cmd_variants = [
                    frpc_path,
                    "-u", token_manager.get_token(),
                    "-p", str(tunnel_info['id'])
                ]

                process = subprocess.Popen(
                    cmd_variants,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    stdin=subprocess.PIPE,
                    bufsize=0,
                    universal_newlines=False,
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
                )

                self.tunnel_processes[tunnel_info['name']] = process

                with QMutexLocker(self.output_mutex):
                    run_number = 1
                    existing_dialog = None

                    if tunnel_info['name'] in self.tunnel_outputs:
                        run_number = self.tunnel_outputs[tunnel_info['name']].get('run_number', 0) + 1
                        existing_dialog = self.tunnel_outputs[tunnel_info['name']].get('dialog')

                    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    cmd_str = ' '.join(cmd_variants)
                    token = token_manager.get_token() or ""
                    if token and len(token) > 10:
                        cmd_str = cmd_str.replace(token, '*******Token*******')

                    self.tunnel_outputs[tunnel_info['name']] = {
                        'output': f"""<b>===== 隧道启动 #{run_number} | {timestamp} =====</b><br>
    <span style='color: #1976d2;'>[{datetime.now().strftime('%H:%M:%S')}] [SYS] 隧道名称: {tunnel_info['name']}</span><br>
    <span style='color: #1976d2;'>[{datetime.now().strftime('%H:%M:%S')}] [SYS] 节点: {tunnel_info['node']}</span><br>
    <span style='color: #1976d2;'>[{datetime.now().strftime('%H:%M:%S')}] [SYS] 类型: {tunnel_info['type']}</span><br>
    <span style='color: #1976d2;'>[{datetime.now().strftime('%H:%M:%S')}] [SYS] 本地端口: {tunnel_info['nport']}</span><br>
    <span style='color: #1976d2;'>[{datetime.now().strftime('%H:%M:%S')}] [SYS] 启动命令: {cmd_str}</span><br>
    <span style='color: #1976d2;'>[{datetime.now().strftime('%H:%M:%S')}] [SYS] 等待frpc输出...</span><br>""",
                        'dialog': existing_dialog,
                        'run_number': run_number
                    }

                output_thread = TunnelOutputThread(process, tunnel_info['name'], self)
                output_thread.start()

                self.start_frequent_tunnel_monitor(tunnel_info['name'])

                tunnel_card.update_status(True)

                InfoBar.success(
                    title="成功",
                    content=f"隧道 {tunnel_info['name']} 启动中，请查看日志获取详细信息",
                    position=InfoBarPosition.TOP_RIGHT,
                    duration=3000,
                    parent=self.window()
                )

                logging.info(f"隧道 {tunnel_info['name']} 启动成功, PID: {process.pid}")

        except subprocess.SubprocessError as e:
            error_msg = f"进程启动失败: {str(e)}"
            logging.error(f"启动隧道失败: {error_msg}")
            InfoBar.error(
                title="启动失败",
                content=f"隧道启动失败: {error_msg}",
                position=InfoBarPosition.TOP_RIGHT,
                duration=5000,
                parent=self.window()
            )
        except FileNotFoundError as e:
            error_msg = f"找不到frpc.exe文件: {str(e)}"
            logging.error(f"启动隧道失败: {error_msg}")
            InfoBar.error(
                title="文件缺失",
                content="找不到frpc.exe文件，请重新启动程序进行下载",
                position=InfoBarPosition.TOP_RIGHT,
                duration=5000,
                parent=self.window()
            )
        except PermissionError as e:
            error_msg = f"权限不足: {str(e)}"
            logging.error(f"启动隧道失败: {error_msg}")
            InfoBar.error(
                title="权限错误",
                content="启动frpc时权限不足，请以管理员身份运行程序",
                position=InfoBarPosition.TOP_RIGHT,
                duration=5000,
                parent=self.window()
            )
        except Exception as e:
            error_msg = str(e)
            logging.error(f"启动隧道失败: {error_msg}")
            InfoBar.error(
                title="启动失败",
                content=f"隧道启动失败: {error_msg}",
                position=InfoBarPosition.TOP_RIGHT,
                duration=5000,
                parent=self.window()
            )

            try:
                with QMutexLocker(self.process_lock):
                    if tunnel_info['name'] in self.tunnel_processes:
                        del self.tunnel_processes[tunnel_info['name']]
            except:
                pass

    def stop_tunnel(self, tunnel_card):
        """停止隧道"""
        tunnel_name = tunnel_card.tunnel_info['name']

        with QMutexLocker(self.process_lock):
            if tunnel_name not in self.tunnel_processes:
                InfoBar.info(
                    title="提示",
                    content=f"隧道 {tunnel_name} 未在运行",
                    position=InfoBarPosition.TOP_RIGHT,
                    duration=2000,
                    parent=self.window()
                )
                return

            process = self.tunnel_processes[tunnel_name]

            try:
                process.terminate()

                start_time = time.time()
                while process.poll() is None and time.time() - start_time < 3:
                    time.sleep(0.1)

                if process.poll() is None:
                    process.kill()

                exit_code = process.poll()

                with QMutexLocker(self.output_mutex):
                    if tunnel_name in self.tunnel_outputs:
                        self.tunnel_outputs[tunnel_name][
                            'output'] += f"<br><span style='color: blue;'>[I] 隧道被手动停止，退出代码: {exit_code}</span><br>"

                        if (self.tunnel_outputs[tunnel_name]['dialog'] and
                                not self.tunnel_outputs[tunnel_name]['dialog'].isHidden()):
                            dialog = self.tunnel_outputs[tunnel_name]['dialog']
                            output = self.tunnel_outputs[tunnel_name]['output']
                            run_number = self.tunnel_outputs[tunnel_name]['run_number']
                            QTimer.singleShot(0, lambda: dialog.add_output(tunnel_name, output, run_number))

                del self.tunnel_processes[tunnel_name]

                tunnel_card.update_status(False)

                InfoBar.success(
                    title="成功",
                    content=f"隧道 {tunnel_name} 已停止",
                    position=InfoBarPosition.TOP_RIGHT,
                    duration=2000,
                    parent=self.window()
                )

            except Exception as e:
                logging.error(f"停止隧道失败: {str(e)}")
                InfoBar.error(
                    title="错误",
                    content=f"停止隧道失败: {str(e)}",
                    position=InfoBarPosition.TOP_RIGHT,
                    duration=3000,
                    parent=self.window()
                )

    def edit_tunnel(self, tunnel_card):
        """编辑隧道"""
        tunnel_info = tunnel_card.tunnel_info
        dialog = TunnelEditDialog(tunnel_info, self)
        dialog.exec()

    def delete_tunnel(self, tunnel_card):
        """删除单个隧道"""
        tunnel_name = tunnel_card.tunnel_info['name']
        tunnel_id = tunnel_card.tunnel_info['id']

        dialog = MessageBox(
            "确认删除",
            f"确定要删除隧道 {tunnel_name} 吗？此操作不可撤销。",
            self.window()
        )

        def confirm_delete():
            with QMutexLocker(self.process_lock):
                if tunnel_name in self.tunnel_processes:
                    InfoBar.warning(
                        title="警告",
                        content=f"隧道 {tunnel_name} 正在运行，请先停止后再删除",
                        position=InfoBarPosition.TOP_RIGHT,
                        duration=3000,
                        parent=self.window()
                    )
                    return

            self.delete_thread = TunnelDeleteThread(token_manager.get_token(), tunnel_id)
            self.delete_thread.deleteFinished.connect(
                lambda success, msg: self.handle_delete_result(success, msg, tunnel_card))
            self.delete_thread.start()

        dialog.yesButton.clicked.connect(confirm_delete)
        dialog.exec()

    def handle_delete_result(self, success, message, tunnel_card):
        """处理删除操作的结果"""
        if success:
            self.grid_layout.removeWidget(tunnel_card)
            tunnel_card.deleteLater()
            if tunnel_card in self.tunnel_cards:
                self.tunnel_cards.remove(tunnel_card)

            self.reorganize_grid_layout()
            self.update_selection_status()

            InfoBar.success(
                title="成功",
                content=message,
                position=InfoBarPosition.TOP_RIGHT,
                duration=2000,
                parent=self.window()
            )
        else:
            InfoBar.error(
                title="删除失败",
                content=message,
                position=InfoBarPosition.TOP_RIGHT,
                duration=3000,
                parent=self.window()
            )

    def start_frequent_tunnel_monitor(self, tunnel_name):
        """开始以高频率监控隧道进程状态"""
        QTimer.singleShot(100, lambda: self.check_tunnel_status_frequent(tunnel_name))

    def check_tunnel_status_frequent(self, tunnel_name):
        """高频率检查隧道状态"""
        try:
            with QMutexLocker(self.process_lock):
                if tunnel_name not in self.tunnel_processes:
                    for card in self.tunnel_cards:
                        if card.tunnel_info['name'] == tunnel_name:
                            card.update_status(False)
                            break
                    return

                process = self.tunnel_processes[tunnel_name]

            if process.poll() is not None:
                exit_code = process.returncode
                error_message = f"进程退出，退出代码: {exit_code}"

                if exit_code == -1073741819:  # 0xC0000005
                    error_message += " (内存访问冲突, 可能是由于节点离线或网络问题)"

                with QMutexLocker(self.output_mutex):
                    if tunnel_name in self.tunnel_outputs:
                        self.tunnel_outputs[tunnel_name][
                            'output'] += f"<br><span style='color: red;'>[E] {error_message}</span><br>"

                        if (self.tunnel_outputs[tunnel_name]['dialog'] and
                                not self.tunnel_outputs[tunnel_name]['dialog'].isHidden()):
                            dialog = self.tunnel_outputs[tunnel_name]['dialog']
                            output = self.tunnel_outputs[tunnel_name]['output']
                            run_number = self.tunnel_outputs[tunnel_name]['run_number']
                            QTimer.singleShot(0, lambda: dialog.add_output(tunnel_name, output, run_number))

                with QMutexLocker(self.process_lock):
                    if tunnel_name in self.tunnel_processes:
                        del self.tunnel_processes[tunnel_name]

                for card in self.tunnel_cards:
                    if card.tunnel_info['name'] == tunnel_name:
                        card.update_status(False)
                        break

                InfoBar.error(
                    title="隧道异常停止",
                    content=f"隧道 {tunnel_name} 已停止运行: {error_message}",
                    position=InfoBarPosition.TOP_RIGHT,
                    duration=5000,
                    parent=self.window()
                )

                QTimer.singleShot(100, self.load_tunnels)
                return

            QTimer.singleShot(100, lambda: self.check_tunnel_status_frequent(tunnel_name))

        except Exception as e:
            logging.error(f"监控隧道状态失败: {str(e)}")
            InfoBar.error(
                title="监控错误",
                content=f"监控隧道状态失败: {str(e)}",
                position=InfoBarPosition.TOP_RIGHT,
                duration=3000,
                parent=self.window()
            )
            for card in self.tunnel_cards:
                if card.tunnel_info['name'] == tunnel_name:
                    card.update_status(False)
                    break

    def show_tunnel_log(self, tunnel_card):
        """显示隧道日志"""
        tunnel_name = tunnel_card.tunnel_info['name']
        with QMutexLocker(self.output_mutex):
            if tunnel_name not in self.tunnel_outputs:
                self.tunnel_outputs[tunnel_name] = {
                    'output': "<b>暂无日志</b>",
                    'dialog': None,
                    'run_number': 0
                }

            output = self.tunnel_outputs[tunnel_name]['output']
            run_number = self.tunnel_outputs[tunnel_name]['run_number']

            existing_dialog = self.tunnel_outputs[tunnel_name]['dialog']

            if existing_dialog is None or existing_dialog.isHidden():
                dialog = TunnelLogDialog(tunnel_name, output, run_number, self)
                self.tunnel_outputs[tunnel_name]['dialog'] = dialog

                dialog.show()
                dialog.raise_()
                dialog.activateWindow()
            else:
                existing_dialog.raise_()
                existing_dialog.activateWindow()
                existing_dialog.force_refresh()


class DomainCard(CardWidget):
    """域名卡片"""
    selectionChanged = pyqtSignal(bool)

    def __init__(self, domain_info, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.domain_info = domain_info
        self.init_ui()

    def init_ui(self):
        """初始化界面"""
        self.setFixedSize(470, 150)  # 固定尺寸

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(12, 10, 12, 10)
        main_layout.setSpacing(6)

        # 标题行
        title_layout = QHBoxLayout()
        title_layout.setContentsMargins(0, 0, 0, 0)
        title_layout.setSpacing(8)

        self.checkbox = CheckBox(self)
        self.checkbox.stateChanged.connect(self.on_selection_changed)
        title_layout.addWidget(self.checkbox)

        # 显示完整域名
        full_domain = f"{self.domain_info['record']}.{self.domain_info['domain']}"
        title_label = BodyLabel(full_domain, self)
        title_label.setStyleSheet("font-weight: bold; font-size: 13px;")
        title_layout.addWidget(title_label)

        title_layout.addStretch()

        # 记录类型标签
        type_badge = InfoBadge.info(self.domain_info['type'], self)
        type_badge.setFixedSize(40, 16)
        title_layout.addWidget(type_badge)

        # 复制按钮
        self.copy_button = TransparentToolButton(FluentIcon.COPY, self)
        self.copy_button.setFixedSize(24, 24)
        self.copy_button.setToolTip("复制域名")
        self.copy_button.clicked.connect(self.copy_domain)
        title_layout.addWidget(self.copy_button)

        # 菜单按钮
        self.menu_button = TransparentToolButton(FluentIcon.MORE, self)
        self.menu_button.setFixedSize(24, 24)
        self.menu_button.clicked.connect(self.show_menu)
        title_layout.addWidget(self.menu_button)

        main_layout.addLayout(title_layout)

        # 信息网格
        info_layout = QGridLayout()
        info_layout.setContentsMargins(0, 2, 0, 2)
        info_layout.setHorizontalSpacing(15)
        info_layout.setVerticalSpacing(3)

        info_items = [
            ("根域名", self.domain_info['domain']),
            ("记录值", self.domain_info['record']),
            ("目标", self.domain_info['target']),
            ("TTL", self.domain_info['ttl']),
            ("备注", self.domain_info.get('remarks', '无') or '无'),
            ("ID", str(self.domain_info['id'])),
        ]

        row, col = 0, 0
        for label, value in info_items:
            if value:
                label_widget = CaptionLabel(f"{label}:", self)
                label_widget.setTextColor("#666666", "#cccccc")
                value_widget = CaptionLabel(str(value), self)

                info_layout.addWidget(label_widget, row, col * 2)
                info_layout.addWidget(value_widget, row, col * 2 + 1)

                col += 1
                if col >= 2:
                    col = 0
                    row += 1

        main_layout.addLayout(info_layout)
        main_layout.addStretch()

    def on_selection_changed(self, state):
        """复选框状态变化"""
        self.selectionChanged.emit(state == Qt.CheckState.Checked.value)

    def is_selected(self):
        """获取选择状态"""
        return self.checkbox.isChecked()

    def set_selected(self, selected):
        """设置选择状态"""
        self.checkbox.setChecked(selected)

    def show_menu(self):
        """显示操作菜单"""
        menu = RoundMenu(parent=self)

        edit_action = Action(FluentIcon.EDIT, '编辑域名')
        edit_action.triggered.connect(lambda: self.parent.edit_domain(self))
        menu.addAction(edit_action)

        delete_action = Action(FluentIcon.DELETE, '删除域名')
        delete_action.triggered.connect(lambda: self.parent.delete_domain(self))
        menu.addAction(delete_action)

        menu.exec(self.menu_button.mapToGlobal(self.menu_button.rect().bottomLeft()))

    def copy_domain(self):
        """复制域名"""
        full_domain = f"{self.domain_info['record']}.{self.domain_info['domain']}"
        QApplication.clipboard().setText(full_domain)
        InfoBar.success(
            title="成功",
            content=f"域名已复制: {full_domain}",
            position=InfoBarPosition.TOP_RIGHT,
            duration=2000,
            parent=self.window()
        )


class DomainLoaderThread(QThread):
    """域名加载线程"""
    dataLoaded = pyqtSignal(dict)

    def __init__(self, token):
        super().__init__()
        self.token = token

    def run(self):
        try:
            url = f"http://cf-v2.uapis.cn/get_user_free_subdomains?token={self.token}"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                self.dataLoaded.emit(data)
            else:
                self.dataLoaded.emit({"code": response.status_code, "msg": "请求失败"})
        except Exception as e:
            self.dataLoaded.emit({"code": 500, "msg": f"网络错误: {str(e)}"})
        finally:
            self.quit()


class DomainDeleteThread(QThread):
    """域名删除线程"""
    deleteFinished = pyqtSignal(bool, str)

    def __init__(self, token, domain_info):
        super().__init__()
        self.token = token
        self.domain_info = domain_info

    def run(self):
        try:
            url = "http://cf-v2.uapis.cn/delete_free_subdomain"
            params = {
                'token': self.token,
                'domain': self.domain_info['domain'],
                'record': self.domain_info['record']
            }

            headers = {
                'Content-Type': 'application/json',
                'User-Agent': USER_AGENT
            }

            response = requests.post(url, json=params, headers=headers, timeout=10)

            if response.status_code == 200:
                data = response.json()
                if data.get("code") == 200:
                    self.deleteFinished.emit(True, data.get("msg", "删除成功"))
                else:
                    self.deleteFinished.emit(False, data.get("msg", "删除失败"))
            else:
                self.deleteFinished.emit(False, f"请求失败: HTTP {response.status_code}")
        except Exception as e:
            self.deleteFinished.emit(False, f"网络错误: {str(e)}")
        finally:
            self.quit()


class AvailableDomainsThread(QThread):
    """获取可用域名列表线程"""
    dataLoaded = pyqtSignal(dict)

    def run(self):
        try:
            url = "http://cf-v2.uapis.cn/list_available_domains"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                self.dataLoaded.emit(data)
            else:
                self.dataLoaded.emit({"code": response.status_code, "msg": "请求失败"})
        except Exception as e:
            self.dataLoaded.emit({"code": 500, "msg": f"网络错误: {str(e)}"})
        finally:
            self.quit()


class DomainCreateThread(QThread):
    """创建域名线程"""
    createFinished = pyqtSignal(bool, str)

    def __init__(self, token, domain_data):
        super().__init__()
        self.token = token
        self.domain_data = domain_data

    def run(self):
        try:
            url = "http://cf-v2.uapis.cn/create_free_subdomain"
            params = {
                'token': self.token,
                'domain': self.domain_data['domain'],
                'record': self.domain_data['record'],
                'type': self.domain_data['type'],
                'target': self.domain_data['target'],
                'ttl': self.domain_data['ttl'],
                'remarks': self.domain_data['remarks']
            }

            headers = {
                'Content-Type': 'application/json',
                'User-Agent': USER_AGENT
            }

            response = requests.post(url, json=params, headers=headers, timeout=15)

            if response.status_code == 200:
                data = response.json()
                if data.get("code") == 200:
                    self.createFinished.emit(True, data.get("msg", "域名创建成功"))
                else:
                    self.createFinished.emit(False, data.get("msg", "域名创建失败"))
            else:
                self.createFinished.emit(False, f"请求失败: HTTP {response.status_code}")

        except Exception as e:
            self.createFinished.emit(False, f"网络错误: {str(e)}")
        finally:
            self.quit()

class DomainAddDialog(MessageBoxBase):
    """域名添加对话框"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.available_domains = []
        self.setWindowTitle("添加域名")
        self.init_ui()
        QTimer.singleShot(100, self.load_available_domains)

    def init_ui(self):
        """初始化界面"""
        self.resize(1000, 600)
        self.yesButton.hide()
        self.cancelButton.hide()

        main_widget = QWidget()
        main_layout = QVBoxLayout(main_widget)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(15)

        # 标题
        title_label = SubtitleLabel("添加免费二级域名", self)
        main_layout.addWidget(title_label)

        # 表单
        form_layout = QFormLayout()
        form_layout.setSpacing(15)

        # 主域名选择
        self.domain_combo = ComboBox()
        self.domain_combo.setPlaceholderText("正在加载可用域名...")
        self.domain_combo.setEnabled(False)
        form_layout.addRow("主域名:", self.domain_combo)

        # 记录（子域名）
        self.record_edit = LineEdit()
        self.record_edit.setPlaceholderText("例如: mysite (最终域名为 mysite.主域名)")
        form_layout.addRow("记录:", self.record_edit)

        # 类型选择
        self.type_combo = ComboBox()
        self.type_combo.addItems(["A", "AAAA", "CNAME", "SRV"])
        self.type_combo.currentTextChanged.connect(self.on_type_changed)
        form_layout.addRow("类型:", self.type_combo)

        # 目标
        self.target_edit = LineEdit()
        self.target_edit.setPlaceholderText("例如: 192.168.1.1 或 example.com")
        form_layout.addRow("目标:", self.target_edit)

        # TTL选择
        self.ttl_combo = ComboBox()
        ttl_options = [
            "1分钟", "2分钟", "5分钟", "10分钟", "15分钟", "30分钟",
            "1小时", "2小时", "5小时", "12小时", "1天"
        ]
        self.ttl_combo.addItems(ttl_options)
        self.ttl_combo.setCurrentText("5分钟")
        form_layout.addRow("TTL:", self.ttl_combo)

        # 备注
        self.remarks_edit = LineEdit()
        self.remarks_edit.setPlaceholderText("例如: 解析隧道:ChmlFrp-Tunnel")
        form_layout.addRow("备注:", self.remarks_edit)

        main_layout.addLayout(form_layout)

        # 提示信息
        tip_card = CardWidget(self)
        tip_layout = QVBoxLayout(tip_card)
        tip_layout.setContentsMargins(15, 10, 15, 10)

        tip_title = BodyLabel("💡 提示", tip_card)
        tip_title.setStyleSheet("font-weight: bold;")
        tip_layout.addWidget(tip_title)

        tips = [
            "• A/AAAA记录: 解析到IPv4/IPv6地址",
            "• CNAME/SRV记录: 解析到另一个域名/用于特定服务的记录",
            "• TTL越短更新越快，长则反之"
        ]

        for tip in tips:
            tip_label = CaptionLabel(tip, tip_card)
            tip_label.setTextColor("#666666", "#cccccc")
            tip_layout.addWidget(tip_label)

        main_layout.addWidget(tip_card)
        main_layout.addStretch()

        self.viewLayout.addWidget(main_widget)

        # 按钮
        self.create_button = PrimaryPushButton("创建域名")
        self.create_button.clicked.connect(self.create_domain)
        self.create_button.setEnabled(False)

        self.cancel_button = PushButton("取消")
        self.cancel_button.clicked.connect(self.close)

        while self.buttonLayout.count():
            item = self.buttonLayout.takeAt(0)
            if item.widget():
                item.widget().hide()

        self.buttonLayout.addStretch()
        self.buttonLayout.addWidget(self.create_button)
        self.buttonLayout.addWidget(self.cancel_button)
        self.buttonLayout.addStretch()

    def load_available_domains(self):
        """加载可用域名列表"""
        self.loader_thread = AvailableDomainsThread()
        self.loader_thread.dataLoaded.connect(self.on_domains_loaded)
        self.loader_thread.start()

    def on_domains_loaded(self, data):
        """域名列表加载完成"""
        if data.get("code") == 200:
            self.available_domains = data.get("data", [])
            self.domain_combo.clear()
            self.domain_combo.setEnabled(True)

            if not self.available_domains:
                self.domain_combo.addItem("暂无可用域名")
                self.create_button.setEnabled(False)
                return

            for domain_info in self.available_domains:
                domain = domain_info.get("domain", "")
                remarks = domain_info.get("remarks", "")
                icp = domain_info.get("icpFiling", False)

                display_text = domain
                if remarks:
                    display_text += f" - {remarks}"
                if icp:
                    display_text += " (已备案)"

                self.domain_combo.addItem(display_text, domain)

            self.create_button.setEnabled(True)
        else:
            self.domain_combo.clear()
            self.domain_combo.addItem("加载失败")
            self.domain_combo.setEnabled(True)
            self.create_button.setEnabled(False)

            InfoBar.error(
                title="加载失败",
                content=data.get("msg", "获取可用域名失败"),
                position=InfoBarPosition.TOP_RIGHT,
                duration=3000,
                parent=self.window()
            )

    def on_type_changed(self, type_text):
        """记录类型改变时更新提示"""
        if type_text == "A":
            self.target_edit.setPlaceholderText("例如: 192.168.1.1")
        elif type_text == "AAAA":
            self.target_edit.setPlaceholderText("例如: 2001:db8::1")
        elif type_text == "CNAME":
            self.target_edit.setPlaceholderText("例如: example.com")
        elif type_text == "SRV":
            self.target_edit.setPlaceholderText("例如: 0 5 5060 sipserver.example.com")

    def validate_input(self):
        """验证输入"""
        # 检查域名
        if self.domain_combo.currentIndex() < 0:
            return False, "请选择主域名"

        # 检查记录
        record = self.record_edit.text().strip()
        if not record:
            return False, "请输入记录（子域名）"

        # 验证记录格式
        if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$', record):
            return False, "记录格式无效，只能包含字母、数字和连字符"

        # 检查目标
        target = self.target_edit.text().strip()
        if not target:
            return False, "请输入目标"

        # 根据类型验证目标
        record_type = self.type_combo.currentText()
        if record_type == "A":
            # 验证IPv4地址
            try:
                import ipaddress
                ipaddress.IPv4Address(target)
            except:
                return False, "请输入有效的IPv4地址"
        elif record_type == "AAAA":
            # 验证IPv6地址
            try:
                import ipaddress
                ipaddress.IPv6Address(target)
            except:
                return False, "请输入有效的IPv6地址"
        elif record_type == "CNAME":
            # 验证域名格式
            if not re.match(r'^([a-zA-Z0-9-]+\.)*[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$', target):
                return False, "请输入有效的域名"

        # 检查备注
        remarks = self.remarks_edit.text().strip()
        if not remarks:
            return False, "请输入备注信息"

        return True, ""

    def create_domain(self):
        """创建域名"""
        is_valid, error_msg = self.validate_input()
        if not is_valid:
            InfoBar.error(
                title="输入错误",
                content=error_msg,
                position=InfoBarPosition.TOP_RIGHT,
                duration=3000,
                parent=self.window()
            )
            return

        token = token_manager.get_token()
        if not token:
            InfoBar.error(
                title="未登录",
                content="请先登录后再创建域名",
                position=InfoBarPosition.TOP_RIGHT,
                duration=3000,
                parent=self.window()
            )
            return

        domain_data = {
            'domain': self.domain_combo.currentData(),
            'record': self.record_edit.text().strip(),
            'type': self.type_combo.currentText(),
            'target': self.target_edit.text().strip(),
            'ttl': self.ttl_combo.currentText(),
            'remarks': self.remarks_edit.text().strip()
        }

        self.create_button.setText("创建中...")
        self.create_button.setEnabled(False)

        self.create_thread = DomainCreateThread(token, domain_data)
        self.create_thread.createFinished.connect(self.on_create_finished)
        self.create_thread.start()

    def on_create_finished(self, success, message):
        """创建完成"""
        self.create_button.setText("创建域名")
        self.create_button.setEnabled(True)

        if success:
            InfoBar.success(
                title="创建成功",
                content=message,
                position=InfoBarPosition.TOP_RIGHT,
                duration=3000,
                parent=self.window()
            )
            self.close()

            # 刷新域名列表
            if hasattr(self.parent(), 'load_domains'):
                QTimer.singleShot(1000, self.parent().load_domains)
        else:
            InfoBar.error(
                title="创建失败",
                content=message,
                position=InfoBarPosition.TOP_RIGHT,
                duration=5000,
                parent=self.window()
            )

class DomainEditDialog(MessageBoxBase):
    """域名编辑对话框"""

    def __init__(self, domain_info, parent=None):
        super().__init__(parent)
        self.domain_info = domain_info
        self.setWindowTitle("编辑域名")
        self.init_ui()

    def init_ui(self):
        """初始化界面"""
        self.resize(1000, 600)
        self.yesButton.hide()
        self.cancelButton.hide()

        main_widget = QWidget()
        main_layout = QVBoxLayout(main_widget)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(15)

        # 标题
        title_label = SubtitleLabel("编辑域名", self)
        main_layout.addWidget(title_label)

        # 只读信息区域
        readonly_card = CardWidget(self)
        readonly_layout = QVBoxLayout(readonly_card)
        readonly_layout.setContentsMargins(15, 15, 15, 15)
        readonly_layout.setSpacing(12)

        # 只读信息标题
        readonly_title = CaptionLabel("域名信息（不可修改）", readonly_card)
        readonly_title.setTextColor("#666666", "#cccccc")
        readonly_layout.addWidget(readonly_title)

        # 只读字段网格布局
        readonly_form = QGridLayout()
        readonly_form.setSpacing(8)
        readonly_form.setColumnStretch(1, 1)

        # 主域名（只读美化显示）
        domain_label = BodyLabel("主域名:")
        domain_label.setTextColor("#333333", "#ffffff")
        self.domain_display = self.create_readonly_display(self.domain_info.get('domain', ''))
        readonly_form.addWidget(domain_label, 0, 0)
        readonly_form.addWidget(self.domain_display, 0, 1)

        # 记录（只读美化显示）
        record_label = BodyLabel("记录:")
        record_label.setTextColor("#333333", "#ffffff")
        self.record_display = self.create_readonly_display(self.domain_info.get('record', ''))
        readonly_form.addWidget(record_label, 1, 0)
        readonly_form.addWidget(self.record_display, 1, 1)

        # 类型（只读美化显示）
        type_label = BodyLabel("类型:")
        type_label.setTextColor("#333333", "#ffffff")
        self.type_display = self.create_readonly_display(self.domain_info.get('type', ''))
        readonly_form.addWidget(type_label, 2, 0)
        readonly_form.addWidget(self.type_display, 2, 1)

        readonly_layout.addLayout(readonly_form)
        main_layout.addWidget(readonly_card)

        # 可编辑字段区域
        editable_card = CardWidget(self)
        editable_layout = QVBoxLayout(editable_card)
        editable_layout.setContentsMargins(15, 15, 15, 15)
        editable_layout.setSpacing(12)

        # 可编辑信息标题
        editable_title = CaptionLabel("编辑信息", editable_card)
        editable_title.setTextColor("#666666", "#cccccc")
        editable_layout.addWidget(editable_title)

        # 表单
        form_layout = QFormLayout()
        form_layout.setSpacing(15)
        form_layout.setLabelAlignment(Qt.AlignmentFlag.AlignLeft)

        # 目标（可编辑）
        self.target_edit = LineEdit()
        self.target_edit.setText(self.domain_info.get('target', ''))
        self.update_target_placeholder()
        form_layout.addRow("目标:", self.target_edit)

        # TTL（可编辑）
        self.ttl_combo = ComboBox()
        ttl_options = [
            "1分钟", "2分钟", "5分钟", "10分钟", "15分钟", "30分钟",
            "1小时", "2小时", "5小时", "12小时", "1天"
        ]
        self.ttl_combo.addItems(ttl_options)
        current_ttl = self.domain_info.get('ttl', '5分钟')
        if current_ttl in ttl_options:
            self.ttl_combo.setCurrentText(current_ttl)
        form_layout.addRow("TTL:", self.ttl_combo)

        # 备注（可编辑）
        self.remarks_edit = LineEdit()
        self.remarks_edit.setText(self.domain_info.get('remarks', ''))
        self.remarks_edit.setPlaceholderText("例如: 解析隧道:ChmlFrp-Tunnel")
        form_layout.addRow("备注:", self.remarks_edit)

        editable_layout.addLayout(form_layout)
        main_layout.addWidget(editable_card)

        self.viewLayout.addWidget(main_widget)

        # 按钮
        self.update_button = PrimaryPushButton("更新域名")
        self.update_button.clicked.connect(self.update_domain)

        self.cancel_button = PushButton("取消")
        self.cancel_button.clicked.connect(self.close)

        while self.buttonLayout.count():
            item = self.buttonLayout.takeAt(0)
            if item.widget():
                item.widget().hide()

        self.buttonLayout.addStretch()
        self.buttonLayout.addWidget(self.update_button)
        self.buttonLayout.addWidget(self.cancel_button)
        self.buttonLayout.addStretch()

    def create_readonly_display(self, text):
        """创建只读信息的美化显示控件"""
        container = QWidget()
        layout = QHBoxLayout(container)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(8)

        # 文本标签
        text_label = BodyLabel(text or "未设置")
        text_label.setTextColor("#333333", "#ffffff")

        layout.addWidget(text_label)
        layout.addStretch()

        return container

    def update_target_placeholder(self):
        """更新目标输入框的提示"""
        record_type = self.domain_info.get('type', '')
        if record_type == "A":
            self.target_edit.setPlaceholderText("例如: 192.168.1.1")
        elif record_type == "AAAA":
            self.target_edit.setPlaceholderText("例如: 2001:db8::1")
        elif record_type == "CNAME":
            self.target_edit.setPlaceholderText("例如: example.com")
        elif record_type == "SRV":
            self.target_edit.setPlaceholderText("例如: 0 5 5060 sipserver.example.com")

    def validate_input(self):
        """验证输入"""
        # 检查目标
        target = self.target_edit.text().strip()
        if not target:
            return False, "请输入目标"

        # 根据类型验证目标
        record_type = self.domain_info.get('type', '')
        if record_type == "A":
            # 验证IPv4地址
            try:
                import ipaddress
                ipaddress.IPv4Address(target)
            except:
                return False, "请输入有效的IPv4地址"
        elif record_type == "AAAA":
            # 验证IPv6地址
            try:
                import ipaddress
                ipaddress.IPv6Address(target)
            except:
                return False, "请输入有效的IPv6地址"
        elif record_type == "CNAME":
            # 验证域名格式
            if not re.match(r'^([a-zA-Z0-9-]+\.)*[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$', target):
                return False, "请输入有效的域名"

        # 检查备注
        remarks = self.remarks_edit.text().strip()
        if not remarks:
            return False, "请输入备注信息"

        return True, ""

    def update_domain(self):
        """更新域名"""
        is_valid, error_msg = self.validate_input()
        if not is_valid:
            InfoBar.error(
                title="输入错误",
                content=error_msg,
                position=InfoBarPosition.TOP_RIGHT,
                duration=3000,
                parent=self.window()
            )
            return

        token = token_manager.get_token()
        if not token:
            InfoBar.error(
                title="未登录",
                content="请先登录后再更新域名",
                position=InfoBarPosition.TOP_RIGHT,
                duration=3000,
                parent=self.window()
            )
            return

        domain_data = {
            'domain': self.domain_info.get('domain', ''),
            'record': self.domain_info.get('record', ''),
            'target': self.target_edit.text().strip(),
            'ttl': self.ttl_combo.currentText(),
            'remarks': self.remarks_edit.text().strip()
        }

        self.update_button.setText("更新中...")
        self.update_button.setEnabled(False)

        self.update_thread = DomainUpdateThread(token, domain_data)
        self.update_thread.updateFinished.connect(self.on_update_finished)
        self.update_thread.start()

    def on_update_finished(self, success, message):
        """更新完成"""
        self.update_button.setText("更新域名")
        self.update_button.setEnabled(True)

        if success:
            InfoBar.success(
                title="更新成功",
                content=message,
                position=InfoBarPosition.TOP_RIGHT,
                duration=3000,
                parent=self.window()
            )
            self.close()

            # 刷新域名列表
            if hasattr(self.parent(), 'load_domains'):
                QTimer.singleShot(1000, self.parent().load_domains)
        else:
            InfoBar.error(
                title="更新失败",
                content=message,
                position=InfoBarPosition.TOP_RIGHT,
                duration=5000,
                parent=self.window()
            )

class DomainUpdateThread(QThread):
    """更新域名线程"""
    updateFinished = pyqtSignal(bool, str)

    def __init__(self, token, domain_data):
        super().__init__()
        self.token = token
        self.domain_data = domain_data

    def run(self):
        try:
            url = "http://cf-v2.uapis.cn/update_free_subdomain"
            params = {
                'token': self.token,
                'domain': self.domain_data['domain'],
                'record': self.domain_data['record'],
                'target': self.domain_data['target'],
                'ttl': self.domain_data['ttl'],
                'remarks': self.domain_data['remarks']
            }

            headers = {
                'Content-Type': 'application/json',
                'User-Agent': USER_AGENT
            }

            response = requests.post(url, json=params, headers=headers, timeout=15)

            if response.status_code == 200:
                data = response.json()
                if data.get("code") == 200:
                    self.updateFinished.emit(True, data.get("msg", "域名更新成功"))
                else:
                    self.updateFinished.emit(False, data.get("msg", "域名更新失败"))
            else:
                self.updateFinished.emit(False, f"请求失败: HTTP {response.status_code}")

        except Exception as e:
            self.updateFinished.emit(False, f"网络错误: {str(e)}")
        finally:
            self.quit()

class DomainManagementPage(QWidget):
    """域名管理页面"""

    def __init__(self, parent=None):
        super().__init__(parent=parent)
        self.setObjectName("domainManagementPage")
        self.domain_cards = []
        self.loader_thread = None
        self.init_ui()
        self.load_domains()

    def init_ui(self):
        """初始化界面"""
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(15)

        # 顶部操作栏
        top_bar = self.create_top_bar()
        main_layout.addWidget(top_bar)

        # 批量操作栏
        batch_bar = self.create_batch_bar()
        main_layout.addWidget(batch_bar)

        # 滚动区域
        self.scroll_area = SingleDirectionScrollArea(orient=Qt.Orientation.Vertical)
        self.scroll_area.setWidgetResizable(True)
        self.scroll_content = QWidget()
        self.scroll_area.setWidget(self.scroll_content)
        self.scroll_area.enableTransparentBackground()
        self.scroll_content.setStyleSheet("background: transparent;")

        self.grid_layout = QGridLayout(self.scroll_content)
        self.grid_layout.setContentsMargins(0, 0, 0, 0)
        self.grid_layout.setSpacing(15)
        self.grid_layout.setColumnStretch(0, 1)
        self.grid_layout.setColumnStretch(1, 1)

        self.loading_label = BodyLabel("正在加载域名列表...", self)
        self.loading_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.grid_layout.addWidget(self.loading_label, 0, 0, 1, 2)

        main_layout.addWidget(self.scroll_area)

    def create_top_bar(self):
        """创建顶部操作栏"""
        top_bar = QWidget(self)
        top_layout = QHBoxLayout(top_bar)
        top_layout.setContentsMargins(0, 0, 0, 0)

        self.refresh_btn = PushButton("刷新", self)
        self.refresh_btn.setIcon(FluentIcon.SYNC)
        self.refresh_btn.clicked.connect(self.load_domains)

        self.add_domain_btn = PrimaryPushButton("添加域名", self)
        self.add_domain_btn.setIcon(FluentIcon.ADD)
        self.add_domain_btn.clicked.connect(self.add_domain)

        top_layout.addWidget(self.refresh_btn)
        top_layout.addStretch()
        top_layout.addWidget(self.add_domain_btn)

        return top_bar

    def create_batch_bar(self):
        """创建批量操作栏"""
        batch_bar = QWidget(self)
        batch_layout = QHBoxLayout(batch_bar)
        batch_layout.setContentsMargins(0, 0, 0, 0)
        batch_layout.setSpacing(10)

        self.select_all_btn = PushButton("全选", self)
        self.select_all_btn.setIcon(FluentIcon.CHECKBOX)
        self.select_all_btn.clicked.connect(self.select_all)

        self.select_none_btn = PushButton("取消全选", self)
        self.select_none_btn.setIcon(FluentIcon.CANCEL)
        self.select_none_btn.clicked.connect(self.select_none)

        self.select_inverse_btn = PushButton("反选", self)
        self.select_inverse_btn.setIcon(FluentIcon.SYNC)
        self.select_inverse_btn.clicked.connect(self.select_inverse)

        self.batch_delete_btn = PushButton("批量删除", self)
        self.batch_delete_btn.setIcon(FluentIcon.DELETE)
        self.batch_delete_btn.clicked.connect(self.batch_delete)

        self.selection_label = CaptionLabel("未选择任何域名", self)
        self.selection_label.setTextColor("#666666", "#cccccc")

        batch_layout.addWidget(self.select_all_btn)
        batch_layout.addWidget(self.select_none_btn)
        batch_layout.addWidget(self.select_inverse_btn)
        batch_layout.addWidget(QFrame())
        batch_layout.addWidget(self.batch_delete_btn)
        batch_layout.addStretch()
        batch_layout.addWidget(self.selection_label)

        return batch_bar

    def load_domains(self):
        """加载域名列表"""
        if self.loader_thread and self.loader_thread.isRunning():
            self.loader_thread.terminate()
            self.loader_thread.wait(1000)

        try:
            if hasattr(self, 'loading_label') and self.loading_label:
                self.loading_label.setText("正在加载域名列表...")
                self.loading_label.show()
        except RuntimeError:
            self.loading_label = BodyLabel("正在加载域名列表...", self)
            self.loading_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.grid_layout.addWidget(self.loading_label, 0, 0, 1, 2)

        self.clear_domain_cards()

        token = token_manager.get_token()
        if not token:
            self.loading_label.setText("请先登录后再查看域名")
            InfoBar.warning(
                title="未登录",
                content="请先登录后再查看域名",
                position=InfoBarPosition.TOP_RIGHT,
                duration=3000,
                parent=self.window()
            )
            return

        self.loader_thread = DomainLoaderThread(token)
        self.loader_thread.dataLoaded.connect(self.handle_domains_data)
        self.loader_thread.start()

    def clear_domain_cards(self):
        """清空域名卡片"""
        self.domain_cards.clear()

        items_to_remove = []
        for i in range(self.grid_layout.count()):
            item = self.grid_layout.itemAt(i)
            if item and item.widget() and item.widget() != self.loading_label:
                items_to_remove.append(item.widget())

        for widget in items_to_remove:
            self.grid_layout.removeWidget(widget)
            widget.deleteLater()

    def handle_domains_data(self, data):
        """处理获取到的域名数据"""
        try:
            if data.get("code") == 200:
                domains = data.get("data", [])
                try:
                    if hasattr(self, 'loading_label') and self.loading_label:
                        if not domains:
                            self.loading_label.setText("暂无域名，请点击添加域名按钮创建")
                            return
                        else:
                            self.loading_label.hide()
                except RuntimeError:
                    pass

                if not domains:
                    try:
                        if not hasattr(self, 'loading_label') or not self.loading_label:
                            self.loading_label = BodyLabel("暂无域名，请点击添加域名按钮创建", self)
                            self.loading_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
                        else:
                            self.loading_label.setText("暂无域名，请点击添加域名按钮创建")
                            self.loading_label.show()
                        self.grid_layout.addWidget(self.loading_label, 0, 0, 1, 2)
                    except RuntimeError:
                        pass
                    return

                row = 0
                col = 0
                for domain in domains:
                    domain_card = DomainCard(domain, self)
                    domain_card.selectionChanged.connect(self.update_selection_status)
                    self.domain_cards.append(domain_card)

                    self.grid_layout.addWidget(domain_card, row, col)

                    col += 1
                    if col >= 2:
                        col = 0
                        row += 1

                self.update_selection_status()

                InfoBar.success(
                    title="加载成功",
                    content=f"成功加载 {len(domains)} 个域名",
                    position=InfoBarPosition.TOP_RIGHT,
                    duration=2000,
                    parent=self.window()
                )
            else:
                error_msg = data.get("msg", "未知错误")
                try:
                    if hasattr(self, 'loading_label') and self.loading_label:
                        self.loading_label.setText(f"加载失败: {error_msg}")
                        self.loading_label.show()
                    else:
                        self.loading_label = BodyLabel(f"加载失败: {error_msg}", self)
                        self.loading_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
                    self.grid_layout.addWidget(self.loading_label, 0, 0, 1, 2)
                except RuntimeError:
                    pass

                InfoBar.error(
                    title="加载失败",
                    content=error_msg,
                    position=InfoBarPosition.TOP_RIGHT,
                    duration=3000,
                    parent=self.window()
                )
        except Exception as e:
            logging.error(f"处理域名数据时出错: {e}")
            InfoBar.error(
                title="错误",
                content=f"处理数据时发生错误: {str(e)}",
                position=InfoBarPosition.TOP_RIGHT,
                duration=3000,
                parent=self.window()
            )
        finally:
            if hasattr(self, 'loader_thread'):
                self.loader_thread = None

    def select_all(self):
        """全选"""
        for card in self.domain_cards:
            card.set_selected(True)
        self.update_selection_status()

    def select_none(self):
        """取消全选"""
        for card in self.domain_cards:
            card.set_selected(False)
        self.update_selection_status()

    def select_inverse(self):
        """反选"""
        for card in self.domain_cards:
            card.set_selected(not card.is_selected())
        self.update_selection_status()

    def update_selection_status(self):
        """更新选择状态标签"""
        selected_count = sum(1 for card in self.domain_cards if card.is_selected())
        total_count = len(self.domain_cards)

        if selected_count == 0:
            self.selection_label.setText("未选择任何域名")
        else:
            self.selection_label.setText(f"已选择 {selected_count} / {total_count} 个域名")

    def add_domain(self):
        """添加新域名"""
        if not token_manager.get_token():
            InfoBar.warning(
                title="未登录",
                content="请先登录后再操作",
                position=InfoBarPosition.TOP_RIGHT,
                duration=3000,
                parent=self.window()
            )
            return

        dialog = DomainAddDialog(self)
        dialog.exec()

    def edit_domain(self, domain_card):
        """编辑域名"""
        dialog = DomainEditDialog(domain_card.domain_info, self)
        dialog.exec()

    def delete_domain(self, domain_card):
        """删除单个域名"""
        domain_info = domain_card.domain_info
        full_domain = f"{domain_info['record']}.{domain_info['domain']}"

        dialog = MessageBox(
            "确认删除",
            f"确定要删除域名 {full_domain} 吗？此操作不可撤销。",
            self.window()
        )

        def confirm_delete():
            self.delete_thread = DomainDeleteThread(token_manager.get_token(), domain_info)
            self.delete_thread.deleteFinished.connect(
                lambda success, msg: self.handle_delete_result(success, msg, domain_card))
            self.delete_thread.start()

        dialog.yesButton.clicked.connect(confirm_delete)
        dialog.exec()

    def handle_delete_result(self, success, message, domain_card):
        """处理删除操作的结果"""
        if success:
            self.grid_layout.removeWidget(domain_card)
            domain_card.deleteLater()
            if domain_card in self.domain_cards:
                self.domain_cards.remove(domain_card)

            self.reorganize_grid_layout()
            self.update_selection_status()

            InfoBar.success(
                title="成功",
                content=message,
                position=InfoBarPosition.TOP_RIGHT,
                duration=2000,
                parent=self.window()
            )
        else:
            InfoBar.error(
                title="删除失败",
                content=message,
                position=InfoBarPosition.TOP_RIGHT,
                duration=3000,
                parent=self.window()
            )

    def batch_delete(self):
        """批量删除"""
        selected_cards = [card for card in self.domain_cards if card.is_selected()]

        if not selected_cards:
            InfoBar.warning(
                title="警告",
                content="请先选择要删除的域名",
                position=InfoBarPosition.TOP_RIGHT,
                duration=3000,
                parent=self.window()
            )
            return

        domain_names = [f"{card.domain_info['record']}.{card.domain_info['domain']}"
                        for card in selected_cards]

        dialog = MessageBox(
            "确认批量删除",
            f"确定要删除以下 {len(selected_cards)} 个域名吗？\n\n"
            f"{', '.join(domain_names[:3])}{'...' if len(domain_names) > 3 else ''}\n\n"
            f"此操作不可撤销。",
            self.window()
        )

        def confirm_batch_delete():
            self.perform_batch_delete(selected_cards)

        dialog.yesButton.clicked.connect(confirm_batch_delete)
        dialog.exec()

    def perform_batch_delete(self, cards_to_delete):
        """执行批量删除"""
        delete_count = 0
        failed_deletions = []
        token = token_manager.get_token()

        for card in cards_to_delete:
            domain_info = card.domain_info
            domain_name = f"{card.domain_info['record']}.{card.domain_info['domain']}"

            try:
                url = "http://cf-v2.uapis.cn/delete_free_subdomain"
                params = {
                    'token': token,
                    'domain': domain_info['domain'],
                    'record': domain_info['record']
                }

                headers = {
                    'Content-Type': 'application/json',
                    'User-Agent': USER_AGENT
                }

                response = requests.post(url, json=params, headers=headers, timeout=10)

                if response.status_code == 200:
                    data = response.json()
                    if data.get("code") == 200:
                        self.grid_layout.removeWidget(card)
                        card.deleteLater()
                        if card in self.domain_cards:
                            self.domain_cards.remove(card)
                        delete_count += 1
                    else:
                        failed_deletions.append(f"{domain_name}: {data.get('msg', '删除失败')}")
                else:
                    failed_deletions.append(f"{domain_name}: HTTP {response.status_code}")

            except Exception as e:
                failed_deletions.append(f"{domain_name}: {str(e)}")

        self.reorganize_grid_layout()
        self.update_selection_status()

        if delete_count > 0:
            InfoBar.success(
                title="批量删除完成",
                content=f"成功删除 {delete_count} 个域名",
                position=InfoBarPosition.TOP_RIGHT,
                duration=3000,
                parent=self.window()
            )

        if failed_deletions:
            InfoBar.error(
                title="部分删除失败",
                content=f"以下域名删除失败：\n{chr(10).join(failed_deletions[:3])}"
                        f"{'...' if len(failed_deletions) > 3 else ''}",
                position=InfoBarPosition.TOP_RIGHT,
                duration=5000,
                parent=self.window()
            )

    def reorganize_grid_layout(self):
        """重新整理网格布局"""
        cards = []
        for card in self.domain_cards:
            self.grid_layout.removeWidget(card)
            cards.append(card)

        row = 0
        col = 0
        for card in cards:
            self.grid_layout.addWidget(card, row, col)
            col += 1
            if col >= 2:
                col = 0
                row += 1

class GradientLabel(QLabel):
    """支持渐变色的标签组件"""

    def __init__(self, text="", parent=None):
        super().__init__(text, parent)
        self.gradient_colors = ["#FF6B6B", "#4ECDC4"]
        self.setMinimumHeight(40)

    def setGradientColors(self, colors):
        """设置渐变颜色列表"""
        self.gradient_colors = colors
        self.update()

    def paintEvent(self, event):
        """自定义绘制事件，实现渐变文字"""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        # 创建渐变
        gradient = QLinearGradient(0, 0, self.width(), 0)
        for i, color in enumerate(self.gradient_colors):
            position = i / (len(self.gradient_colors) - 1) if len(self.gradient_colors) > 1 else 0
            gradient.setColorAt(position, QColor(color))

        brush = QBrush(gradient)
        pen = QPen(brush, 1)
        painter.setPen(pen)
        painter.setFont(self.font())

        rect = self.rect()
        painter.drawText(rect, self.alignment(), self.text())
        painter.end()

class GreetingCard(CardWidget):
    """问候卡片"""
    def __init__(self, avatar_path, username, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.username = username
        self.setFixedHeight(130)

        self.mainLayout = QHBoxLayout(self)
        self.mainLayout.setContentsMargins(20, 15, 20, 15)
        self.mainLayout.setSpacing(20)

        self.avatarLabel = QLabel(self)
        self.avatarLabel.setFixedSize(72, 72)
        self.avatarLabel.setScaledContents(True)
        self.avatarLabel.setStyleSheet("""
            QLabel {
                border-radius: 36px;
                background-color: #f5f5f5;
            }
        """)

        try:
            pixmap = QPixmap()
            pixmap.loadFromData(requests.get(avatar_path).content)
            rounded_pixmap = QPixmap(72, 72)
            rounded_pixmap.fill(Qt.GlobalColor.transparent)
            painter = QPainter(rounded_pixmap)
            painter.setRenderHint(QPainter.RenderHint.Antialiasing)
            path = QPainterPath()
            path.addEllipse(0, 0, 72, 72)
            painter.setClipPath(path)
            painter.drawPixmap(0, 0, 72, 72, pixmap)
            painter.end()
            self.avatarLabel.setPixmap(rounded_pixmap)
        except:
            self.avatarLabel.setPixmap(QPixmap(":/favicon.ico"))

        self.textLayout = QVBoxLayout()
        self.textLayout.setSpacing(5)
        self.textLayout.addSpacing(10)

        self.greetingLabel = BodyLabel("", self)
        self.greetingLabel.setStyleSheet("font-weight: bold; font-size: 16px;")

        self.sayLabel = CaptionLabel("正在获取每日一言...", self)
        self.sayLabel.setTextColor("#606060", "#d2d2d2")
        self.sayLabel.setWordWrap(True)

        self.textLayout.addWidget(self.greetingLabel)
        self.textLayout.addSpacing(5)
        self.textLayout.addWidget(self.sayLabel)
        self.textLayout.addStretch()

        self.buttonLayout = QVBoxLayout()
        self.buttonLayout.setSpacing(10)
        self.buttonLayout.addSpacing(5)

        self.copyTokenButton = PrimaryPushButton("复制 Token", self)
        self.copyTokenButton.setFixedWidth(110)
        self.copyTokenButton.clicked.connect(self.copyToken)

        self.logoutButton = PushButton("退出登录", self)
        self.logoutButton.setFixedWidth(110)
        self.logoutButton.clicked.connect(self.parent.logout)

        self.buttonLayout.addWidget(self.copyTokenButton)
        self.buttonLayout.addWidget(self.logoutButton)
        self.buttonLayout.addStretch()

        self.mainLayout.addWidget(self.avatarLabel, 0, Qt.AlignmentFlag.AlignTop)
        self.mainLayout.addLayout(self.textLayout, 1)
        self.mainLayout.addLayout(self.buttonLayout, 0)

        self.updateGreeting()
        self.fetchDailySay()

    def copyToken(self):
        """复制Token到剪贴板"""
        token = token_manager.get_token() or ""
        QApplication.clipboard().setText(token)
        InfoBar.success(
            title="成功",
            content="Token 已复制到剪贴板",
            position=InfoBarPosition.TOP_RIGHT,
            duration=2000,
            parent=self.window()
        )

    def updateGreeting(self):
        """更新问候语"""
        hour = datetime.now().hour
        if 0 <= hour < 6:
            greeting = f"夜深了，{self.username}，夜晚依然静谧，但新的希望已经开始萌芽。"
        elif 6 <= hour < 11:
            greeting = f"早上好，{self.username}，今天又是充满活力的一天。"
        elif 11 <= hour < 14:
            greeting = f"中午好，{self.username}，享受这温暖的阳光和美味的午餐吧。"
        elif 14 <= hour < 15:
            greeting = f"饮茶先啦，{self.username}，3点多啦，饮茶先啦。"
        elif 15 <= hour < 17:
            greeting = f"下午好，{self.username}，午后的时光总是最适合专注与思考。"
        elif 17 <= hour < 22:
            greeting = f"晚上好，{self.username}，夜幕降临，是时候享受片刻宁静了。"
        else:
            greeting = f"夜深了，{self.username}，记得早点休息，明天会更美好。"
        self.greetingLabel.setText(greeting)

    def fetchDailySay(self):
        """获取每日一言"""
        try:
            response = requests.get("https://uapis.cn/api/say", timeout=5)
            if response.status_code == 200:
                self.sayLabel.setText(response.text.strip())
            else:
                self.sayLabel.setText("今日一言获取失败")
        except Exception as e:
            self.sayLabel.setText("网络连接异常，无法获取今日一言")

class StatCard(CardWidget):
    """统计卡片"""
    def __init__(self, title, value, icon=None, parent=None):
        super().__init__(parent)
        self.setFixedHeight(80)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(15, 10, 15, 10)
        layout.setSpacing(5)

        titleLabel = CaptionLabel(title, self)
        titleLabel.setTextColor("#606060", "#d2d2d2")
        titleLabel.setAlignment(Qt.AlignmentFlag.AlignCenter)

        valueLabel = BodyLabel(str(value), self)
        valueLabel.setStyleSheet("font-weight: bold; font-size: 18px;")
        valueLabel.setAlignment(Qt.AlignmentFlag.AlignCenter)

        layout.addWidget(titleLabel)
        layout.addWidget(valueLabel)

class DetailedUserInfoCard(CardWidget):
    """用户详细信息卡片"""
    def __init__(self, user_data, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.user_data = user_data
        self.setFixedHeight(230)

        self.mainLayout = QVBoxLayout(self)
        self.mainLayout.setContentsMargins(20, 15, 20, 15)
        self.mainLayout.setSpacing(15)

        titleLayout = QHBoxLayout()
        titleLabel = BodyLabel("📋 详细信息", self)
        titleLabel.setStyleSheet("font-weight: bold; font-size: 16px;")

        self.refreshButton = PushButton("🔄 刷新信息", self)
        self.refreshButton.setFixedWidth(100)
        self.refreshButton.clicked.connect(self.refreshUserInfo)

        titleLayout.addWidget(titleLabel)
        titleLayout.addStretch()
        titleLayout.addWidget(self.refreshButton)

        self.mainLayout.addLayout(titleLayout)

        self.infoLayout = QGridLayout()
        self.infoLayout.setHorizontalSpacing(20)
        self.infoLayout.setVerticalSpacing(12)
        self.infoLayout.setContentsMargins(0, 0, 0, 0)

        self.createInfoItems()
        self.mainLayout.addLayout(self.infoLayout)
        self.mainLayout.addStretch()

    def createInfoItems(self):
        """创建信息项"""
        term = self.user_data.get('term', '')
        if term and term < "9999-09-09":
            term_display = term
        else:
            term_display = "永久"

        bandwidth = self.user_data.get('bandwidth', 0)
        bandwidth_display = f"国内: {bandwidth} Mbps / 国外: {bandwidth * 4} Mbps"

        realname = self.user_data.get('realname', '')
        if realname == '已实名':
            realname_display = "✅ 已实名"
        else:
            realname_display = "❌ 未实名"

        info_items = [
            ("🆔 用户ID", str(self.user_data.get('id', '未知'))),
            ("📅 注册时间", self.user_data.get('regtime', '未知')),
            ("👤 QQ", self.user_data.get('qq', '未绑定')),
            ("🏷️ 权限组", self.user_data.get('usergroup', '未知')),
            ("⏰ 到期时间", term_display),
            ("🔒 实名状态", realname_display),
            ("🌐 带宽限制", bandwidth_display),
            ("📧 邮箱", self.user_data.get('email', '未知'))
        ]

        while self.infoLayout.count():
            item = self.infoLayout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        row = 0
        col = 0
        for label, value in info_items:
            itemWidget = self.createInfoItem(label, value)
            self.infoLayout.addWidget(itemWidget, row, col)
            col += 1
            if col >= 4:  # 每行4个
                col = 0
                row += 1

    def createInfoItem(self, label, value):
        """创建单个信息项"""
        itemWidget = QWidget()
        itemLayout = QVBoxLayout(itemWidget)
        itemLayout.setContentsMargins(10, 8, 10, 8)
        itemLayout.setSpacing(4)

        itemWidget.setStyleSheet("""
            QWidget {
                background-color: rgba(255, 255, 255, 0.1);
                border-radius: 6px;
                border: 1px solid rgba(255, 255, 255, 0.2);
            }
        """)

        labelWidget = CaptionLabel(label, itemWidget)
        labelWidget.setTextColor("#606060", "#d2d2d2")
        labelWidget.setAlignment(Qt.AlignmentFlag.AlignLeft)

        valueWidget = BodyLabel(str(value), itemWidget)
        valueWidget.setStyleSheet("font-weight: 500;")
        valueWidget.setAlignment(Qt.AlignmentFlag.AlignLeft)
        valueWidget.setWordWrap(True)

        itemLayout.addWidget(labelWidget)
        itemLayout.addWidget(valueWidget)

        return itemWidget

    def refreshUserInfo(self):
        """刷新用户信息"""
        token = token_manager.get_token()
        if not token:
            InfoBar.warning(
                title="未登录",
                content="请先登录以刷新用户信息",
                position=InfoBarPosition.TOP_RIGHT,
                duration=3000,
                parent=self.window()
            )
            return

        # 显示加载提示
        self.refreshButton.setText("🔄 刷新中...")
        self.refreshButton.setEnabled(False)

        # 创建刷新线程
        self.refreshThread = UserInfoRefreshThread(token)
        self.refreshThread.dataLoaded.connect(self.onDataRefreshed)
        self.refreshThread.start()

    def onDataRefreshed(self, data):
        """数据刷新完成"""
        self.refreshButton.setText("🔄 刷新信息")
        self.refreshButton.setEnabled(True)

        if data.get("code") == 200:
            self.user_data = data.get("data", {})
            self.createInfoItems()
            InfoBar.success(
                title="刷新成功",
                content="用户信息已更新",
                position=InfoBarPosition.TOP_RIGHT,
                duration=2000,
                parent=self.window()
            )
        else:
            InfoBar.error(
                title="刷新失败",
                content=data.get("msg", "未知错误"),
                position=InfoBarPosition.TOP_RIGHT,
                duration=3000,
                parent=self.window()
            )
        if hasattr(self, "refreshThread"):
            self.refreshThread.deleteLater()
            del self.refreshThread

class UserInfoRefreshThread(QThread):
    """用户信息刷新"""
    dataLoaded = pyqtSignal(dict)

    def __init__(self, token):
        super().__init__()
        self.token = token

    def run(self):
        """执行用户信息刷新请求"""
        try:
            url = f"http://cf-v2.uapis.cn/userinfo?token={self.token}"

            response = requests.get(url, timeout=10, headers={
                'User-Agent': USER_AGENT
            })

            if response.status_code == 200:
                data = response.json()
                self.dataLoaded.emit(data)
            else:
                self.dataLoaded.emit({
                    "code": response.status_code,
                    "msg": f"请求失败: HTTP {response.status_code}"
                })

        except requests.exceptions.Timeout:
            self.dataLoaded.emit({
                "code": 408,
                "msg": "请求超时，请检查网络连接"
            })
        except requests.exceptions.ConnectionError:
            self.dataLoaded.emit({
                "code": 503,
                "msg": "网络连接错误，无法访问服务器"
            })
        except requests.exceptions.RequestException as e:
            self.dataLoaded.emit({
                "code": 500,
                "msg": f"网络请求错误: {str(e)}"
            })
        except json.JSONDecodeError:
            self.dataLoaded.emit({
                "code": 502,
                "msg": "服务器响应格式错误"
            })
        except Exception as e:
            self.dataLoaded.emit({
                "code": 500,
                "msg": f"未知错误: {str(e)}"
            })
        finally:
            self.quit()

class TipCard(CardWidget):
    """提示卡片"""
    def __init__(self, parent=None):
        super().__init__(parent)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 15, 20, 15)
        layout.setSpacing(10)

        titleLabel = BodyLabel("💡 提示", self)
        titleLabel.setStyleSheet("font-weight: bold; font-size: 16px;")

        tipText = """如果这里没有您想了解的，可以前往 TechCat Docs 或 TechCat QQ交流群询问。

QQ群：
• 一群：992067118
• 二群：592908249  
• 三群：838521529"""

        contentLabel = CaptionLabel(tipText, self)
        contentLabel.setTextColor("#606060", "#d2d2d2")
        contentLabel.setWordWrap(True)

        linkButton = HyperlinkButton("TechCat Docs", "https://docs.chcat.cn/", self)
        linkButton.setIcon(FluentIcon.LINK)

        layout.addWidget(titleLabel)
        layout.addWidget(contentLabel)
        layout.addWidget(linkButton, 0, Qt.AlignmentFlag.AlignLeft)

class InfoCard(CardWidget):
    """信息卡片"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 15, 20, 15)
        layout.setSpacing(15)

        titleLabel = BodyLabel("📊 平台信息", self)
        titleLabel.setStyleSheet("font-weight: bold; font-size: 16px;")
        layout.addWidget(titleLabel)

        self.statsLayout = QVBoxLayout()
        self.statsLayout.setSpacing(8)

        self.tunnelCountLabel = CaptionLabel("隧道总数: 获取中...", self)
        self.nodeCountLabel = CaptionLabel("节点总数: 获取中...", self)
        self.userCountLabel = CaptionLabel("用户总数: 获取中...", self)

        self.statsLayout.addWidget(self.tunnelCountLabel)
        self.statsLayout.addWidget(self.nodeCountLabel)
        self.statsLayout.addWidget(self.userCountLabel)

        layout.addLayout(self.statsLayout)

        self.messagesLayout = QVBoxLayout()
        self.messagesTitle = BodyLabel("📢 消息通知", self)
        self.messagesTitle.setStyleSheet("font-weight: bold; font-size: 14px;")
        self.messagesLayout.addWidget(self.messagesTitle)

        self.messagesContainer = QVBoxLayout()
        self.messagesContainer.setSpacing(5)
        self.messagesLayout.addLayout(self.messagesContainer)

        layout.addLayout(self.messagesLayout)
        layout.addStretch()

        self.fetchPanelInfo()
        self.fetchMessages()

    def fetchPanelInfo(self):
        """获取平台信息"""
        try:
            response = requests.get("http://cf-v2.uapis.cn/panelinfo", timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get("code") == 200:
                    panel_data = data.get("data", {})
                    self.tunnelCountLabel.setText(f"隧道总数: {panel_data.get('tunnel_amount', 0):,}")
                    self.nodeCountLabel.setText(f"节点总数: {panel_data.get('node_amount', 0)}")
                    self.userCountLabel.setText(f"用户总数: {panel_data.get('user_amount', 0):,}")
                else:
                    self.showError("平台信息获取失败")
            else:
                self.showError("平台信息获取失败")
        except Exception as e:
            self.showError("网络连接异常")

    def fetchMessages(self):
        """获取消息"""
        token = token_manager.get_token()
        if not token:
            return
        try:
            response = requests.get(f"http://cf-v2.uapis.cn/messages?token={token}", timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get("code") == 200:
                    messages = data.get("data", [])
                    self.displayMessages(messages[:3])
                else:
                    self.addMessageItem("暂无消息通知")
            else:
                self.addMessageItem("消息获取失败")
        except Exception as e:
            self.addMessageItem("网络连接异常")

    def displayMessages(self, messages):
        """显示消息"""
        if not messages:
            self.addMessageItem("暂无消息通知")
            return

        for message in messages:
            content = message.get("content", "")
            time_str = message.get("time", "")
            quanti = message.get("quanti", "no")

            try:
                time_obj = datetime.fromisoformat(time_str.replace("Z", "+00:00"))
                formatted_time = time_obj.strftime("%m-%d %H:%M")
            except:
                formatted_time = "未知时间"

            if len(content) > 50:
                content = content[:50] + "..."

            message_text = f"[{formatted_time}] {content}"
            if quanti == "yes":
                message_text = "🔔 " + message_text

            self.addMessageItem(message_text)

    def addMessageItem(self, text):
        """添加消息项"""
        messageLabel = CaptionLabel(text, self)
        messageLabel.setTextColor("#606060", "#d2d2d2")
        messageLabel.setWordWrap(True)
        self.messagesContainer.addWidget(messageLabel)

    def showError(self, error_text):
        """显示错误信息"""
        self.tunnelCountLabel.setText(f"隧道总数: {error_text}")
        self.nodeCountLabel.setText(f"节点总数: {error_text}")
        self.userCountLabel.setText(f"用户总数: {error_text}")

class InfoItemCard(CardWidget):
    def __init__(self, label, value, parent=None):
        super().__init__(parent)
        self.setFixedSize(180, 60)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(10, 5, 10, 5)
        layout.addWidget(QLabel(f"<b>{label}:</b>"))
        layout.addWidget(QLabel(str(value)))
        layout.addStretch()

class UserInfoCard(CardWidget):
    def __init__(self, avatar_path, user_data, parent=None):
        super().__init__(parent)
        self.parent = parent

        self.avatarLabel = QLabel(self)
        self.avatarLabel.setFixedSize(110, 110)
        self.avatarLabel.setScaledContents(True)
        try:
            pixmap = QPixmap()
            pixmap.loadFromData(requests.get(avatar_path).content)
            self.avatarLabel.setPixmap(pixmap)
        except:
            self.avatarLabel.setPixmap(QPixmap(":/favicon.ico"))

        self.tokenButton = PrimaryPushButton("复制 Token", self)
        self.tokenButton.clicked.connect(self.copyToken)
        self.tokenButton.setFixedWidth(120)

        self.logoutButton = PushButton("退出登录", self)
        self.logoutButton.clicked.connect(self.parent.logout)
        self.logoutButton.setFixedWidth(120)

        self.leftLayout = QVBoxLayout()
        self.leftLayout.setContentsMargins(0, 0, 15, 0)
        self.leftLayout.setSpacing(10)
        self.leftLayout.addWidget(self.avatarLabel, 0, Qt.AlignmentFlag.AlignHCenter)
        self.leftLayout.addWidget(self.tokenButton, 0, Qt.AlignmentFlag.AlignHCenter)
        self.leftLayout.addWidget(self.logoutButton, 0, Qt.AlignmentFlag.AlignHCenter)
        self.leftLayout.addStretch()

        self.rightLayout = QGridLayout()
        self.rightLayout.setHorizontalSpacing(10)
        self.rightLayout.setVerticalSpacing(10)
        self.rightLayout.setContentsMargins(0, 0, 0, 0)

        term = user_data['term'] if user_data['term'] < "9999-09-09" else "永久"

        info_items = [
            ("ID", user_data['id']),
            ("用户名", user_data['username']),
            ("注册时间", user_data['regtime']),
            ("邮箱", user_data['email']),
            ("实名状态", user_data['realname']),
            ("用户组", user_data['usergroup']),
            ("国内带宽", f"{user_data['bandwidth']} Mbps"),
            ("国外带宽", f"{user_data['bandwidth'] * 4} Mbps"),
            ("隧道数量", f"{user_data['tunnelCount']} / {user_data['tunnel']}"),
            ("积分", user_data['integral']),
            ("到期时间", term),
            ("上传数据", f"{user_data['total_upload'] / (1024 * 1024):.2f} MB"),
            ("下载数据", f"{user_data['total_download'] / (1024 * 1024):.2f} MB")
        ]

        row = col = 0
        for label, value in info_items:
            card = InfoItemCard(label, value, self)
            self.rightLayout.addWidget(card, row, col)
            col += 1
            if col == 4:
                col = 0
                row += 1

        self.mainLayout = QHBoxLayout(self)
        self.mainLayout.setContentsMargins(15, 15, 15, 15)
        self.mainLayout.addLayout(self.leftLayout)
        self.mainLayout.addLayout(self.rightLayout)
        self.mainLayout.setStretch(0, 1)
        self.mainLayout.setStretch(1, 3)

    def copyToken(self):
        current_token = token_manager.get_token() or ""
        QApplication.clipboard().setText(current_token)
        InfoBar.success(
            title="成功",
            content="Token 已复制到剪贴板",
            position=InfoBarPosition.TOP_RIGHT,
            duration=2000,
            parent=self.window()
        )

class LoginCard(CardWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.mainLayout = QVBoxLayout(self)
        self.mainLayout.setContentsMargins(20, 25, 20, 25)
        self.mainLayout.setSpacing(20)
        self.createColorfulTitle()
        self.segmentedWidget = SegmentedWidget(self)
        self.segmentedWidget.addItem(routeKey="tokenLogin", text="Token 登录")
        self.segmentedWidget.addItem(routeKey="accountLogin", text="账户登录")
        self.stackedWidget = QStackedWidget(self)

        self.tokenLoginWidget = QWidget()
        self.tokenInput = LineEdit(self.tokenLoginWidget)
        self.tokenInput.setPlaceholderText("请输入 Token")
        self.tokenLoginButton = PrimaryPushButton("登录", self.tokenLoginWidget)
        self.tokenRegisterLink = HyperlinkLabel("还没有账户? 点击去注册！", self.tokenLoginWidget)
        self.tokenRegisterLink.setUrl("https://panel.chmlfrp.cn/")
        self.tokenLayout = QVBoxLayout(self.tokenLoginWidget)
        self.tokenLayout.addWidget(QLabel("Token:"))
        self.tokenLayout.addWidget(self.tokenInput)
        self.tokenLayout.addStretch()
        self.tokenLayout.addWidget(self.tokenLoginButton)
        self.tokenLayout.addWidget(self.tokenRegisterLink)

        self.accountLoginWidget = QWidget()
        self.usernameInput = LineEdit(self.accountLoginWidget)
        self.usernameInput.setPlaceholderText("请输入用户名")
        self.passwordInput = PasswordLineEdit(self.accountLoginWidget)
        self.passwordInput.setPlaceholderText("请输入密码")
        self.accountLoginButton = PrimaryPushButton("登录", self.accountLoginWidget)
        self.accountRegisterLink = HyperlinkLabel("还没有账户? 点击去注册！", self.accountLoginWidget)
        self.accountRegisterLink.setUrl("https://panel.chmlfrp.cn/")
        self.accountLayout = QVBoxLayout(self.accountLoginWidget)
        self.accountLayout.addWidget(QLabel("用户名:"))
        self.accountLayout.addWidget(self.usernameInput)
        self.accountLayout.addWidget(QLabel("密码:"))
        self.accountLayout.addWidget(self.passwordInput)
        self.accountLayout.addStretch()
        self.accountLayout.addWidget(self.accountLoginButton)
        self.accountLayout.addWidget(self.accountRegisterLink)

        self.stackedWidget.addWidget(self.tokenLoginWidget)
        self.stackedWidget.addWidget(self.accountLoginWidget)

        self.mainLayout.addWidget(self.segmentedWidget)
        self.mainLayout.addWidget(self.stackedWidget)

        self.segmentedWidget.currentItemChanged.connect(self.onSegmentChanged)
        self.tokenLoginButton.clicked.connect(self.tokenLogin)
        self.accountLoginButton.clicked.connect(self.accountLogin)

        self.segmentedWidget.setCurrentItem("tokenLogin")
        self.stackedWidget.setCurrentWidget(self.tokenLoginWidget)

    def createColorfulTitle(self):
        """创建彩色标题"""
        titleWidget = QWidget(self)
        titleLayout = QVBoxLayout(titleWidget)
        titleLayout.setContentsMargins(0, 0, 0, 0)
        titleLayout.setSpacing(5)

        chmlfrpLabel = GradientLabel("ChmlFrp", titleWidget)
        chmlfrpLabel.setAlignment(Qt.AlignmentFlag.AlignCenter)
        chmlfrpLabel.setFont(QFont("Microsoft YaHei", 28, QFont.Weight.Bold))
        chmlfrpLabel.setGradientColors([
            "#FF6B6B", "#4ECDC4", "#45B7D1", "#96CEB4", "#FFEAA7", "#DDA0DD"
        ])

        culLabel = GradientLabel("CUL", titleWidget)
        culLabel.setAlignment(Qt.AlignmentFlag.AlignCenter)
        culLabel.setFont(QFont("Microsoft YaHei", 20, QFont.Weight.DemiBold))
        culLabel.setGradientColors(["#667eea", "#764ba2", "#f093fb"])

        versionLabel = QLabel(f"v{APP_VERSION}", titleWidget)
        versionLabel.setAlignment(Qt.AlignmentFlag.AlignCenter)
        versionLabel.setStyleSheet("""
            QLabel {
                font-size: 11px;
                font-weight: normal;
                color: #888888;
                margin: 0px;
                padding: 2px 0px;
            }
        """)

        titleLayout.addWidget(chmlfrpLabel)
        titleLayout.addWidget(culLabel)
        titleLayout.addWidget(versionLabel)

        self.mainLayout.addWidget(titleWidget)

    def onSegmentChanged(self, routeKey):
        if routeKey == "tokenLogin":
            self.stackedWidget.setCurrentWidget(self.tokenLoginWidget)
        elif routeKey == "accountLogin":
            self.stackedWidget.setCurrentWidget(self.accountLoginWidget)

    def tokenLogin(self):
        token = self.tokenInput.text()
        url = f"http://cf-v2.uapis.cn/userinfo?token={token}"
        try:
            response = requests.get(url)
            if response.status_code == 200:
                data = response.json()
                if data['code'] == 200:
                    self.parent.onLoginSuccess(data['data'])
                    token_manager.set_token(token)
                    token_manager.set_username(data['data'].get('username', ''))
                    InfoBar.success(
                        title="登录成功",
                        content=data.get('msg', '欢迎回来！'),
                        position=InfoBarPosition.TOP_RIGHT,
                        duration=3000,
                        parent=self.window()
                    )
                else:
                    InfoBar.error(
                        title="登录失败",
                        content=data.get('msg', 'Token 无效'),
                        position=InfoBarPosition.TOP_RIGHT,
                        duration=3000,
                        parent=self.window()
                    )
            else:
                InfoBar.error(
                    title="错误",
                    content="服务器响应错误",
                    position=InfoBarPosition.TOP_RIGHT,
                    duration=3000,
                    parent=self.window()
                )
        except Exception as e:
            InfoBar.error(
                title="错误",
                content=f"网络错误: {str(e)}",
                position=InfoBarPosition.TOP_RIGHT,
                duration=3000,
                parent=self.window()
            )

    def accountLogin(self):
        username = self.usernameInput.text()
        password = self.passwordInput.text()
        url = f"http://cf-v2.uapis.cn/login?username={username}&password={password}"
        try:
            response = requests.get(url)
            if response.status_code == 200:
                data = response.json()
                if data['code'] == 200:
                    self.parent.onLoginSuccess(data['data'])
                    token_manager.set_token(data['data'].get('token', ''))
                    token_manager.set_username(username)
                    config_manager.set("password", password)
                    InfoBar.success(
                        title="登录成功",
                        content=data.get('msg', '欢迎回来！'),
                        position=InfoBarPosition.TOP_RIGHT,
                        duration=3000,
                        parent=self.window()
                    )
                else:
                    InfoBar.error(
                        title="登录失败",
                        content=data.get('msg', '用户名或密码错误'),
                        position=InfoBarPosition.TOP_RIGHT,
                        duration=3000,
                        parent=self.window()
                    )
            else:
                InfoBar.error(
                    title="错误",
                    content="服务器响应错误",
                    position=InfoBarPosition.TOP_RIGHT,
                    duration=3000,
                    parent=self.window()
                )
        except Exception as e:
            InfoBar.error(
                title="错误",
                content=f"网络错误: {str(e)}",
                position=InfoBarPosition.TOP_RIGHT,
                duration=3000,
                parent=self.window()
            )

class HomePage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("homePage")
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(20, 20, 20, 20)
        self.layout.setSpacing(20)

        self.scrollArea = SingleDirectionScrollArea(orient=Qt.Orientation.Vertical)
        self.scrollArea.setWidgetResizable(True)
        self.scrollContent = QWidget()
        self.scrollLayout = QVBoxLayout(self.scrollContent)
        self.scrollLayout.setContentsMargins(0, 0, 0, 0)
        self.scrollLayout.setSpacing(20)
        self.scrollArea.setWidget(self.scrollContent)
        self.scrollArea.enableTransparentBackground()
        self.scrollContent.setStyleSheet("background: transparent;")

        self.loginCard = LoginCard(self)

        center_layout = QHBoxLayout()
        center_layout.addStretch()
        center_layout.addWidget(self.loginCard)
        center_layout.addStretch()
        self.loginCard.setMaximumWidth(450)

        self.scrollLayout.addLayout(center_layout)
        self.scrollLayout.addStretch()

        self.layout.addWidget(self.scrollArea)

        self.autoLogin()

    def autoLogin(self):
        token = token_manager.get_token()
        if token:
            url = f"http://cf-v2.uapis.cn/userinfo?token={token}"
            try:
                response = requests.get(url)
                if response.status_code == 200:
                    data = response.json()
                    if data['code'] == 200:
                        self.onLoginSuccess(data['data'])
                    else:
                        InfoBar.error(
                            title="自动登录失败",
                            content=data.get('msg', 'Token 无效'),
                            position=InfoBarPosition.TOP_RIGHT,
                            duration=3000,
                            parent=self.window()
                        )
                else:
                    InfoBar.error(
                        title="错误",
                        content="服务器响应错误",
                        position=InfoBarPosition.TOP_RIGHT,
                        duration=3000,
                        parent=self.window()
                    )
            except Exception as e:
                InfoBar.error(
                    title="错误",
                    content=f"网络错误: {str(e)}",
                    position=InfoBarPosition.TOP_RIGHT,
                    duration=3000,
                    parent=self.window()
                )
        else:
            username = config_manager.get("username", "")
            password = config_manager.get("password", "")
            if username and password:
                url = f"http://cf-v2.uapis.cn/login?username={username}&password={password}"
                try:
                    response = requests.get(url)
                    if response.status_code == 200:
                        data = response.json()
                        if data['code'] == 200:
                            self.onLoginSuccess(data['data'])
                            token_manager.set_token(data['data'].get('token', ''))
                        else:
                            InfoBar.error(
                                title="自动登录失败",
                                content=data.get('msg', '用户名或密码错误'),
                                position=InfoBarPosition.TOP_RIGHT,
                                duration=3000,
                                parent=self.window()
                            )
                    else:
                        InfoBar.error(
                            title="错误",
                            content="服务器响应错误",
                            position=InfoBarPosition.TOP_RIGHT,
                            duration=3000,
                            parent=self.window()
                        )
                except Exception as e:
                    InfoBar.error(
                        title="错误",
                        content=f"网络错误: {str(e)}",
                        position=InfoBarPosition.TOP_RIGHT,
                        duration=3000,
                        parent=self.window()
                    )

    def onLoginSuccess(self, user_data):
        """登录成功后的界面重新设计"""
        self.loginCard.hide()

        while self.scrollLayout.count():
            item = self.scrollLayout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
            if item.layout():
                self.clearLayout(item.layout())

        greetingCard = GreetingCard(user_data['userimg'], user_data['username'], self)
        self.scrollLayout.addWidget(greetingCard)

        statsContainer = QWidget()
        statsLayout = QHBoxLayout(statsContainer)
        statsLayout.setContentsMargins(0, 0, 0, 0)
        statsLayout.setSpacing(15)

        stats_data = [
            ("积分", user_data.get('integral', 0)),
            ("上传流量", f"{user_data.get('total_upload', 0) / (1024 * 1024):.1f} MB"),
            ("下载流量", f"{user_data.get('total_download', 0) / (1024 * 1024):.1f} MB"),
            ("总积分", user_data.get('integral', 0)),  # 这里您可以根据需要修改为其他数据
            ("隧道数", f"{user_data.get('tunnelCount', 0)}/{user_data.get('tunnel', 0)}")
        ]

        for title, value in stats_data:
            statCard = StatCard(title, value, parent=self)
            statsLayout.addWidget(statCard)

        self.scrollLayout.addWidget(statsContainer)

        detailedInfoCard = DetailedUserInfoCard(user_data, self)
        self.scrollLayout.addWidget(detailedInfoCard)

        bottomContainer = QWidget()
        bottomLayout = QHBoxLayout(bottomContainer)
        bottomLayout.setContentsMargins(0, 0, 0, 0)
        bottomLayout.setSpacing(20)

        infoCard = InfoCard(self)
        infoCard.setMinimumWidth(400)
        bottomLayout.addWidget(infoCard)

        tipCard = TipCard(self)
        tipCard.setMinimumWidth(300)
        bottomLayout.addWidget(tipCard)

        self.scrollLayout.addWidget(bottomContainer)
        self.scrollLayout.addStretch()

    def clearLayout(self, layout):
        """清空布局的辅助方法"""
        while layout.count():
            item = layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
            elif item.layout():
                self.clearLayout(item.layout())

    def logout(self):
        token_manager.clear()

        while self.scrollLayout.count():
            item = self.scrollLayout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
            if item.layout():
                self.clearLayout(item.layout())

        self.loginCard = LoginCard(self)
        center_layout = QHBoxLayout()
        center_layout.addStretch()
        center_layout.addWidget(self.loginCard)
        center_layout.addStretch()
        self.loginCard.setMaximumWidth(450)

        self.scrollLayout.addLayout(center_layout)
        self.scrollLayout.addStretch()

        InfoBar.info(
            title="提示",
            content="已退出登录",
            position=InfoBarPosition.TOP_RIGHT,
            duration=3000,
            parent=self.window()
        )

class AboutPage(QWidget):
    """关于页面"""
    def __init__(self, parent=None):
        super().__init__(parent=parent)
        self.setObjectName("aboutPage")
        self.init_ui()

    def init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(15)
        scroll_area = SingleDirectionScrollArea(orient=Qt.Orientation.Vertical, parent=self)
        scroll_area.setWidgetResizable(True)

        scroll_area.setStyleSheet("QScrollArea{background: transparent; border: none}")
        scroll_widget = QWidget()
        scroll_widget.setStyleSheet("QWidget{background: transparent}")
        scroll_layout = QVBoxLayout(scroll_widget)
        scroll_layout.setContentsMargins(0, 0, 0, 0)
        scroll_layout.setSpacing(16)

        title_label = SubtitleLabel("CUL-CHMLFRP 启动器", self)
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        scroll_layout.addWidget(title_label)

        author_card = self.create_author_card()
        scroll_layout.addWidget(author_card)

        intro_card = self.create_intro_card()
        scroll_layout.addWidget(intro_card)

        links_card = self.create_links_card()
        scroll_layout.addWidget(links_card)

        api_card = self.create_api_card()
        scroll_layout.addWidget(api_card)

        version_card = CardWidget(self)
        version_card.setBorderRadius(8)
        version_layout = QVBoxLayout(version_card)
        version_label = CaptionLabel("CUL-CHMLFRP 启动器 © 2023-2025")
        version_layout.addWidget(version_label, 0, Qt.AlignmentFlag.AlignCenter)
        scroll_layout.addWidget(version_card)

        scroll_area.setWidget(scroll_widget)
        main_layout.addWidget(scroll_area)
        scroll_area.enableTransparentBackground()

    def create_author_card(self):
        """创建作者信息卡片"""
        author_card = CardWidget(self)
        author_card.setBorderRadius(8)
        author_card.setFixedHeight(90)

        hbox_layout = QHBoxLayout(author_card)
        hbox_layout.setContentsMargins(16, 12, 12, 12)
        hbox_layout.setSpacing(12)

        try:
            avatar_widget = QLabel(self)
            avatar_widget.setFixedSize(48, 48)
            avatar_widget.setScaledContents(True)

            avatar_widget.setStyleSheet("""
                QLabel {
                    border-radius: 10px;
                    background-color: #f5f5f5;
                }
            """)

            avatar_url = "http://q.qlogo.cn/headimg_dl?dst_uin=1972403603&spec=640&img_type=jpg"
            response = requests.get(avatar_url)
            if response.status_code == 200:
                img = QImage()
                img.loadFromData(response.content)
                if img.width() != img.height():
                    side = min(img.width(), img.height())
                    x = (img.width() - side) // 2
                    y = (img.height() - side) // 2
                    img = img.copy(x, y, side, side)

                pixmap = QPixmap.fromImage(img).scaled(
                    48, 48,
                    Qt.AspectRatioMode.IgnoreAspectRatio,
                    Qt.TransformationMode.SmoothTransformation
                )
                avatar_widget.setPixmap(pixmap)
            else:
                avatar_widget = IconWidget(FluentIcon.PEOPLE, self)
                avatar_widget.setFixedSize(48, 48)
        except Exception as e:
            logging.error(f"加载头像出错: {e}")
            avatar_widget = IconWidget(FluentIcon.PEOPLE, self)
            avatar_widget.setFixedSize(48, 48)

        hbox_layout.addWidget(avatar_widget)

        vbox_layout = QVBoxLayout()
        vbox_layout.setContentsMargins(0, 0, 0, 0)
        vbox_layout.setSpacing(2)

        title_label = BodyLabel("boring_student", self)
        content_label = CaptionLabel("CUL-CHMLFRP启动器开发者", self)
        content_label.setTextColor("#606060", "#d2d2d2")

        vbox_layout.addWidget(title_label, 0, Qt.AlignmentFlag.AlignVCenter)
        vbox_layout.addWidget(content_label, 0, Qt.AlignmentFlag.AlignVCenter)
        vbox_layout.setAlignment(Qt.AlignmentFlag.AlignVCenter)

        hbox_layout.addLayout(vbox_layout)
        hbox_layout.addStretch(1)

        repo_button = PushButton("GitHub项目", self)
        repo_button.setIcon(FluentIcon.GITHUB)
        repo_button.clicked.connect(lambda: self.open_url("https://github.com/boringstudents/CHMLFRP-UI-Launcher"))

        profile_button = PushButton("作者GitHub", self)
        profile_button.setIcon(FluentIcon.GITHUB)
        profile_button.clicked.connect(lambda: self.open_url("https://github.com/boringstudents"))

        hbox_layout.addWidget(repo_button, 0, Qt.AlignmentFlag.AlignRight)
        hbox_layout.addWidget(profile_button, 0, Qt.AlignmentFlag.AlignRight)
        author_card.clicked.connect(lambda: self.open_url("https://github.com/boringstudents"))

        return author_card

    def create_intro_card(self):
        """创建项目介绍卡片"""
        intro_card = HeaderCardWidget(self)
        intro_card.setBorderRadius(8)
        intro_card.setTitle("项目介绍")

        intro_text = """
        CUL (CHMLFRP-UI-Launcher) 是基于PyQt6开发的 CHMLFRP 第三方图形化启动器。
    使用GPL-3.0 license的开源协议。
        """
        info_label = BodyLabel(intro_text.strip(), intro_card)
        info_icon = IconWidget(InfoBarIcon.INFORMATION, intro_card)
        info_icon.setFixedSize(16, 16)

        favicon_label = QLabel(intro_card)
        favicon_label.setPixmap(QIcon('favicon.ico').pixmap(48, 48))
        favicon_label.setAlignment(Qt.AlignmentFlag.AlignVCenter)

        main_layout = QHBoxLayout()
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(15)

        main_layout.addWidget(favicon_label)

        right_layout = QHBoxLayout()
        right_layout.addWidget(info_icon)
        right_layout.addWidget(info_label, stretch=1)
        right_layout.setSpacing(8)

        main_layout.addLayout(right_layout, stretch=1)

        intro_card.viewLayout.addLayout(main_layout)
        return intro_card

    def create_links_card(self):
        """创建相关链接卡片"""
        links_card = GroupHeaderCardWidget(self)
        links_card.setBorderRadius(8)
        links_card.setTitle("相关链接")
        links = [
            ("xcl", "枫相的xcl2", "https://xcl.chmlfrp.com"),
            ("cat", "千依🅥的cat", "https://cat.chmlfrp.com"),
            ("cat", "我的CSL", "https://csl.chmlfrp.com"),
            ("cat", "纯爱战神的frpc-ui", "https://frpcui.chmlfrp.com"),
            ("cat", "唐鹏程的内网穿透辅助工具", "内网穿透辅助工具.chmlfrp.com"),
            ("cul", "就这个！！！", "https://cul.chmlfrp.com")
        ]

        for icon, name, url in links:
            button = HyperlinkButton(name, url, self)
            button.setIcon(FluentIcon.LINK)
            group = links_card.addGroup(FluentIcon.LINK, name, url, button)
            button.clicked.connect(lambda checked=False, link=url: self.open_url(link))

        github_links = [
            ("frpc", "CHMLFRP官方魔改frpc", "https://github.com/TechCat-Team/ChmlFrp-Frp"),
            ("panel", "ChmlFrp-Panel-v3开源", "https://github.com/TechCat-Team/ChmlFrp-Panel-v3"),
            ("techcat", "TechCat开源代码", "https://github.com/orgs/TechCat-Team")
        ]

        for icon, name, url in github_links:
            button = HyperlinkButton(name, url, self)
            button.setIcon(FluentIcon.GITHUB)
            group = links_card.addGroup(FluentIcon.GITHUB, name, url, button)
            button.clicked.connect(lambda checked=False, link=url: self.open_url(link))
            if icon != "techcat":
                group.setSeparatorVisible(True)

        return links_card

    def create_api_card(self):
        """创建API文档卡片"""
        api_card = GroupHeaderCardWidget(self)
        api_card.setBorderRadius(8)
        api_card.setTitle("API文档")
        api_links = [
            ("群友API文档", "https://docs.api.chmlfrp.com"),
            ("官方API v2文档", "https://docs.apiv2.chmlfrp.com"),
            ("CUL-API文档", "https://culapi.apifox.cn"),
            ("ChmlFrp第三方启动器联盟", "https://all.chmlfrp.com"),
            ("官方BUG链接", "http://bug.chmlfrp.com")
        ]

        for name, url in api_links:
            button = HyperlinkButton(name, url, self)
            button.setIcon(FluentIcon.DOCUMENT)
            group = api_card.addGroup(FluentIcon.DOCUMENT, name, url, button)
            button.clicked.connect(lambda checked=False, link=url: self.open_url(link))
            if name != "官方BUG链接":
                group.setSeparatorVisible(True)
        return api_card

    def open_url(self, url):
        """打开URL的辅助方法"""
        QDesktopServices.openUrl(QUrl(url))

class ApiServerStatusThread(QThread):
    """API服务器状态数据加载"""
    dataLoaded = pyqtSignal(dict)

    def run(self):
        try:
            url = "http://cf-v2.uapis.cn/api/server-status"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                self.dataLoaded.emit(data)
        except Exception as e:
            logging.error(f"获取API服务器状态失败: {e}")
        finally:
            self.quit()

class NodeStatusPage(QWidget):
    """节点状态页面"""
    def __init__(self, parent=None):
        super().__init__(parent=parent)
        self.setObjectName("nodeStatusPage")
        self.raw_data = []
        self.current_filter = "all"
        self.filter_vip = True
        self.filter_udp = True
        self.filter_web = True
        self.filter_foreign = True
        self.api_server_data = None

        self.mainLayout = QVBoxLayout(self)
        self.mainLayout.setContentsMargins(0, 0, 0, 0)
        self.mainLayout.setSpacing(15)
        self.setupToolBar()

        self.scrollArea = SingleDirectionScrollArea(orient=Qt.Orientation.Vertical)
        self.scrollArea.setWidgetResizable(True)
        self.scrollContent = QWidget()
        self.scrollLayout = QVBoxLayout(self.scrollContent)
        self.scrollLayout.setContentsMargins(20, 0, 20, 20)
        self.scrollLayout.setSpacing(15)
        self.scrollArea.setWidget(self.scrollContent)
        self.scrollArea.enableTransparentBackground()
        self.scrollContent.setStyleSheet("background: transparent;")

        self.mainLayout.addWidget(self.scrollArea)
        self.refreshData()

        self.format_traffic = lambda \
                bytes: f"{bytes / 1024 ** 2:.1f} MB" if bytes < 1024 ** 3 else f"{bytes / 1024 ** 3:.1f} GB"

        self.refreshTimer = QTimer()
        self.refreshTimer.timeout.connect(self.refreshData)
        self.refreshTimer.start(30000)  # 30秒

    def setupToolBar(self):
        toolBar = QWidget()
        hLayout = QHBoxLayout(toolBar)
        hLayout.setContentsMargins(20, 10, 20, 10)

        self.filterCombo = ComboBox()
        self.filterCombo.addItems(["所有节点", "在线节点", "离线节点", "低负载节点"])
        self.filterCombo.currentIndexChanged.connect(self.applyFilter)

        hLayout.addWidget(QLabel("节点筛选:"))
        hLayout.addWidget(self.filterCombo)

        self.checkVip = CheckBox("VIP")
        self.checkUdp = CheckBox("UDP")
        self.checkWeb = CheckBox("Web")
        self.checkForeign = CheckBox("非大陆")

        self.checkVip.setChecked(True)
        self.checkUdp.setChecked(True)
        self.checkWeb.setChecked(True)
        self.checkForeign.setChecked(True)

        self.checkVip.stateChanged.connect(self.updateTagFilters)
        self.checkUdp.stateChanged.connect(self.updateTagFilters)
        self.checkWeb.stateChanged.connect(self.updateTagFilters)
        self.checkForeign.stateChanged.connect(self.updateTagFilters)

        hLayout.addWidget(self.checkVip)
        hLayout.addWidget(self.checkUdp)
        hLayout.addWidget(self.checkWeb)
        hLayout.addWidget(self.checkForeign)

        stats_widget = QWidget()
        stats_layout = QHBoxLayout(stats_widget)
        stats_layout.setContentsMargins(15, 0, 15, 0)
        stats_layout.setSpacing(6)

        self.label_total = QLabel("总节点: 0")
        self.label_online = QLabel("在线节点: 0")
        self.label_offline = QLabel("离线节点: 0")
        self.label_clients = QLabel("客户端: 0")
        self.label_tunnels = QLabel("隧道: 0")

        for label in [self.label_online, self.label_offline, self.label_clients, self.label_tunnels]:
            label.setMinimumWidth(70)
        self.label_online.setStyleSheet("color: #27ae60;")
        self.label_offline.setStyleSheet("color: #c0392b;")

        def add_sep():
            sep = QLabel("|")
            sep.setStyleSheet("color: #95a5a6;")
            return sep

        stats_layout.addWidget(self.label_total)
        stats_layout.addWidget(add_sep())
        stats_layout.addWidget(self.label_online)
        stats_layout.addWidget(add_sep())
        stats_layout.addWidget(self.label_offline)
        stats_layout.addWidget(add_sep())
        stats_layout.addWidget(self.label_clients)
        stats_layout.addWidget(add_sep())
        stats_layout.addWidget(self.label_tunnels)

        hLayout.addWidget(stats_widget)
        hLayout.addStretch()

        self.refreshBtn = PushButton('刷新', self)
        self.refreshBtn.setFixedWidth(80)
        self.refreshBtn.clicked.connect(self.refreshData)
        hLayout.addWidget(self.refreshBtn)

        self.mainLayout.addWidget(toolBar)

    def updateTagFilters(self):
        """更新标签筛选状态"""
        self.filter_vip = self.checkVip.isChecked()
        self.filter_udp = self.checkUdp.isChecked()
        self.filter_web = self.checkWeb.isChecked()
        self.filter_foreign = self.checkForeign.isChecked()
        self.updateDisplay()

    def updateStatistics(self):
        """更新统计信息显示"""
        total = len(self.raw_data)
        online = sum(1 for n in self.raw_data if n.get("state") == "online")
        offline = total - online
        clients = sum(n.get("client_counts", 0) for n in self.raw_data)
        tunnels = sum(n.get("tunnel_counts", 0) for n in self.raw_data)

        self.label_total.setText(f"总节点: {total}")
        self.label_online.setText(f"在线节点: {online}")
        self.label_offline.setText(f"离线节点: {offline}")
        self.label_clients.setText(f"客户端: {clients}")
        self.label_tunnels.setText(f"隧道: {tunnels}")

    def handleData(self, data):
        if isinstance(data, dict) and "data" in data:
            node_info = {node["id"]: node for node in data["data"]}
            if not self.raw_data:
                self.raw_data = list(data["data"])
            else:
                for node in self.raw_data:
                    node_id = node.get("id")
                    if node_id in node_info:
                        original_state = node.get("state")
                        original_client_counts = node.get("client_counts")
                        original_tunnel_counts = node.get("tunnel_counts")
                        original_cpu_usage = node.get("cpu_usage")
                        original_bandwidth_usage = node.get("bandwidth_usage_percent")
                        original_traffic_in = node.get("total_traffic_in")
                        original_traffic_out = node.get("total_traffic_out")
                        info = node_info[node_id]
                        node.update(info)
                        if "state" not in info and original_state:
                            node["state"] = original_state
                        if "client_counts" not in info and original_client_counts:
                            node["client_counts"] = original_client_counts
                        if "tunnel_counts" not in info and original_tunnel_counts:
                            node["tunnel_counts"] = original_tunnel_counts
                        if "cpu_usage" not in info and original_cpu_usage:
                            node["cpu_usage"] = original_cpu_usage
                        if "bandwidth_usage_percent" not in info and original_bandwidth_usage:
                            node["bandwidth_usage_percent"] = original_bandwidth_usage
                        if "total_traffic_in" not in info and original_traffic_in:
                            node["total_traffic_in"] = original_traffic_in
                        if "total_traffic_out" not in info and original_traffic_out:
                            node["total_traffic_out"] = original_traffic_out
        else:
            if self.raw_data and isinstance(data, list):
                existing_nodes = {node.get("id"): {
                    "name": node.get("name"),
                    "nodegroup": node.get("nodegroup"),
                    "china": node.get("china"),
                    "web": node.get("web"),
                    "udp": node.get("udp")
                } for node in self.raw_data if node.get("id")}
                for node in data:
                    node_id = node.get("id")
                    if node_id in existing_nodes:
                        for attr, value in existing_nodes[node_id].items():
                            if value is not None and attr not in node:
                                node[attr] = value

            self.raw_data = data

        self.updateStatistics()
        self.updateDisplay()

        if hasattr(self, "loaderThread"):
            self.sender().deleteLater()
            del self.loaderThread

    def applyFilter(self, index):
        """应用筛选条件"""
        filters = ["all", "online", "offline", "low_usage"]
        self.current_filter = filters[index]
        self.updateDisplay()

    def refreshData(self):
        """触发数据刷新"""
        if hasattr(self, "loaderThread"):
            return

        self.loaderThread = DataLoaderThread()
        self.loaderThread.dataLoaded.connect(self.handleData)
        self.loaderThread.start()

        self.nodeInfoThread = NodeInfoThread()
        self.nodeInfoThread.dataLoaded.connect(self.handleData)
        self.nodeInfoThread.start()

        self.apiServerThread = ApiServerStatusThread()
        self.apiServerThread.dataLoaded.connect(self.handleApiServerData)
        self.apiServerThread.start()

    def handleApiServerData(self, data):
        """处理API服务器数据"""
        self.api_server_data = data
        self.updateDisplay()

        if hasattr(self, "apiServerThread"):
            self.sender().deleteLater()
            del self.apiServerThread

    def createApiServerCard(self, data):
        """创建API服务器卡片"""
        try:
            cpu = data.get("metrics", {}).get("cpu", 0)
            memory = data.get("metrics", {}).get("memory", 0)
            steal = data.get("metrics", {}).get("steal", 0)
            io_latency = data.get("metrics", {}).get("ioLatency", 0)
            thread_contention = data.get("metrics", {}).get("threadContention", 0)
            server_name = data.get("serverName", "API服务器")
            load = data.get("load", 0)

            content = (
                f"cpu占用: {cpu:.2f} | 内存: {memory:.1f}% | IO延迟: {io_latency:.2f}\n"
                f"线程争用: {thread_contention:.2f} | 宿主机抢占资源: {steal:.2f}%"
            )

            card = AppCard(
                icon=":/images/server.png",
                title=f"{server_name} (API服务器)",
                content=content,
                cpu=int(cpu),
                bandwidth=int(memory),
                parent=self
            )
            card.cpuLabel.setText(f"{load:.1f}%\n总负载")
            card.bwLabel.setText(f"{memory:.1f}%\n内存")
            api_badge = InfoBadge.custom("API", "#9C27B0", "#F3E5F5", parent=card)
            api_badge.move(card.width() - 60, 10)
            api_badge.setProperty("badge_index", 0)
            api_badge.setVisible(True)

            return card
        except Exception as e:
            logging.error(f"创建API服务器卡片失败: {e}")
            return None

    def updateDisplay(self):
        """更新界面显示"""
        while self.scrollLayout.count():
            item = self.scrollLayout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        if self.api_server_data:
            api_card = self.createApiServerCard(self.api_server_data)
            self.scrollLayout.addWidget(api_card)
        filtered_data = []
        for node in self.raw_data:
            if self.current_filter == "online" and node["state"] != "online":
                continue
            if self.current_filter == "offline" and node["state"] != "offline":
                continue
            if self.current_filter == "low_usage":
                cpu = node["cpu_usage"]
                bw = node["bandwidth_usage_percent"]
                if cpu >= 20 or bw >= 20:
                    continue
            if not self.filter_vip and node.get("nodegroup") == "vip":
                continue
            if not self.filter_udp and node.get("udp") == "true":
                continue
            if not self.filter_web and node.get("web") == "yes":
                continue
            if not self.filter_foreign and node.get("china") == "no":
                continue

            filtered_data.append(node)

        for node in filtered_data:
            card = self.createCard(node)
            self.scrollLayout.addWidget(card)

        self.scrollLayout.addStretch()

    def createCard(self, node):
        """创建节点卡片"""
        cpu = int(round(node.get("cpu_usage", 0)))
        bandwidth = node.get("bandwidth_usage_percent", 0)

        state = "在线" if node.get("state") == "online" else "离线"
        content = (
            f"状态: {state} | 客户端: {node.get('client_counts', 0)} "
            f"| 隧道: {node.get('tunnel_counts', 0)}\n"
            f"上传: {self.format_traffic(node.get('total_traffic_out', 0))} "
            f"| 下载: {self.format_traffic(node.get('total_traffic_in', 0))}"
        )
        node_name = node.get("name", node.get("node_name", "未命名节点"))

        card = AppCard(
            icon=":/images/server.png",
            title=node_name,
            content=content,
            cpu=cpu,
            bandwidth=bandwidth,
            parent=self
        )

        card.node_id = node.get("id")
        card.node_name = node_name
        card.moreButton.clicked.connect(lambda: self.showCardMenu(card))
        badges = []

        if node.get("nodegroup") == "vip":
            vip_badge = InfoBadge.custom("VIP", "#FF9800", "#FFF3E0", parent=card)
            badges.append(vip_badge)

        if str(node.get("udp")).lower() == "true":
            udp_badge = InfoBadge.info("UDP", parent=card)
            badges.append(udp_badge)

        if str(node.get("web")).lower() == "yes":
            web_badge = InfoBadge.success("Web", parent=card)
            badges.append(web_badge)

        if str(node.get("china")).lower() == "no":
            foreign_badge = InfoBadge.attension("非大陆", parent=card)
            badges.append(foreign_badge)

        if str(node.get("state")).lower() == "offline":
            foreign_badge = InfoBadge.custom("离线", "#DC143C", "#FFF3E0", parent=card)
            badges.append(foreign_badge)

        if cpu > 50 or bandwidth > 80:
            foreign_badge = InfoBadge.custom("高负载", "#b8146f", "#FFF3E0", parent=card)
            badges.append(foreign_badge)

        badge_width = 50
        spacing = 5
        right_margin = 10

        for i, badge in enumerate(badges):
            badge.move(card.width() - right_margin - (i + 1) * (badge_width + spacing), 10)
            badge.setProperty("badge_index", i)
            badge.setVisible(True)

        return card

    def showCardMenu(self, card):
        """显示节点卡片右键菜单"""
        menu = RoundMenu(parent=self)
        viewUptimeAction = Action(FluentIcon.HISTORY, '查看在线率')
        viewUptimeAction.triggered.connect(lambda: self.viewNodeUptime(card.node_name))
        menu.addAction(viewUptimeAction)

        viewDetailsAction = Action(FluentIcon.INFO, '查看节点详情')
        viewDetailsAction.triggered.connect(lambda: self.viewNodeDetails(card.node_name))
        menu.addAction(viewDetailsAction)

        menu.exec(QCursor.pos())

    def viewNodeDetails(self, node_name):
        user_token = token_manager.get_token()
        if not user_token:
            InfoBar.warning(
                title='未登录',
                content="请先登录以查看节点详情。",
                parent=self
            )
            return

        infoBar = InfoBar(
            icon=InfoBarIcon.INFORMATION,
            title='正在加载',
            content="正在获取节点详情...",
            orient=Qt.Orientation.Horizontal,
            isClosable=False,
            parent=self
        )
        infoBar.show()

        class NodeDetailsLoaderThread(QThread):
            dataLoaded = pyqtSignal(dict)

            def __init__(self, token, node_name):
                super().__init__()
                self.token = token
                self.node_name = node_name

            def run(self):
                try:
                    url = f"http://cf-v2.uapis.cn/nodeinfo?token={self.token}&node={self.node_name}"
                    response = requests.get(url, timeout=10)
                    if response.status_code == 200:
                        data = response.json()
                        self.dataLoaded.emit(data)
                    else:
                        self.dataLoaded.emit({"code": response.status_code, "msg": "请求失败"})
                except Exception as e:
                    self.dataLoaded.emit({"code": 500, "msg": f"获取节点详情失败: {str(e)}"})

        self.detailsThread = NodeDetailsLoaderThread(user_token, node_name)
        self.detailsThread.dataLoaded.connect(lambda data: self.showNodeDetails(data, infoBar))
        self.detailsThread.start()

    def showNodeDetails(self, data, infoBar=None):
        if infoBar:
            infoBar.close()

        if data.get("code") != 200:
            InfoBar.error(
                title='获取失败',
                content=data.get("msg", "未知错误"),
                parent=self
            )
            return

        node_data = data.get("data", {})
        if not node_data:
            InfoBar.warning(
                title='无数据',
                content="没有找到该节点的详细数据。",
                parent=self
            )
            return

        dialog = MessageBox(
            f"节点详情 - {node_data.get('name', '未知')}",
            "",
            self
        )
        dialog.cancelButton.hide()
        dialog.buttonLayout.insertStretch(1)
        dialog.yesButton.setText("关闭")

        if node_data.get('state') == "online":
            state = "在线"
        else:
            state = "离线 or 维护中"

        details = (
            f"名称: {node_data.get('name', '未知')}\n"
            f"状态: {state}\n"
            f"区域: {node_data.get('area', '未知')}\n"
            f"CPU信息: {node_data.get('cpu_info', '未知')}\n"
            f"内存总量: {node_data.get('memory_total', 0) / (1024 ** 3):.2f} GB\n"
            f"存储总量: {node_data.get('storage_total', 0) / (1024 ** 3):.2f} GB\n"
            f"带宽使用: {node_data.get('bandwidth_usage_percent', 0)}%\n"
            f"总流量上传: {self.format_traffic(node_data.get('total_traffic_out', 0))}\n"
            f"总流量下载: {self.format_traffic(node_data.get('total_traffic_in', 0))}\n"
            f"备注: {node_data.get('notes', '无')}"
        )

        contentWidget = QWidget()
        contentLayout = QVBoxLayout(contentWidget)
        contentLayout.addWidget(QLabel(details))
        contentLayout.setContentsMargins(0, 0, 0, 0)

        dialog.contentLabel.hide()
        dialog.textLayout.addWidget(contentWidget)
        dialog.exec()

    def viewNodeUptime(self, node_name):
        infoBar = InfoBar(
            icon=InfoBarIcon.INFORMATION,
            title='正在加载',
            content=f"正在获取 {node_name} 的在线率数据...",
            orient=Qt.Orientation.Horizontal,
            isClosable=False,
            parent=self
        )
        infoBar.show()

        class UptimeLoaderThread(QThread):
            dataLoaded = pyqtSignal(dict)

            def __init__(self, node_name):
                super().__init__()
                self.node_name = node_name

            def run(self):
                try:
                    url = f"https://cf-v2.uapis.cn/node_uptime?time=90&node={self.node_name}"
                    response = requests.get(url, timeout=10)
                    if response.status_code == 200:
                        data = response.json()
                        self.dataLoaded.emit(data)
                    else:
                        self.dataLoaded.emit({"code": response.status_code, "msg": "请求失败"})
                except Exception as e:
                    self.dataLoaded.emit({"code": 500, "msg": f"获取节点在线率失败: {str(e)}"})

        self.uptimeThread = UptimeLoaderThread(node_name)
        self.uptimeThread.dataLoaded.connect(lambda data: self.showUptimeData(data, infoBar))
        self.uptimeThread.start()

    def showUptimeData(self, data, infoBar=None):
        if infoBar:
            infoBar.close()
        if data.get("code") != 200:
            InfoBar.error(
                title='获取失败',
                content=data.get("msg", "未知错误"),
                parent=self
            )
            return

        node_data = data.get("data", [])
        if not node_data:
            InfoBar.warning(
                title='无数据',
                content="没有找到该节点的在线率数据",
                parent=self
            )
            return

        node_info = node_data[0]
        history = node_info.get("history_uptime", [])

        if not history:
            InfoBar.information(
                title='无历史数据',
                content=f"节点 {node_info.get('node_name')} 暂无历史在线率数据",
                parent=self
            )
            return

        parent_window = self
        while parent_window.parent():
            parent_window = parent_window.parent()

        dialog = MessageBox(
            f"{node_info.get('node_name')} 在线率",
            "",
            self
        )

        dialog.cancelButton.hide()
        dialog.buttonLayout.insertStretch(1)
        dialog.yesButton.setText("关闭")

        dialog.resize(wide, high)

        contentWidget = QWidget()
        contentLayout = QVBoxLayout(contentWidget)
        contentLayout.setContentsMargins(0, 0, 0, 0)

        chart = QChart()
        chart.setTitle(f"{node_info.get('node_name')} 最近90天在线率")
        chart.setAnimationOptions(QChart.AnimationOption.SeriesAnimations)

        series = QLineSeries()
        series.setName("在线率 (%)")

        end_date = datetime.now()
        start_date = end_date - timedelta(days=89)  # 90天

        uptime_map = {}
        for point in history:
            date_str = point.get("recorded_at")
            uptime = point.get("uptime", 0)
            try:
                date_obj = datetime.strptime(date_str, "%Y-%m-%d")
                uptime_map[date_obj.strftime("%Y-%m-%d")] = uptime
            except:
                continue

        current_date = start_date
        for i in range(90):
            date_str = current_date.strftime("%Y-%m-%d")
            uptime = uptime_map.get(date_str, 0)

            date_qt = QDateTime.fromString(date_str, "yyyy-MM-dd")
            series.append(date_qt.toMSecsSinceEpoch(), uptime)

            current_date += timedelta(days=1)

        chart.addSeries(series)

        # X轴（日期）
        axisX = QDateTimeAxis()
        axisX.setFormat("MM-dd")
        axisX.setTitleText("日期")
        chart.addAxis(axisX, Qt.AlignmentFlag.AlignBottom)
        series.attachAxis(axisX)

        # Y轴（在线率）
        axisY = QValueAxis()
        axisY.setRange(0, 101)
        axisY.setTitleText("在线率 (%)")
        chart.addAxis(axisY, Qt.AlignmentFlag.AlignLeft)
        series.attachAxis(axisY)

        chartView = QChartView(chart)
        chartView.setRenderHint(QPainter.RenderHint.Antialiasing)
        chartView.setMinimumHeight(300)
        chartView.setMinimumWidth(400)

        contentLayout.addWidget(chartView)

        if history:
            avg_uptime = sum(point.get("uptime", 0) for point in history) / len(history)
        else:
            avg_uptime = 0

        if avg_uptime == 100:
            tip_text = "哇！这个节点真不错awa"
            tip_color = "#27ae60"
        elif avg_uptime >= 95:
            tip_text = "还不错哈！"
            tip_color = "#2ecc71"
        elif avg_uptime >= 90:
            tip_text = "这个节点还好abab"
            tip_color = "#f39c12"
        elif avg_uptime >= 85:
            tip_text = "有点不稳定哈"
            tip_color = "#e67e22"
        else:
            tip_text = "这边建议，不要用啊啊啊！"
            tip_color = "#e74c3c"

        avgLabel = SubtitleLabel(f"平均在线率: {avg_uptime:.2f}% - {tip_text}")
        avgLabel.setAlignment(Qt.AlignmentFlag.AlignCenter)
        avgLabel.setStyleSheet(f"color: {tip_color}; font-weight: bold;")
        contentLayout.addWidget(avgLabel)

        dialog.contentLabel.hide()
        dialog.textLayout.addWidget(contentWidget)
        dialog.exec()

    def format_traffic(self, bytes):
        if bytes < 1024 ** 3:
            return f"{bytes / 1024 ** 2:.1f} MB"
        return f"{bytes / 1024 ** 3:.1f} GB"

class NodeInfoThread(QThread):
    """节点信息加载"""
    dataLoaded = pyqtSignal(dict)

    def run(self):
        try:
            url = "https://cf-v2.uapis.cn/node"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                self.dataLoaded.emit(data)
            else:
                logging.error(f"api访问失败")
        except Exception as e:
            logging.error(f"获取节点信息失败: {e}")

class AppCard(CardWidget):
    def __init__(self, icon, title, content, cpu=0, bandwidth=0, parent=None):
        super().__init__(parent)
        self.iconContainer = QWidget(self)
        self.iconContainer.setFixedSize(96, 48)

        # CPU进度环
        self.cpuRing = ProgressRing(self.iconContainer)
        self.cpuRing.setFixedSize(48, 48)
        self.cpuRing.setValue(cpu)
        self.cpuLabel = QLabel(f"{cpu}%\nCPU", self.iconContainer)
        self.cpuLabel.setGeometry(0, 0, 48, 48)
        self.cpuLabel.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.cpuLabel.setStyleSheet("""
                    color: #e74c3c;
                    font-size: 10px;
                    line-height: 1.2;
                """)
        self.cpuLabel.setWordWrap(True)

        # 带宽进度环
        self.bwRing = ProgressRing(self.iconContainer)
        self.bwRing.setFixedSize(48, 48)
        self.bwRing.move(48, 0)
        self.bwRing.setValue(bandwidth)
        self.bwLabel = QLabel(f"{bandwidth}%\n带宽", self.iconContainer)
        self.bwLabel.setGeometry(48, 0, 48, 48)
        self.bwLabel.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.bwLabel.setStyleSheet("""
                    color: #3498db;
                    font-size: 10px;
                    line-height: 1.2;
                """)
        self.bwLabel.setWordWrap(True)

        self.titleLabel = BodyLabel(title, self)
        self.contentLabel = CaptionLabel(content, self)
        self.moreButton = TransparentToolButton(FluentIcon.MORE, self)
        self.hBoxLayout = QHBoxLayout(self)
        self.vBoxLayout = QVBoxLayout()

        self.setFixedHeight(85)
        self.contentLabel.setTextColor("#606060", "#d2d2d2")

        self.hBoxLayout.setContentsMargins(20, 11, 11, 11)
        self.hBoxLayout.setSpacing(15)
        self.hBoxLayout.addWidget(self.iconContainer)

        self.vBoxLayout.setContentsMargins(0, 0, 0, 0)
        self.vBoxLayout.setSpacing(2)
        self.vBoxLayout.addWidget(self.titleLabel)
        self.vBoxLayout.addWidget(self.contentLabel)
        self.hBoxLayout.addLayout(self.vBoxLayout)

        self.hBoxLayout.addStretch(1)
        self.hBoxLayout.addWidget(self.moreButton, 0, Qt.AlignmentFlag.AlignCenter)
        self.moreButton.setFixedSize(32, 32)

        self.node_id = None
        self.node_name = None

    def resizeEvent(self, event):
        super().resizeEvent(event)
        badges = [child for child in self.children() if isinstance(child, InfoBadge)]

        badges.sort(key=lambda badge: badge.property("badge_index") or 0)

        badge_width = 50
        spacing = 5
        right_margin = 10

        for i, badge in enumerate(badges):
            badge.move(self.width() - right_margin - (i + 1) * (badge_width + spacing), 10)

class DataLoaderThread(QThread):
    """node_stats数据"""
    dataLoaded = pyqtSignal(list)

    def run(self):
        try:
            response = requests.get("https://cf-v2.uapis.cn/node_stats", timeout=15)
            if response.status_code == 200:
                data = response.json().get("data", [])
                self.dataLoaded.emit(data)
            else:
                logging.error(f"api访问失败")
        except Exception as e:
            logging.error(f"node_stats数据加载失败: {e}")
        finally:
            self.quit()

class NodeDetailThread(QThread):
    """节点详细信息获取线程"""
    nodeDetailLoaded = pyqtSignal(dict)
    loadError = pyqtSignal(str)

    def __init__(self, token, node_name):
        super().__init__()
        self.token = token
        self.node_name = node_name

    def run(self):
        try:
            url = f"http://cf-v2.uapis.cn/nodeinfo?token={self.token}&node={self.node_name}"
            response = requests.get(url, timeout=10)

            if response.status_code == 200:
                data = response.json()
                if data.get("code") == 200:
                    self.nodeDetailLoaded.emit(data.get("data", {}))
                else:
                    self.loadError.emit(data.get("msg", "获取节点详情失败"))
            else:
                self.loadError.emit(f"HTTP错误: {response.status_code}")
        except Exception as e:
            self.loadError.emit(f"网络错误: {str(e)}")

class MainWindow(FluentWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"CUL-v{APP_VERSION}")
        self.setFixedSize(wide, high)
        self.setWindowIcon(QIcon('favicon.ico'))
        self.file_checker = FileChecker(self)

        self.homePage: QWidget = HomePage(self)
        self.settingsPage: QWidget = SettingsPage(self)
        self.aboutPage: QWidget = AboutPage(self)
        self.tunnelManagementPage: QWidget = TunnelManagementPage(self)
        self.domainManagementPage: QWidget = DomainManagementPage(self)
        self.nodeStatusPage: QWidget = NodeStatusPage(self)

        self.initNavigation()
        self.switchTo(self.homePage)

        QTimer.singleShot(1000, self.check_required_files)

    def check_required_files(self):
        """检查必需文件"""
        def on_check_complete(success, message):
            if success:
                logging.info("文件检查完成，程序已就绪")
            else:
                logging.warning(f"文件检查未完成: {message}")
        self.file_checker.check_and_download_files(on_check_complete)

    def get_frpc_path(self):
        """获取frpc.exe路径的统一方法"""
        return self.file_checker.get_frpc_path()

    def is_frpc_available(self):
        """检查frpc是否可用的统一方法"""
        return self.file_checker.is_frpc_available()

    def initNavigation(self):
        """初始化导航栏"""
        self.addSubInterface(self.homePage, FluentIcon.HOME, "主页")
        self.addSubInterface(self.tunnelManagementPage, FluentIcon.CALENDAR, "隧道管理")
        self.addSubInterface(self.domainManagementPage, FluentIcon.GLOBE, "域名管理")
        self.addSubInterface(self.nodeStatusPage, FluentIcon.CHECKBOX, "节点状态")
        self.addSubInterface(self.settingsPage, FluentIcon.SETTING, "设置")
        self.addSubInterface(self.aboutPage, FluentIcon.INFO, "关于")

if __name__ == "__main__":
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )
    setup_logging()
    logging.info("应用程序启动")
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
# CHMLFRP_UI_2025_07_10
# python -m nuitka --standalone --python-flag=-O --include-data-files=./favicon.ico=./favicon.ico --include-data-files=./frpc.exe=./frpc.exe --include-package=PyQt6 --include-package-data=PyQt6 --include-qt-plugins=styles,platforms,qml --plugin-enable=pyqt6 --follow-import-to=PyQt6,PyQt6.QtCore,PyQt6.QtGui,PyQt6.QtWidgets,ipaddress,requests --remove-output --windows-console-mode=disable --assume-yes-for-downloads --output-dir=./build_output --nofollow-import-to=psutil.tests,psutil.tests.test_testutils,dns.tests --windows-icon-from-ico=./favicon.ico CUL.py