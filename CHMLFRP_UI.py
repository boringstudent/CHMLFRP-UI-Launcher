import ipaddress
import json
import logging
import os
import random
import re
import socket
import subprocess
import sys
import threading
import time
import traceback
import urllib
import winreg
import zipfile
from datetime import datetime
from logging.handlers import *
import glob

import psutil
import pyperclip
import requests
import win32api
import win32con
import win32security
import ctypes
import markdown
import tempfile
from PyQt6.QtCore import *
from PyQt6.QtGui import *
from PyQt6.QtWidgets import *
from PyQt6.QtNetwork import *
from dns.resolver import Resolver, NoNameservers, NXDOMAIN, NoAnswer, Timeout
import urllib3
urllib3.disable_warnings()

# ------------------------------以下为程序信息--------------------
# 程序信息
APP_NAME = "CUL" # 程序名称
APP_VERSION = "1.5.9" # 程序版本
PY_VERSION = "3.13.2" # Python 版本
WINDOWS_VERSION = "Windows NT 10.0" # 系统版本
Number_of_tunnels = 0 # 隧道数量
PSEXEC_PATH = "PsExec.exe" if os.path.exists("PsExec.exe") else "PsExec"
PSTOOLS_URL = "https://download.sysinternals.com/files/PSTools.zip"
PSEXEC_EXE = "PsExec.exe"

# 更新全局配置

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

def get_absolute_path(relative_path):
    """获取相对于程序目录的绝对路径"""
    return os.path.abspath(os.path.join(os.path.split(sys.argv[0])[0], relative_path))

def check_file_empty(filename):
    """检查文件是否为空"""
    file_path = get_absolute_path(filename)

    if not os.path.exists(file_path):
        return True, "文件不存在"

    try:
        return os.path.getsize(file_path) == 0, "文件为空" if os.path.getsize(file_path) == 0 else "文件不为空"
    except OSError as e:
        return True, f"读取文件出错: {str(e)}"

# 从配置文件加载日志设置
try:
    settings_path = get_absolute_path("settings.json")
    if os.path.exists(settings_path):
        with open(settings_path, 'r') as f:
            settings = json.load(f)
            maxBytes = settings.get('log_size_mb', 10) * 1024 * 1024  # 默认10MB
            backupCount = settings.get('backup_count', 30)  # 默认30个备份
    else:
        maxBytes = 10 * 1024 * 1024  # 默认10MB
        backupCount = 30  # 默认30个备份
except Exception as e:
    print(f"加载日志设置失败: {str(e)}")
    maxBytes = 10 * 1024 * 1024  # 默认10MB
    backupCount = 30  # 默认30个备份

# 生成统一的 User-Agent
USER_AGENT = f"{APP_NAME}/{APP_VERSION} (Python/{PY_VERSION}; {WINDOWS_VERSION})"

# 生成统一的请求头
def get_headers(request_json=False):
    """
    获取统一的请求头
    Args:
        request_json: 是否添加 Content-Type: application/json
    Returns:
        dict: 请求头字典
    """
    headers = {'User-Agent': USER_AGENT}
    if request_json:
        headers['Content-Type'] = 'application/json'
    return headers

# 设置全局日志
logger = logging.getLogger('CHMLFRP_UI')
logger.setLevel(logging.DEBUG)
file_handler = RotatingFileHandler('CHMLFRP_UI.log', maxBytes=maxBytes, backupCount=backupCount)
file_handler.setLevel(logging.DEBUG)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
console_handler.setFormatter(formatter)
logger.addHandler(file_handler)
logger.addHandler(console_handler)

class ProgramUpdates:
    @classmethod
    def check_update(cls, current_version):
        """检测更新，返回最新版本、更新内容和所有镜像下载链接"""
        try:
            # 1. DNS解析和IP测试
            resolver = Resolver()
            resolver.nameservers = DNS_CONFIG["servers"]
            resolver.lifetime = DNS_CONFIG["timeout"]

            try:
                ips = [str(r) for r in resolver.resolve(DNS_CONFIG["domain"], 'A')]
            except (NoNameservers, NXDOMAIN, NoAnswer, Timeout):
                print("DNS解析失败，使用域名直连")
                endpoint = DNS_CONFIG["domain"]
            else:
                endpoint = DNS_CONFIG["domain"]  # 默认回退域名
                for ip in ips:
                    try:
                        sock = socket.create_connection((ip, 443), timeout=5)
                        sock.close()
                        endpoint = ip
                        break
                    except:
                        continue

            # 2. 构建请求
            headers = {"Host": DNS_CONFIG["domain"]} if re.match(r"\d+\.\d+\.\d+\.\d+", endpoint) else {}
            url = f"https://{endpoint}/repos/boringstudents/CHMLFRP-UI-Launcher/releases/latest"

            # 3. 获取版本信息
            response = requests.get(url, headers=headers, timeout=DNS_CONFIG["timeout"], verify=False)
            response.raise_for_status()
            release_data = response.json()
            latest_version = release_data["tag_name"]
            update_content = release_data.get("body", "无更新内容")
            download_links = []

            # 4. 版本比较
            current = tuple(map(int, re.sub(r"[^0-9.]", "", current_version).split(".")))
            latest = tuple(map(int, re.sub(r"[^0-9.]", "", latest_version).split(".")))

            if latest < current:
                # 本地版本比远程版本新（可能是开发版）
                return current_version, "当前版本比最新发布版本新", []
            elif latest == current:
                # 已经是最新版本
                return current_version, "当前已是最新版本", []

            # 5. 获取所有镜像下载链接
            for asset in release_data.get("assets", []):
                original_url = asset.get("browser_download_url", "")
                if not original_url: continue
                urls = [f"https://{prefix}/{original_url}" for prefix in MIRROR_PREFIXES] + [original_url]
                download_links.extend(urls)

            return latest_version, update_content, download_links

        except Exception as e:
            print(f"更新检测异常: {str(e)}")
            return None, None, None

class Pre_run_operations():
    def __init__(self):
        super().__init__()

    @classmethod
    def _ensure_psexec(cls) -> bool:
        """确保 PsExec.exe 存在，否则自动下载"""
        if os.path.exists(PSEXEC_EXE):
            return True

        print("PsExec 未找到，尝试下载...")
        try:
            # 下载 PSTools.zip
            temp_dir = tempfile.mkdtemp()
            zip_path = os.path.join(temp_dir, "PSTools.zip")
            urllib.request.urlretrieve(PSTOOLS_URL, zip_path)

            # 解压并提取 PsExec.exe
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extract(PSEXEC_EXE, temp_dir)

            # 移动到当前目录
            os.rename(os.path.join(temp_dir, PSEXEC_EXE), PSEXEC_EXE)
            print("PsExec 下载成功！")
            return True
        except Exception as e:
            print(f"下载 PsExec 失败: {e}")
            return False

    @classmethod
    def is_admin(cls) -> bool:
        """检查当前是否以管理员身份运行"""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False

    @classmethod
    def run_as_admin(cls) -> bool:
        """以管理员身份重新运行程序"""
        try:
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, " ".join(sys.argv), None, 1
            )
            sys.exit(0)
            return True
        except Exception as e:
            print(f"管理员提权失败: {e}")
            return False

    @classmethod
    def enable_debug_privilege(cls) -> bool:
        """启用 SeDebugPrivilege 权限"""
        try:
            token = win32security.OpenProcessToken(
                win32api.GetCurrentProcess(),
                win32security.TOKEN_ADJUST_PRIVILEGES | win32security.TOKEN_QUERY
            )
            priv = win32security.LookupPrivilegeValue(None, win32security.SE_DEBUG_NAME)
            win32security.AdjustTokenPrivileges(
                token,
                False,
                [(priv, win32security.SE_PRIVILEGE_ENABLED)]
            )
            return win32api.GetLastError() == 0
        except Exception as e:
            print(f"SeDebugPrivilege 启用失败: {e}")
            return False

    @classmethod
    def run_as_trusted_installer(cls) -> bool:
        """使用 PsExec 以 SYSTEM 权限运行（接近 TrustedInstaller）"""
        if not cls._ensure_psexec():
            return False

        try:
            # -i: 交互式, -s: SYSTEM 权限, -accepteula: 自动接受协议
            cmd = [PSEXEC_EXE, "-i", "-s", "-accepteula", sys.executable] + sys.argv
            subprocess.run(cmd, check=True)
            sys.exit(0)
            return True
        except Exception as e:
            print(f"TrustedInstaller 提权失败: {e}")
            return False

    @classmethod
    def test_registry_access(cls) -> bool:
        """测试是否有注册表写入权限（示例：尝试写入 HKLM）"""
        try:
            key = win32api.RegCreateKey(
                win32con.HKEY_CURRENT_USER,
                "SOFTWARE\\TestKey"
            )

            win32api.RegCloseKey(key)
            win32api.RegDeleteKey(win32con.HKEY_CURRENT_USER, "SOFTWARE\\TestKey")
            return True
        except Exception as e:
            print(f"注册表访问失败: {e}")
            return False

    @classmethod
    def elevation_rights(cls):
        """
        提权逻辑：
        1. 检查是否已有权限修改注册表
        2. 如果没有，尝试启用 SeDebugPrivilege
        3. 如果仍然失败，尝试以 TrustedInstaller 运行（使用 PsExec）
        """
        if cls.test_registry_access():
            print("已有足够权限，无需提权")
            return True

        print("当前权限不足，尝试提权...")

        # 1. 如果不是管理员，先提权到管理员
        if not cls.is_admin():
            print("当前非管理员，尝试提权...")
            return cls.run_as_admin()

        # 2. 尝试启用 SeDebugPrivilege
        if cls.enable_debug_privilege():
            print("SeDebugPrivilege 启用成功，再次尝试...")
            if cls.test_registry_access():
                return True

        # 3. 如果仍然失败，使用 PsExec 以 TrustedInstaller 运行
        print("SeDebugPrivilege 仍不足，尝试 TrustedInstaller...")
        return cls.run_as_trusted_installer()

    @classmethod
    def document_checking(cls):
        # 默认设置
        default_settings = {
            "auto_start_tunnels": [],
            "theme": "system",
            "log_size_mb": 10,
            "backup_count": 30
        }

        # 检查并创建settings.json
        is_empty, _ = check_file_empty("settings.json")
        if is_empty:
            settings_path = get_absolute_path("settings.json")
            with open(settings_path, 'w', encoding='utf-8') as f:
                json.dump(default_settings, f, indent=4, ensure_ascii=False)

    @classmethod
    def document_checking(cls):
        """文档检查与数据迁移"""
        # 迁移旧的凭证文件到注册表
        credentials_path = get_absolute_path("credentials.json")
        if os.path.exists(credentials_path):
            try:
                with open(credentials_path, 'r') as f:
                    credentials = json.load(f)

                # 尝试写入注册表
                key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"SOFTWARE\ChmlFrp")
                winreg.SetValueEx(key, "username", 0, winreg.REG_SZ, credentials.get('username', ''))
                winreg.SetValueEx(key, "password", 0, winreg.REG_SZ, credentials.get('password', ''))
                winreg.SetValueEx(key, "token", 0, winreg.REG_SZ, credentials.get('token', ''))
                winreg.CloseKey(key)

                # 删除旧文件
                os.remove(credentials_path)
                logger.info("已迁移旧凭证文件到注册表")
            except PermissionError:
                logger.error("迁移凭证需要管理员权限！")
            except Exception as e:
                logger.error(f"迁移凭证文件失败: {str(e)}")

class enter_inspector():
    def __init__(self):
        super().__init__()

    @staticmethod
    def validate_port(port,tyen):
        """端口检查"""
        try:
            port_num = int(port)
            if tyen == True:
                return 0 < port_num <= 65535
            elif tyen == False:
                return 10000 < port_num <= 65535
        except ValueError:
            return False

    @staticmethod
    def remove_http_https(url):
        """htpp头去除"""
        return re.sub(r'^https?://', '', url)

    @staticmethod
    def parse_srv_target(target):
        """srv解析操作"""
        parts = target.split()
        if len(parts) == 4:
            return parts[0], parts[1], parts[2], parts[3]
        return None, None, None, target

    @staticmethod
    def is_valid_ipv6(ip):
        """IPV6检测"""
        try:
            ipaddress.IPv6Address(ip)
            return True
        except ipaddress.AddressValueError:
            return False

    @staticmethod
    def is_valid_domain(domain):
        """域名检测"""
        pattern = re.compile(
            r'^(?!-)[A-Za-z0-9-\u0080-\uffff]{1,63}(?<!-)(\.[A-Za-z\u0080-\uffff]{2,})+$',
            re.UNICODE
        )
        return bool(pattern.match(domain))

    @staticmethod
    def is_valid_ipv4(ip):
        """IPV4检测"""
        pattern = re.compile(
            r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
        return bool(pattern.match(ip))

class API():
    def __init__(self):
        super().__init__()

    @classmethod
    def login(cls, username, password):
        """用户登录"""
        logger.info(f"尝试登录用户: {username}")
        url = f"https://cf-v2.uapis.cn/login"
        params = {
            "username": username,
            "password": password
        }
        headers = get_headers()
        try:
            response = requests.get(url, headers=headers, params=params)
            response_data = response.json()
            return response_data
        except Exception as content:
            logger.exception("登录API发生错误")
            logger.exception(content)
            return None

    @classmethod
    def get_nodes(cls, max_retries=3, retry_delay=1):
        """获取节点数据"""
        url = "https://cf-v2.uapis.cn/node"
        headers = get_headers()

        for attempt in range(max_retries):
            try:
                response = requests.post(url, headers=headers)
                response.raise_for_status()
                data = response.json()
                if data['code'] == 200:
                    return data['data']
                else:
                    logger.error(f"获取节点数据失败: {data['msg']}")
                    return []
            except requests.RequestException as content:
                logger.warning(f"获取节点数据时发生网络错误 (尝试 {attempt + 1}/{max_retries}): {str(content)}")
                if attempt < max_retries - 1:
                    time.sleep(retry_delay)
                else:
                    logger.error("获取节点数据失败，已达到最大重试次数")
                    return []
            except Exception:
                logger.exception("获取节点数据时发生未知错误")
                return []

    @classmethod
    def is_node_online(cls, node_name=None, tyen=None):
        url = "https://cf-v2.uapis.cn/node_stats"
        headers = get_headers()
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                stats = response.json()

                if tyen == "online":
                    if stats and 'data' in stats:
                        for node in stats['data']:
                            if node['node_name'] == node_name:
                                return node['state'] == "online"
                elif tyen == "all":
                    if node_name is not None:
                        raise ValueError("当tyen为'all'时，不能传入node_name参数")
                    return stats

            return False
        except Exception:
            logger.exception("检查节点在线状态时发生错误")
            return False

    @classmethod
    def get_user_tunnels(cls, user_token):
        """获取用户隧道列表"""
        url = f"https://cf-v2.uapis.cn/tunnel"
        params = {
            "token": user_token
        }
        headers = get_headers()
        try:
            response = requests.get(url, headers=headers, params=params)
            response.raise_for_status()
            data = response.json()
            if data['code'] == 200:
                tunnels = data.get("data", [])
                return tunnels
            else:
                logger.error(f" {data.get('msg')}")
                return []

        except requests.RequestException:
            logger.exception("获取隧道列表时发生网络错误")
            return []
        except Exception:
            logger.exception("获取隧道列表时发生未知错误")
            return []

    @classmethod
    def userinfo(cls,user_token):
        """用户信息"""
        url = f"https://cf-v2.uapis.cn/userinfo"
        headers = get_headers()
        params = {
            "token": user_token
        }
        try:
            data = requests.get(url, params=params, headers=headers).json()
            return data
        except Exception as content:
            logger.exception("用户信息API发生错误")
            logger.exception(content)
            return None

class QtHandler(QObject, logging.Handler):
    """Qt日志处理器"""
    new_record = pyqtSignal(str)

    def __init__(self, parent):
        super(QtHandler, self).__init__(parent)  # 只调用一次 super()
        qt_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        self.setFormatter(qt_formatter)

    def emit(self, record):
        msg = self.format(record)
        self.new_record.emit(msg)

class TunnelCard(QFrame):
    clicked = pyqtSignal(object, bool)
    start_stop_signal = pyqtSignal(object, bool)

    def __init__(self, tunnel_info, user_token):
        super().__init__()
        self.start_stop_button = None
        self.link_label = None
        self.status_label = None
        self.tunnel_info = tunnel_info
        self.token = user_token
        self.node_domain = None
        self.is_running = False
        self.is_selected = False
        self.initUI()
        self.updateStyle()
        self.fetch_node_info()

    def initUI(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(10, 10, 10, 10)

        name_label = QLabel(f"<b>{self.tunnel_info.get('name', 'Unknown')}</b>")
        name_label.setObjectName("nameLabel")
        type_label = QLabel(f"类型: {self.tunnel_info.get('type', 'Unknown')}")
        local_label = QLabel(
            f"本地: {self.tunnel_info.get('localip', 'Unknown')}:{self.tunnel_info.get('nport', 'Unknown')}")

        # 根据隧道类型显示不同的远程连接信息
        tunnel_type = self.tunnel_info.get('type', '').lower()
        if tunnel_type == 'http':
            remote_label = QLabel("远程端口: 80")
        elif tunnel_type == 'https':
            remote_label = QLabel("远程端口: 443")
        else:
            remote_label = QLabel(f"远程端口: {self.tunnel_info.get('dorp', 'Unknown')}")

        node_label = QLabel(f"节点: {self.tunnel_info.get('node', 'Unknown')}")
        self.status_label = QLabel("状态: 未启动")
        self.link_label = QLabel(f"连接: {self.get_link()}")
        self.link_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.link_label.setCursor(Qt.CursorShape.PointingHandCursor)
        self.link_label.mousePressEvent = self.copy_link

        self.start_stop_button = QPushButton("启动")
        self.start_stop_button.clicked.connect(self.toggle_start_stop)

        layout.addWidget(name_label)
        layout.addWidget(type_label)
        layout.addWidget(local_label)
        layout.addWidget(remote_label)
        layout.addWidget(node_label)
        layout.addWidget(self.status_label)
        layout.addWidget(self.link_label)
        layout.addWidget(self.start_stop_button)

        self.setLayout(layout)
        self.setFixedSize(250, 250)

    def fetch_node_info(self):
        node = self.tunnel_info.get('node', '')
        url = f"http://cf-v2.uapis.cn/nodeinfo"
        params = {
            'token': self.token,
            'node': node
        }
        headers = get_headers()
        try:
            response = requests.get(url, headers=headers, params=params)
            data = response.json()
            if data['code'] == 200:
                self.node_domain = data['data']['ip']
                self.update_link_label()
        except Exception as content:
            print(f"获取节点信息时出错: {content}")

    def get_link(self):
        tunnel_type = self.tunnel_info.get('type', '').lower()
        if tunnel_type in ['http', 'https']:
            if self.tunnel_info.get('dorp', ''):
                return self.tunnel_info.get('dorp', '')
            return "未绑定域名"
        else:
            # 对于其他类型的隧道，显示节点和端口
            domain = self.node_domain or self.tunnel_info.get('node', '')
            port = self.tunnel_info.get('dorp', '')
            return f"{domain}:{port}"

    def update_link_label(self):
        if hasattr(self, 'link_label'):
            self.link_label.setText(f"连接: {self.get_link()}")

    def copy_link(self, event):
        link = self.get_link()
        pyperclip.copy(link)
        QToolTip.showText(event.globalPosition().toPoint(), "链接已复制!", self)

    def toggle_start_stop(self):
        self.is_running = not self.is_running
        self.update_status()
        self.start_stop_signal.emit(self.tunnel_info, self.is_running)

    def update_status(self):
        if self.is_running:
            self.status_label.setText("状态: 运行中")
            self.start_stop_button.setText("停止")
        else:
            self.status_label.setText("状态: 未启动")
            self.start_stop_button.setText("启动")
        self.update()

    def paintEvent(self, event):
        super().paintEvent(event)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        if self.is_running:
            color = QColor(0, 255, 0)  # 绿色
        else:
            color = QColor(255, 0, 0)  # 红色
        painter.setPen(QPen(color, 2))
        painter.setBrush(color)
        painter.drawEllipse(self.width() - 20, 10, 10, 10)

    def updateStyle(self):
        self.setStyleSheet("""
			TunnelCard {
				border: 1px solid #d0d0d0;
				border-radius: 5px;
				padding: 10px;
				margin: 5px;
			}
			TunnelCard:hover {
				background-color: rgba(240, 240, 240, 50);
			}
			#nameLabel {
				font-size: 16px;
				font-weight: bold;
			}
		""")

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.is_selected = not self.is_selected
            self.setSelected(self.is_selected)
            self.clicked.emit(self.tunnel_info, self.is_selected)
        super().mousePressEvent(event)

    def setSelected(self, selected):
        self.is_selected = selected
        if selected:
            self.setStyleSheet(
                self.styleSheet() + "TunnelCard { border: 2px solid #0066cc; background-color: rgba(224, 224, 224, 50); }")
        else:
            self.setStyleSheet(self.styleSheet().replace(
                "TunnelCard { border: 2px solid #0066cc; background-color: rgba(224, 224, 224, 50); }", ""))

class BatchEditDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("批量编辑隧道")
        self.layout = QVBoxLayout(self)

        self.node_combo = QComboBox()
        self.node_combo.addItem("不修改")
        self.node_combo.addItems([node['name'] for node in API.get_nodes()])

        self.type_combo = QComboBox()
        self.type_combo.addItem("不修改")
        self.type_combo.addItems(["tcp", "udp", "http", "https"])

        self.local_ip_input = QLineEdit()
        self.local_ip_input.setPlaceholderText("不修改")

        self.local_port_input = QLineEdit()
        self.local_port_input.setPlaceholderText("不修改")

        self.remote_port_input = QLineEdit()
        self.remote_port_input.setPlaceholderText("不修改")

        form_layout = QFormLayout()
        form_layout.addRow("节点:", self.node_combo)
        form_layout.addRow("类型:", self.type_combo)
        form_layout.addRow("本地IP/主机名:", self.local_ip_input)
        form_layout.addRow("本地端口:", self.local_port_input)
        form_layout.addRow("远程端口:", self.remote_port_input)

        self.layout.addLayout(form_layout)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        self.layout.addWidget(buttons)

    def get_changes(self):
        changes = {}
        if self.node_combo.currentIndex() != 0:
            changes['node'] = self.node_combo.currentText()
        if self.type_combo.currentIndex() != 0:
            changes['type'] = self.type_combo.currentText()
        if self.local_ip_input.text():
            changes['localip'] = self.local_ip_input.text()
        if self.local_port_input.text():
            changes['nport'] = self.local_port_input.text()
        if self.remote_port_input.text():
            changes['dorp'] = self.remote_port_input.text()
        return changes

class DomainCard(QFrame):
    clicked = pyqtSignal(object)

    def __init__(self, domain_info):
        super().__init__()
        self.link_label = None
        self.domain_info = domain_info
        self.initUI()
        self.updateStyle()

    def initUI(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(10, 10, 10, 10)

        domain_label = QLabel(f"<b>{self.domain_info['record']}.{self.domain_info['domain']}</b>")
        domain_label.setObjectName("nameLabel")
        type_label = QLabel(f"类型: {self.domain_info['type']}")
        target_label = QLabel(f"目标: {self.domain_info['target']}")
        ttl_label = QLabel(f"TTL: {self.domain_info['ttl']}")
        remarks_label = QLabel(f"备注: {self.domain_info.get('remarks', '无')}")

        self.link_label = QLabel(f"链接: {self.get_link()}")
        self.link_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.link_label.setCursor(Qt.CursorShape.PointingHandCursor)
        self.link_label.mousePressEvent = self.copy_link

        layout.addWidget(domain_label)
        layout.addWidget(type_label)
        layout.addWidget(target_label)
        layout.addWidget(ttl_label)
        layout.addWidget(remarks_label)
        layout.addWidget(self.link_label)

        self.setLayout(layout)
        self.setFixedSize(250, 200)

    def get_link(self):
        return f"{self.domain_info['record']}.{self.domain_info['domain']}"

    def copy_link(self, event):
        link = self.get_link()
        pyperclip.copy(link)
        QToolTip.showText(event.globalPosition().toPoint(), "链接已复制!", self)

    def updateStyle(self):
        self.setStyleSheet("""
			DomainCard {
				border: 1px solid #d0d0d0;
				border-radius: 5px;
				padding: 10px;
				margin: 5px;
			}
			DomainCard:hover {
				background-color: rgba(240, 240, 240, 50);
			}
			#nameLabel {
				font-size: 16px;
				font-weight: bold;
			}
		""")

    def setSelected(self, selected):
        if selected:
            self.setStyleSheet(
                self.styleSheet() + "DomainCard { border: 2px solid #0066cc; background-color: rgba(224, 224, 224, 50); }")
        else:
            self.setStyleSheet(self.styleSheet().replace(
                "DomainCard { border: 2px solid #0066cc; background-color: rgba(224, 224, 224, 50); }", ""))

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit(self.domain_info)
        super().mousePressEvent(event)

class StopWorker(QObject):
    finished = pyqtSignal()
    progress = pyqtSignal(str)

    def __init__(self, running_tunnels, tunnel_processes, stop_logger):
        super().__init__()
        self.running_tunnels = running_tunnels
        self.tunnel_processes = tunnel_processes
        self.logger = stop_logger

    def run(self):
        self.progress.emit("开始停止所有隧道...")

        # 停止普通隧道
        for tunnel_name in list(self.tunnel_processes.keys()):
            self.stop_single_tunnel(tunnel_name, is_dynamic=False)

        # 确保所有 frpc.exe 进程都被终止
        self.kill_remaining_frpc_processes()

        self.progress.emit("所有隧道已停止")
        self.finished.emit()

    def stop_single_tunnel(self, tunnel_name, is_dynamic):
        self.progress.emit(f"正在停止隧道: {tunnel_name}")
        if is_dynamic:
            worker = self.running_tunnels.get(tunnel_name)
            if worker:
                worker.requestInterruption()
                if not worker.wait(5000):  # 等待最多5秒
                    worker.terminate()
                    worker.wait(2000)
                del self.running_tunnels[tunnel_name]
        else:
            process = self.tunnel_processes.get(tunnel_name)
            if process:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                del self.tunnel_processes[tunnel_name]

        self.logger.info(f"隧道 '{tunnel_name}' 已停止")

    def kill_remaining_frpc_processes(self):
        self.progress.emit("正在清理残留的 frpc.exe 进程...")
        killed_count = 0

        try:
            # 获取当前目录下的 frpc.exe 完整路径
            frpc_path = get_absolute_path('frpc.exe').replace('\\', '\\\\')  # 转义反斜杠

            ps_command = (
                f'powershell -Command "Get-Process | Where-Object {{ $_.Path -eq \'{frpc_path}\' }} | '
                'Stop-Process -Force"'
            )
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE

            subprocess.Popen(ps_command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             startupinfo=startupinfo)
            killed_count += 1
            self.logger.info("已通过 PowerShell 强制终止 frpc.exe 进程")
        except Exception as content:
            self.logger.error(f"使用 PowerShell 终止 frpc.exe 时发生错误: {str(content)}")

        if killed_count > 0:
            self.progress.emit(f"已终止 {killed_count} 个残留的 frpc.exe 进程")
        else:
            self.progress.emit("没有发现残留的 frpc.exe 进程")

class OutputDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("隧道输出")
        self.setGeometry(100, 100, 700, 500)
        self.layout = QVBoxLayout(self)

        self.output_text_edit = QTextEdit()
        self.output_text_edit.setReadOnly(True)
        self.layout.addWidget(self.output_text_edit)

        # 存储每个隧道的输出历史记录
        self.tunnel_outputs = {}

    def add_output(self, tunnel_name, output, run_number):
        """
        添加或更新隧道输出

        Args:
            tunnel_name: 隧道名称
            output: 输出内容
            run_number: 运行次数
        """
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        separator = f'<hr><b>隧道: {tunnel_name}</b> (启动次数: {run_number}) - <i>{timestamp}</i><br>'

        if tunnel_name in self.tunnel_outputs:
            current_text = self.output_text_edit.toHtml()
            if self.tunnel_outputs[tunnel_name]['run_number'] == run_number:
                # 如果是相同的运行次数，替换对应的输出部分
                start_idx = current_text.find(f'<b>隧道: {tunnel_name}</b> (启动次数: {run_number})')
                if start_idx != -1:
                    # 查找下一个分隔符或文档末尾
                    end_idx = current_text.find('<hr>', start_idx + 1)
                    if end_idx == -1:
                        end_idx = len(current_text)
                    # 替换这部分内容
                    new_text = current_text[:start_idx] + separator + output + current_text[end_idx:]
                    self.output_text_edit.setHtml(new_text)
                else:
                    # 如果找不到对应的输出块（不应该发生），添加到末尾
                    self.output_text_edit.append(separator + output)
            else:
                # 如果是新的运行次数，在开头添加新的输出
                self.output_text_edit.setHtml(separator + output + current_text)
        else:
            # 第一次添加该隧道的输出
            self.output_text_edit.append(separator + output)

        # 更新存储的输出信息
        self.tunnel_outputs[tunnel_name] = {
            'output': output,
            'run_number': run_number
        }

        # 滚动到顶部 以显示最新的输出
        self.output_text_edit.verticalScrollBar().setValue(0)

class SettingsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.tunnel_list = None
        self.backup_count_input = None
        self.log_size_input = None
        self.theme_system = None
        self.theme_dark = None
        self.theme_light = None
        self.autostart_checkbox = None
        self.parent = parent
        self.setWindowTitle("设置")
        self.setFixedWidth(400)
        self.init_ui()
        self.load_settings()
        self.apply_theme(parent.dark_theme)

    def init_ui(self):
        layout = QVBoxLayout(self)

        tab_widget = QTabWidget()
        layout.addWidget(tab_widget)

        # === 常规标签页 ===
        general_tab = QWidget()
        general_layout = QVBoxLayout(general_tab)

        # 自启动选项
        self.autostart_checkbox = QCheckBox("开机自启动")
        self.autostart_checkbox.stateChanged.connect(self.toggle_autostart)
        general_layout.addWidget(self.autostart_checkbox)

        # 主题设置
        theme_group = QGroupBox("主题设置")
        theme_layout = QVBoxLayout()
        self.theme_light = QRadioButton("浅色")
        self.theme_dark = QRadioButton("深色")
        self.theme_system = QRadioButton("跟随系统")
        theme_layout.addWidget(self.theme_light)
        theme_layout.addWidget(self.theme_dark)
        theme_layout.addWidget(self.theme_system)
        theme_group.setLayout(theme_layout)
        general_layout.addWidget(theme_group)

        # 日志设置组
        log_group = QGroupBox("日志设置")
        log_layout = QFormLayout()

        # 日志文件大小设置
        self.log_size_input = QLineEdit()
        self.log_size_input.setValidator(QIntValidator(1, 1000))  # 限制输入为1-1000
        self.log_size_input.setPlaceholderText("1-1000")
        size_layout = QHBoxLayout()
        size_layout.addWidget(self.log_size_input)
        size_layout.addWidget(QLabel("MB"))
        log_layout.addRow("日志文件大小:", size_layout)

        # 日志文件备份数量设置
        self.backup_count_input = QLineEdit()
        self.backup_count_input.setValidator(QIntValidator(1, 100))  # 限制输入为1-100
        self.backup_count_input.setPlaceholderText("1-100")
        log_layout.addRow("日志文件备份数量:", self.backup_count_input)

        # 添加日志设置说明
        log_note = QLabel("注: 更改将在重启程序后生效")
        log_note.setStyleSheet("color: gray; font-size: 10px;")
        log_layout.addRow("", log_note)

        log_group.setLayout(log_layout)
        general_layout.addWidget(log_group)

        general_layout.addStretch()
        tab_widget.addTab(general_tab, "常规")

        # === 隧道标签页 ===
        tunnel_tab = QWidget()
        tunnel_layout = QVBoxLayout(tunnel_tab)

        tunnel_layout.addWidget(QLabel("程序启动时自动启动以下隧道:"))
        self.tunnel_list = QListWidget()
        tunnel_layout.addWidget(self.tunnel_list)

        # 添加隧道设置说明
        tunnel_note = QLabel("注: 勾选的隧道将在程序启动时自动启动")
        tunnel_note.setStyleSheet("color: gray; font-size: 10px;")
        tunnel_layout.addWidget(tunnel_note)

        tab_widget.addTab(tunnel_tab, "隧道")

        # === 关于标签页 ===
        about_tab = QWidget()
        about_layout = QVBoxLayout(about_tab)
        about_layout.setSpacing(15)

        # Logo图片
        logo_label = QLabel()
        logo_pixmap = QPixmap("/api/placeholder/100/100")  # 100x100 的占位图
        logo_label.setPixmap(logo_pixmap)
        logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        logo_label.setStyleSheet("margin-top: 20px;")
        about_layout.addWidget(logo_label)

        # 标题
        title_label = QLabel(APP_NAME)
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_label.setStyleSheet("font-size: 24px; font-weight: bold; margin: 10px 0px;")
        about_layout.addWidget(title_label)

        # 版本信息
        version_label = QLabel(f"Version {APP_VERSION}")
        version_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        version_label.setStyleSheet("font-size: 14px; color: #666666;")
        about_layout.addWidget(version_label)

        # 描述文本
        desc_text = QTextBrowser()  # 使用QTextBrowser代替QTextEdit以支持链接点击
        desc_text.setOpenLinks(True)  # 允许打开链接
        desc_text.setOpenExternalLinks(True)  # 在外部浏览器中打开链接
        desc_text.setStyleSheet("""
                    QTextBrowser {
                        border: 1px solid #cccccc;
                        border-radius: 5px;
                        padding: 10px;
                        background-color: transparent;
                    }
                    QTextBrowser:hover {
                        border-color: #999999;
                    }
                """)

        desc_text.setHtml(f"""
                    <div style="text-align: center; margin-bottom: 20px;">
                        <p style="font-size: 14px; line-height: 1.6;">
                            基于chmlfrp api开发的chmlfrp ui版本的客户端<br>
                            如有bug请提出谢谢!
                        </p>
                        <p style="color: #666666;">
                            有bug请投稿至 <a href="mailto:boring_student@qq.com" style="color: #0066cc;">boring_student@qq.com</a>
                        </p>
                    </div>

                    <div style="margin: 20px 0;">
                        <h3 style="color: #333333; border-bottom: 1px solid #eeeeee; padding-bottom: 8px;">相关链接</h3>
                        <ul style="list-style-type: none; padding-left: 0;">
                            <li style="margin: 8px 0;"><a href="https://github.com/Qianyiaz/ChmlFrp_Professional_Launcher" style="color: #0066cc; text-decoration: none;">▸ 千依🅥的cpl</a></li>
                            <li style="margin: 8px 0;"><a href="https://github.com/FengXiang2233/Xingcheng-Chmlfrp-Lanucher" style="color: #0066cc; text-decoration: none;">▸ 枫相的xcl2</a></li>
                            <li style="margin: 8px 0;"><a href="https://github.com/boringstudents/CHMLFRP_UI" style="color: #0066cc; text-decoration: none;">▸ 我的"不道a"</a></li>
                            <li style="margin: 8px 0;"><a href="https://github.com/TechCat-Team/ChmlFrp-Frp" style="color: #0066cc; text-decoration: none;">▸ chmlfrp官方魔改的frpc</a></li>
                        </ul>
                    </div>

                    <div style="margin: 20px 0;">
                        <h3 style="color: #333333; border-bottom: 1px solid #eeeeee; padding-bottom: 8px;">API文档</h3>
                        <ul style="list-style-type: none; padding-left: 0;">
                            <li style="margin: 8px 0;"><a href="https://docs.northwind.top/#/" style="color: #0066cc; text-decoration: none;">▸ 群友的api文档</a></li>
                            <li style="margin: 8px 0;"><a href="https://apifox.com/apidoc/shared-24b31bd1-e48b-44ab-a486-81cf5f964422/" style="color: #0066cc; text-decoration: none;">▸ 官方api v2文档</a></li>
                        </ul>
                    </div>

                    <div style="text-align: center; margin-top: 20px;">
                        <p style="margin: 8px 0;"><a href="http://chmlfrp.cn" style="color: #0066cc; text-decoration: none;">官网：chmlfrp.cn</a></p>
                        <p style="margin: 8px 0;"><a href="http://panel.chmlfrp.cn" style="color: #0066cc; text-decoration: none;">v2控制面板：panel.chmlfrp.cn</a></p>
                        <p style="margin: 8px 0;"><a href="http://preview.panel.chmlfrp.cn" style="color: #0066cc; text-decoration: none;">v3控制面板：preview.panel.chmlfrp.cn</a></p>
                    </div>
                """)
        desc_text.setMinimumHeight(300)
        about_layout.addWidget(desc_text)

        about_layout.addStretch()
        tab_widget.addTab(about_tab, "关于")

        # === 底部按钮 ===
        button_layout = QHBoxLayout()
        save_button = QPushButton("保存")
        save_button.clicked.connect(self.save_settings)
        cancel_button = QPushButton("取消")
        cancel_button.clicked.connect(self.reject)
        button_layout.addWidget(save_button)
        button_layout.addWidget(cancel_button)
        layout.addLayout(button_layout)

    def apply_theme(self, is_dark):
        if is_dark:
            style = """
                QDialog, QTabWidget, QWidget {
                    background-color: #2D2D2D;
                    color: #FFFFFF;
                }
                QTabWidget::pane {
                    border: 1px solid #555555;
                }
                QTabBar::tab {
                    background-color: #3D3D3D;
                    color: #FFFFFF;
                    padding: 5px;
                }
                QTabBar::tab:selected {
                    background-color: #4D4D4D;
                }
                QTextEdit {
                    background-color: #2D2D2D;
                    color: #FFFFFF;
                }
                QTextEdit a {
                    color: #00A0FF;
                }
                """ + self.get_base_dark_style()
        else:
            style = """
                QDialog, QTabWidget, QWidget {
                    background-color: #FFFFFF;
                    color: #000000;
                }
                QTabWidget::pane {
                    border: 1px solid #CCCCCC;
                }
                QTabBar::tab {
                    background-color: #F0F0F0;
                    color: #000000;
                    padding: 5px;
                }
                QTabBar::tab:selected {
                    background-color: #FFFFFF;
                }
                QTextEdit {
                    background-color: #FFFFFF;
                    color: #000000;
                }
                QTextEdit a {
                    color: #0066CC;
                }
                """ + self.get_base_light_style()

        self.setStyleSheet(style)

    @staticmethod
    def get_base_dark_style():
        return """
            QGroupBox {
                border: 1px solid #555555;
                margin-top: 1em;
                padding-top: 0.5em;
            }
            QCheckBox, QRadioButton {
                color: #FFFFFF;
            }
            QPushButton {
                background-color: #0D47A1;
                color: white;
                border: none;
                padding: 5px 10px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #1565C0;
            }
            QListWidget {
                background-color: #3D3D3D;
                border: 1px solid #555555;
            }
        """

    @staticmethod
    def get_base_light_style():
        return """
            QGroupBox {
                border: 1px solid #CCCCCC;
                margin-top: 1em;
                padding-top: 0.5em;
            }
            QCheckBox, QRadioButton {
                color: #000000;
            }
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                padding: 5px 10px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QListWidget {
                background-color: #FFFFFF;
                border: 1px solid #CCCCCC;
            }
        """

    def load_settings(self):
        # 读取配置文件
        settings_path_json = get_absolute_path("settings.json")
        try:
            with open(settings_path_json, 'r') as file_contents:
                settings_content = json.load(file_contents)
        except (FileNotFoundError, json.JSONDecodeError):
            settings_content = {}
            self.parent.logger.info("未找到配置文件或配置文件无效，将使用默认设置")

        # 读取自启动状态
        if sys.platform == "win32":
            try:
                key = winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER,
                    r"Software\Microsoft\Windows\CurrentVersion\Run",
                    0,
                    winreg.KEY_READ
                )
                try:
                    winreg.QueryValueEx(key, "ChmlFrpUI")
                    self.autostart_checkbox.setChecked(True)
                except WindowsError:
                    self.autostart_checkbox.setChecked(False)
                winreg.CloseKey(key)
            except WindowsError as content:
                self.parent.logger.error(f"读取自启动设置失败: {str(content)}")
                self.autostart_checkbox.setChecked(False)

        # 加载日志设置
        try:
            log_size = settings_content.get('log_size_mb')
            if log_size is not None:
                self.log_size_input.setText(str(log_size))
            else:
                self.log_size_input.setText("10")

            backup_count = settings_content.get('backup_count')
            if backup_count is not None:
                self.backup_count_input.setText(str(backup_count))
            else:
                self.backup_count_input.setText("30")
        except Exception as content:
            self.parent.logger.error(f"加载日志设置失败: {str(content)}")
            self.log_size_input.setText("10")
            self.backup_count_input.setText("30")

        # 加载主题设置
        try:
            theme_setting = settings_content.get('theme', 'system')
            if theme_setting == 'light':
                self.theme_light.setChecked(True)
            elif theme_setting == 'dark':
                self.theme_dark.setChecked(True)
            else:
                self.theme_system.setChecked(True)
        except Exception as content:
            self.parent.logger.error(f"加载主题设置失败: {str(content)}")
            self.theme_system.setChecked(True)

        # 加载隧道设置
        try:
            # 清除现有项目
            self.tunnel_list.clear()

            # 获取自动启动的隧道列表
            auto_start_tunnels = settings_content.get('auto_start_tunnels', [])

            if self.parent.token:
                # 获取用户的隧道列表
                tunnels = API.get_user_tunnels(self.parent.token)
                if tunnels:
                    for tunnel in tunnels:
                        item = QListWidgetItem(tunnel['name'])
                        item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
                        # 设置选中状态
                        item.setCheckState(
                            Qt.CheckState.Checked if tunnel['name'] in auto_start_tunnels
                            else Qt.CheckState.Unchecked
                        )
                        self.tunnel_list.addItem(item)
                else:
                    no_tunnels_item = QListWidgetItem("无可用隧道")
                    self.tunnel_list.addItem(no_tunnels_item)
            else:
                not_logged_in_item = QListWidgetItem("请先登录")
                self.tunnel_list.addItem(not_logged_in_item)
        except Exception as content:
            self.parent.logger.error(f"加载隧道设置失败: {str(content)}")
            error_item = QListWidgetItem("加载隧道列表失败")
            self.tunnel_list.addItem(error_item)


    def toggle_autostart(self, state):
        if sys.platform == "win32":
            try:
                # 获取程序的完整路径
                if getattr(sys, 'frozen', False):
                    # 如果是打包后的 exe
                    program_path = f'"{sys.executable}"'
                else:
                    # 如果是 Python 脚本
                    program_path = f'"{sys.executable}" "{os.path.abspath(sys.argv[0])}"'

                key = winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER,
                    r"Software\Microsoft\Windows\CurrentVersion\Run",
                    0,
                    winreg.KEY_ALL_ACCESS
                )

                if state == Qt.CheckState.Checked.value:
                    winreg.SetValueEx(key, "ChmlFrpUI", 0, winreg.REG_SZ, program_path)
                else:
                    try:
                        winreg.DeleteValue(key, "ChmlFrpUI")
                        self.parent.logger.info("已删除自启动项")
                    except WindowsError:
                        pass
                winreg.CloseKey(key)
            except Exception as content:
                self.parent.logger.error(f"设置自启动失败: {str(content)}")
                QMessageBox.warning(self, "错误", f"设置自启动失败: {str(content)}")

    def get_selected_theme(self):
        if self.theme_light.isChecked():
            return 'light'
        elif self.theme_dark.isChecked():
            return 'dark'
        else:
            return 'system'

    def save_settings(self):
        try:
            # 获取设置值
            log_size = int(self.log_size_input.text() or 10)
            backup_count = int(self.backup_count_input.text() or 30)

            # 保存自动启动的隧道列表
            auto_start_tunnels = []
            for i in range(self.tunnel_list.count()):
                item = self.tunnel_list.item(i)
                if item.flags() & Qt.ItemFlag.ItemIsUserCheckable:
                    if item.checkState() == Qt.CheckState.Checked:
                        auto_start_tunnels.append(item.text())

            settings_pathway = get_absolute_path("settings.json")
            settings_content = {
                'auto_start_tunnels': auto_start_tunnels,
                'theme': self.get_selected_theme(),
                'log_size_mb': log_size,
                'backup_count': backup_count
            }

            with open(settings_pathway, 'w') as file_contents:
                json.dump(settings_content, file_contents)

            # 更新全局变量
            global maxBytes, backupCount
            maxBytes = log_size * 1024 * 1024
            backupCount = backup_count

            # 应用主题设置
            if self.get_selected_theme() == 'system':
                self.parent.dark_theme = self.parent.is_system_dark_theme()
            else:
                self.parent.dark_theme = (self.get_selected_theme() == 'dark')
            self.parent.apply_theme()

            QMessageBox.information(self, "成功", "设置已保存")
            self.accept()

        except Exception as content:
            QMessageBox.warning(self, "错误", f"保存设置失败: {str(content)}")

class UpdateCheckerDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.download_links = []
        self.network_manager = QNetworkAccessManager()
        self.setWindowTitle("软件更新")
        self.setFixedSize(600, 500)

        # 添加定时器用于检查本地更新
        self.local_update_timer = QTimer(self)
        self.local_update_timer.timeout.connect(self.check_local_updates)
        self.local_update_timer.start(1000)  # 每秒检查一次

        if os.path.exists("favicon.ico"):
            self.setWindowIcon(QIcon("favicon.ico"))

        self.init_ui()
        QTimer.singleShot(0, self.check_for_updates)
        self.check_local_updates()  # 初始检查



    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(15)

        # 版本信息区域
        version_layout = QFormLayout()
        self.current_version_label = QLabel(APP_VERSION)
        self.latest_version_label = QLabel("检查中...")
        version_layout.addRow("当前版本:", self.current_version_label)
        version_layout.addRow("最新版本:", self.latest_version_label)
        layout.addLayout(version_layout)

        # 检查更新按钮
        self.check_button = QPushButton("重新检查")
        self.check_button.setStyleSheet("""
            QPushButton {
                border-radius: 8px; 
                padding: 8px;
                min-width: 100px;
                background-color: #4CAF50;
                color: white;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
        """)
        self.check_button.clicked.connect(self.check_for_updates)
        layout.addWidget(self.check_button)

        # 更新内容区域
        self.update_content = QTextBrowser()
        self.update_content.setOpenLinks(False)
        self.update_content.setPlaceholderText("更新内容将显示在这里...")
        self.update_content.setStyleSheet("""
            QTextBrowser {
                border-radius: 5px;
                padding: 10px;
            }
        """)
        layout.addWidget(self.update_content)

        # 下载区域
        download_group = QGroupBox("下载更新")
        download_layout = QVBoxLayout(download_group)

        # 镜像选择
        self.mirror_combo = QComboBox()
        self.mirror_combo.addItem("请选择下载源...")
        self.mirror_combo.setStyleSheet("""
            QComboBox {
                border-radius: 5px;
                padding: 5px;
            }
        """)
        download_layout.addWidget(self.mirror_combo)

        # 进度条
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border-radius: 8px;
                height: 20px;
                text-align: center;
            }
            QProgressBar::chunk {
                border-radius: 8px;
                background-color: #4CAF50;
            }
        """)
        download_layout.addWidget(self.progress_bar)

        # 下载/更新按钮
        self.download_button = QPushButton("开始下载")
        self.download_button.setStyleSheet("""
            QPushButton {
                border-radius: 8px; 
                padding: 8px;
                min-width: 100px;
                background-color: #2196F3;
                color: white;
            }
            QPushButton:hover {
                background-color: #0b7dda;
            }
            QPushButton:disabled {
                background-color: #cccccc;
            }
        """)
        self.download_button.setEnabled(False)
        self.download_button.clicked.connect(self.start_download_or_update)
        download_layout.addWidget(self.download_button)

        layout.addWidget(download_group)

        # 底部按钮 (圆角样式)
        button_box = QDialogButtonBox()
        button_box.setStyleSheet("""
            QPushButton {
                border-radius: 8px;
                padding: 5px 10px;
                min-width: 80px;
            }
        """)

        close_button = QPushButton("关闭")
        close_button.clicked.connect(self.close)
        button_box.addButton(close_button, QDialogButtonBox.ButtonRole.RejectRole)

        layout.addWidget(button_box)

    def check_local_updates(self):
        """检查本地是否有可用的更新包"""
        local_updates = glob.glob("CUL*.zip")
        if local_updates:
            # 找到版本号最大的文件
            latest_file = max(local_updates, key=lambda x: [
                int(num) for num in re.findall(r'CUL(\d+)\.(\d+)\.(\d+)\.zip', x)[0]
            ])
            version = re.search(r'CUL(\d+\.\d+\.\d+)\.zip', latest_file).group(1)

            # 检查是否是新版本
            current = tuple(map(int, APP_VERSION.split('.')))
            latest = tuple(map(int, version.split('.')))

            if latest > current:
                self.latest_version_label.setText(version)
                self.update_content.setPlainText(f"检测到本地更新包: {latest_file}\n版本: {version}")
                self.download_button.setText("开始更新")
                self.download_button.setEnabled(True)
                self.download_button.setStyleSheet("""
                    QPushButton {
                        border-radius: 8px; 
                        padding: 8px;
                        min-width: 100px;
                        background-color: #FF9800;
                        color: white;
                    }
                    QPushButton:hover {
                        background-color: #F57C00;
                    }
                """)
                return True
        return False

    def start_download_or_update(self):
        """根据情况开始下载或更新"""
        if self.download_button.text() == "开始下载":
            self.start_download()
        else:
            self.start_update()

    def start_update(self):
        """执行更新流程"""
        reply = QMessageBox.question(
            self, "确认更新",
            "即将关闭程序并执行更新，是否继续?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.No:
            return

        # 查找最新的更新包（格式为CUL1.x.x.zip）
        local_updates = glob.glob("CUL1.*.zip")
        if not local_updates:
            QMessageBox.warning(self, "更新失败", "未找到更新包")
            return

        # 按版本号排序找到最新包
        latest_file = max(local_updates, key=lambda x: [
            int(num) for num in re.findall(r'CUL1\.(\d+)\.(\d+)\.zip', x)[0]
        ])

        # 创建带进度提示的批处理脚本
        bat_content = f"""
        @echo off
        chcp 65001 >nul
        echo 正在准备更新环境...
        echo.

        :: 关闭当前目录所有exe进程（含进度提示）
        echo [1/5] 正在关闭运行中的程序...
        for %%i in ("%cd%\\*.exe") do (
            taskkill /f /im "%%~nxi" >nul 2>&1
            if errorlevel 1 (
                echo 未找到进程：%%~nxi
            ) else (
                echo 已终止进程：%%~nxi
            )
        )

        :: 带倒计时的等待
        echo.
        echo [2/5] 等待进程清理（剩余2秒）...
        timeout /t 2 /nobreak

        :: 解压更新包
        echo.
        echo [3/5] 正在解压更新包：{os.path.basename(latest_file)}
        mkdir temp_update 2>nul
        powershell -command "Expand-Archive -Path '{os.path.abspath(latest_file)}' -DestinationPath 'temp_update' -Force"

        :: 复制文件
        echo.
        echo [4/5] 正在应用更新...
        xcopy /s /y /i "temp_update\\CHMLFRP_UI.dist\\*" "." >nul
        echo 文件更新完成！

        :: 清理环境
        echo.
        echo [5/5] 正在清理临时文件...
        rd /s /q temp_update
        del "{os.path.abspath(latest_file)}" >nul 2>&1

        :: 重启程序
        echo.
        echo 正在启动新版本...
        start "" "CHMLFRP_UI.exe"

        :: 自删除脚本（带延迟确保执行完成）
        ping 127.0.0.1 -n 3 >nul
        del "%~f0"

        echo.
        echo 更新已完成！窗口将在3秒后自动关闭...
        timeout /t 3 /nobreak >nul
        """

        # 写入批处理文件（使用UTF-8编码支持更丰富的字符）
        with open("update.bat", "w", encoding="utf-8") as f:
            f.write(bat_content)

        # 启动独立进程执行更新（显示控制台窗口）
        subprocess.Popen(
            ["cmd.exe", "/c", "start", "update.bat"],
            creationflags=subprocess.CREATE_NEW_CONSOLE
        )
        time.sleep(1)
        # 关闭当前程序
        self.cleanup()

    def cleanup(self):
        # 终止所有子进程
        current_pid = os.getpid()
        try:
            current_process = psutil.Process(current_pid)
            children = current_process.children(recursive=True)
            for child in children:
                try:
                    child.terminate()
                except psutil.NoSuchProcess:
                    pass

            gone, alive = psutil.wait_procs(children, timeout=5)
            for p in alive:
                try:
                    p.kill()
                except psutil.NoSuchProcess:
                    pass

            # 强制终止残留进程
            subprocess.run(["taskkill", "/f", "/im", "frpc.exe"],
                           stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)

        except Exception as e:
            logger.error(f"清理进程时出错: {str(e)}")

        QApplication.quit()
    def apply_theme(self, is_dark):
        """应用主题设置"""
        if is_dark:
            self.setStyleSheet("""
                QDialog {
                    background-color: #2d2d2d;
                    color: #ffffff;
                }
                QGroupBox {
                    border: 1px solid #444;
                    margin-top: 10px;
                    padding-top: 15px;
                    color: #ffffff;
                }
                QTextBrowser {
                    background-color: #252525;
                    border: 1px solid #444;
                    color: #ffffff;
                }
                QComboBox {
                    background-color: #3a3a3a;
                    color: white;
                    border: 1px solid #444;
                }
                QLabel {
                    color: #ffffff;
                }
                QDialogButtonBox QPushButton {
                    border-radius: 8px;
                    padding: 5px 10px;
                    min-width: 80px;
                    background-color: #3a3a3a;
                    color: white;
                }
                QDialogButtonBox QPushButton:hover {
                    background-color: #4a4a4a;
                }
            """)
        else:
            self.setStyleSheet("""
                QDialog {
                    background-color: #ffffff;
                    color: #000000;
                }
                QGroupBox {
                    border: 1px solid #ddd;
                    margin-top: 10px;
                    padding-top: 15px;
                    color: #000000;
                }
                QTextBrowser {
                    background-color: #f9f9f9;
                    border: 1px solid #ddd;
                    color: #000000;
                }
                QComboBox {
                    background-color: #ffffff;
                    color: #000000;
                    border: 1px solid #ccc;
                }
                QLabel {
                    color: #000000;
                }
                QDialogButtonBox QPushButton {
                    border-radius: 8px;
                    padding: 5px 10px;
                    min-width: 80px;
                    background-color: #f0f0f0;
                    color: #000000;
                }
                QDialogButtonBox QPushButton:hover {
                    background-color: #e0e0e0;
                }
            """)

    def check_for_updates(self):
        """执行更新检查"""
        self.check_button.setEnabled(False)
        self.latest_version_label.setText("检查中...")
        self.update_content.setPlainText("正在连接服务器检查更新...")
        self.mirror_combo.clear()
        self.mirror_combo.addItem("请选择下载源...")
        self.download_button.setEnabled(False)
        self.progress_bar.setValue(0)

        self.thread = QThread()
        self.worker = UpdateCheckerWorker()
        self.worker.moveToThread(self.thread)

        self.worker.finished.connect(self.handle_update_result)
        self.worker.error.connect(self.handle_update_error)
        self.thread.started.connect(self.worker.run)
        self.thread.finished.connect(self.thread.deleteLater)

        self.thread.start()

    def handle_update_result(self, latest_version, update_content, download_links):
        """处理更新检查结果"""
        self.thread.quit()
        self.thread.wait()

        self.check_button.setEnabled(True)
        self.latest_version_label.setText(latest_version)

        # 渲染Markdown内容并保留换行
        html = markdown.markdown(update_content or "无更新说明", extensions=['nl2br'])
        self.update_content.setHtml(html)

        self.download_links = download_links

        if latest_version == APP_VERSION:
            QMessageBox.information(self, "检查更新", "当前已是最新版本！")
            return

        if not download_links:
            self.mirror_combo.addItem("无可用下载链接")
            return

        # 添加所有镜像链接（只显示主域名）
        for link in download_links:
            domain = QUrl(link).host()
            self.mirror_combo.addItem(domain, link)

        self.mirror_combo.currentIndexChanged.connect(self.enable_download_button)

        # 版本比较
        current = tuple(map(int, re.sub(r"[^0-9.]", "", APP_VERSION).split(".")))
        latest = tuple(map(int, re.sub(r"[^0-9.]", "", latest_version).split(".")))

        if latest > current:
            QMessageBox.information(self, "发现新版本",
                                    f"发现新版本 {latest_version}，请下载更新！")

    def handle_update_error(self, error_msg):
        """处理更新检查错误"""
        self.thread.quit()
        self.thread.wait()

        self.check_button.setEnabled(True)
        self.latest_version_label.setText("检查失败")
        self.update_content.setPlainText(f"检查更新时出错:\n{error_msg}")
        self.mirror_combo.addItem("无法获取下载链接")

        QMessageBox.warning(self, "检查更新失败", error_msg)

    def enable_download_button(self, index):
        """启用下载按钮"""
        self.download_button.setEnabled(index > 0)

    def start_download(self):
        """开始下载更新"""
        index = self.mirror_combo.currentIndex()
        if index <= 0:
            return

        url = self.mirror_combo.itemData(index)
        version = self.latest_version_label.text()
        filename = f"CUL{version}.zip"
        save_path = os.path.join(os.getcwd(), filename)

        # 检查文件是否已存在
        if os.path.exists(save_path):
            reply = QMessageBox.question(
                self, "文件已存在",
                f"文件 {filename} 已存在，是否覆盖?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if reply == QMessageBox.StandardButton.No:
                return

        self.download_button.setEnabled(False)
        self.check_button.setEnabled(False)
        self.progress_bar.setFormat("准备下载...")

        request = QNetworkRequest(QUrl(url))
        self.reply = self.network_manager.get(request)
        self.reply.downloadProgress.connect(self.update_progress)
        self.reply.finished.connect(lambda: self.download_finished(save_path))

    def update_progress(self, bytes_received, bytes_total):
        """更新下载进度"""
        if bytes_total > 0:
            progress = int((bytes_received / bytes_total) * 100)
            self.progress_bar.setValue(progress)
            self.progress_bar.setFormat(
                f"下载中... {progress}% ({bytes_received / 1024 / 1024:.1f}MB/{bytes_total / 1024 / 1024:.1f}MB)")

    def download_finished(self, save_path):
        """下载完成处理"""
        try:
            # PyQt6中错误检查方式
            if self.reply.error() == QNetworkReply.NetworkError.NoError:
                with open(save_path, 'wb') as f:
                    f.write(self.reply.readAll())
                self.progress_bar.setFormat("下载完成！")
                QMessageBox.information(self, "下载完成", f"文件已保存为:\n{save_path}")
            else:
                self.progress_bar.setFormat("下载失败")
                QMessageBox.warning(self, "下载失败", self.reply.errorString())
        except Exception as e:
            self.progress_bar.setFormat("保存失败")
            QMessageBox.warning(self, "保存失败", f"文件保存失败: {str(e)}")
        finally:
            self.download_button.setEnabled(True)
            self.check_button.setEnabled(True)
            if hasattr(self, 'reply'):
                self.reply.deleteLater()

class UpdateCheckerWorker(QObject):
    """更新检查工作线程"""
    finished = pyqtSignal(str, str, list)
    error = pyqtSignal(str)

    def __init__(self):
        super().__init__()

    def run(self):
        try:
            latest_version, update_content, download_links = ProgramUpdates.check_update(APP_VERSION)
            if latest_version is None:
                self.error.emit("无法获取更新信息")
                return

            if latest_version == APP_VERSION:
                self.finished.emit(latest_version, update_content, [])
            elif download_links:
                self.finished.emit(latest_version, update_content or "无更新说明", download_links or [])
            else:
                self.error.emit("未找到更新信息")
        except Exception as e:
            self.error.emit(f"更新检查失败: {str(e)}")

class NodeCard(QFrame):
    clicked = pyqtSignal(object)
    def __init__(self, node_info):
        super().__init__()
        self.node_info = node_info
        self.initUI()
        self.updateStyle()

    def initUI(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(10, 10, 10, 10)

        name_label = QLabel(f"<b>{self.node_info.get('node_name', 'N/A')}</b>")
        name_label.setObjectName("nameLabel")
        group_label = QLabel(f"节点组: {self.node_info.get('nodegroup', 'N/A')}")
        cpu_label = QLabel(f"CPU使用率: {self.node_info.get('cpu_usage', 'N/A')}%")
        bandwidth_label = QLabel(f"带宽使用率: {self.node_info.get('bandwidth_usage_percent', 'N/A')}%")

        layout.addWidget(name_label)
        layout.addWidget(group_label)
        layout.addWidget(cpu_label)
        layout.addWidget(bandwidth_label)

        self.setLayout(layout)
        self.setFixedSize(250, 150)

    def updateStyle(self):
        self.setStyleSheet("""
			NodeCard {
				border: 1px solid #d0d0d0;
				border-radius: 5px;
				padding: 10px;
				margin: 5px;
			}
			NodeCard:hover {
				background-color: rgba(240, 240, 240, 50);
			}
			#nameLabel {
				font-size: 16px;
				font-weight: bold;
			}
		""")

    def paintEvent(self, event):
        super().paintEvent(event)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        if self.node_info.get('state') == 'online':
            color = QColor(0, 255, 0)  # 绿色
        else:
            color = QColor(255, 0, 0)  # 红色
        painter.setPen(QPen(color, 2))
        painter.setBrush(color)
        painter.drawEllipse(self.width() - 20, 10, 10, 10)

    def setSelected(self, selected):
        if selected:
            self.setStyleSheet(
                self.styleSheet() + "NodeCard { border: 2px solid #0066cc; background-color: rgba(224, 224, 224, 50); }")
        else:
            self.setStyleSheet(self.styleSheet().replace(
                "NodeCard { border: 2px solid #0066cc; background-color: rgba(224, 224, 224, 50); }", ""))

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit(self.node_info)
        super().mousePressEvent(event)

class MainWindow(QMainWindow):
    """主窗口"""
    def __init__(self):
        super().__init__()
        self.stop_worker = None
        self.stop_thread = None
        self.button_hover_color = None
        self.button_color = None
        self.ping_thread = None
        self.selected_node = None
        self.ping_result = None
        self.ping_type_combo = None
        self.target_input = None
        self.ddns_start_button = None
        self.ip_display_label = None
        self.ddns_status_label = None
        self.ddns_api_combo = None
        self.ddns_domain_combo = None
        self.details_button = None
        self.refresh_button = None
        self.node_container = None
        self.delete_domain_button = None
        self.edit_domain_button = None
        self.domain_container = None
        self.batch_edit_button = None
        self.view_output_button = None
        self.delete_tunnel_button = None
        self.edit_tunnel_button = None
        self.selected_domain = None
        self.tunnel_container = None
        self.user_info_display = None
        self.logout_button = None
        self.login_button = None
        self.token_input = None
        self.password_input = None
        self.username_input = None
        self.ip_tools_widget = None
        self.tray_icon = None
        self.dark_theme = None
        self.content_stack = None
        self.ip_tools_button = None
        self.ping_button = None
        self.ddns_button = None
        self.node_button = None
        self.domain_button = None
        self.tunnel_button = None
        self.user_info_button = None
        self.settings_button = None
        self.background_frame = None
        self.tab_buttons = []
        self.selected_tunnels = []
        self.token = None

        # 初始化输出互斥锁
        self.output_mutex = QMutex()

        # 初始化日志系统
        self.logger = logging.getLogger('CHMLFRP_UI')
        self.qt_handler = QtHandler(self)
        self.logger.addHandler(self.qt_handler)
        self.qt_handler.new_record.connect(self.update_log)

        # 初始化日志显示
        self.log_display = QTextEdit(self)
        self.log_display.setReadOnly(True)
        self.log_display.setFixedHeight(100)

        # 添加进程锁
        self.process_lock = threading.Lock()
        self.tunnel_lock = threading.Lock()
        self.output_lock = threading.Lock()

        # 加载程序设置
        self.load_app_settings()

        self.tunnel_outputs = {}
        self.worker = None
        self.process = None
        self.check_and_download_files()
        self.tunnel_processes = {}

        self.dragging = False
        self.offset = None

        self.set_taskbar_icon()
        self.setup_system_tray()

        self.update_timer = QTimer(self)
        self.update_timer.timeout.connect(self.auto_update)
        self.update_timer.start(30000)  # 30秒更新一次

        self.user_info = None
        self.node_list = QWidget()

        self.running_tunnels = {}
        self.running_tunnels_mutex = QMutex()

        self.node_check_timer = QTimer(self)
        self.node_check_timer.timeout.connect(self.check_node_status)
        self.node_check_timer.start(60000)

        # 初始化UI
        self.initUI()

        # 确保在初始化后立即应用主题
        self.apply_theme()

        # 加载凭证和自动登录
        self.load_credentials()
        self.auto_login()

    def initUI(self):
        self.setWindowTitle(APP_NAME+" 程序")
        self.setGeometry(100, 100, 800, 600)
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)

        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)

        main_layout = QVBoxLayout(central_widget)

        self.background_frame = QFrame(self)
        self.background_frame.setObjectName("background")
        background_layout = QVBoxLayout(self.background_frame)
        main_layout.addWidget(self.background_frame)

        title_bar = QWidget()
        title_layout = QHBoxLayout(title_bar)
        title_label = QLabel(APP_NAME+" 程序")
        title_layout.addWidget(title_label)
        title_layout.addStretch(1)

        self.settings_button = QPushButton("设置")
        self.settings_button.clicked.connect(self.show_settings)
        title_layout.addWidget(self.settings_button)

        self.settings_button = QPushButton("检测更新")
        self.settings_button.clicked.connect(self.show_update)
        title_layout.addWidget(self.settings_button)

        min_button = QPushButton("－")
        min_button.clicked.connect(self.showMinimized)
        close_button = QPushButton("×")
        close_button.clicked.connect(self.close)
        theme_button = QPushButton("切换主题")
        theme_button.clicked.connect(self.toggle_theme)

        title_layout.addWidget(theme_button)
        title_layout.addWidget(min_button)
        title_layout.addWidget(close_button)
        background_layout.addWidget(title_bar)

        content_layout = QHBoxLayout()

        menu_widget = QWidget()
        menu_layout = QVBoxLayout(menu_widget)

        self.user_info_button = QPushButton("用户信息")
        self.tunnel_button = QPushButton("隧道管理")
        self.domain_button = QPushButton("域名管理")
        self.node_button = QPushButton("节点状态")

        self.user_info_button.clicked.connect(lambda: self.switch_tab("user_info"))
        self.tunnel_button.clicked.connect(lambda: self.switch_tab("tunnel"))
        self.domain_button.clicked.connect(lambda: self.switch_tab("domain"))
        self.node_button.clicked.connect(lambda: self.switch_tab("node"))

        menu_layout.addWidget(self.user_info_button)
        menu_layout.addWidget(self.tunnel_button)
        menu_layout.addWidget(self.domain_button)
        menu_layout.addWidget(self.node_button)
        menu_layout.addStretch(1)

        content_layout.addWidget(menu_widget)

        self.content_stack = QStackedWidget()
        content_layout.addWidget(self.content_stack, 1)

        background_layout.addLayout(content_layout)

        background_layout.addWidget(self.log_display)

        author_info = QLabel("本程序基于ChmlFrp api开发 作者: boring_student")
        author_info.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignBottom)
        author_info.setStyleSheet("font-size: 7pt; color: #888888; background: transparent; padding: 2px;")
        author_info.setProperty("author_info", True)
        author_info.setFixedHeight(18)

        bottom_layout = QHBoxLayout()
        bottom_layout.addStretch(1)
        bottom_layout.addWidget(author_info)
        bottom_layout.setContentsMargins(0, 0, 5, 2)
        background_layout.addLayout(bottom_layout)

        self.setup_user_info_page()
        self.setup_tunnel_page()
        self.setup_domain_page()
        self.setup_node_page()

        self.switch_tab("user_info")

        self.tab_buttons = [
            self.user_info_button,
            self.tunnel_button,
            self.domain_button,
            self.node_button
        ]

    def load_app_settings(self):
        """加载应用程序设置"""
        settings_path_json = get_absolute_path("settings.json")
        try:
            if os.path.exists(settings_path_json):
                with open(settings_path_json, 'r') as file_contents:
                    settings_content = json.load(file_contents)
                    theme_setting = settings_content.get('theme', 'system')

                    if theme_setting == 'system':
                        self.dark_theme = self.is_system_dark_theme()
                    elif theme_setting == 'dark':
                        self.dark_theme = True
                    else:  # light
                        self.dark_theme = False

            else:
                self.dark_theme = self.is_system_dark_theme()
                self.logger.info("使用系统默认主题设置")
        except Exception as content:
            self.logger.error(f"加载设置失败: {str(content)}")
            self.dark_theme = self.is_system_dark_theme()

    def setup_system_tray(self):
        icon_path = get_absolute_path("favicon.ico")
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(QIcon(icon_path))

        tray_menu = QMenu()
        show_action = tray_menu.addAction("显示")
        show_action.triggered.connect(self.show)
        quit_action = tray_menu.addAction("退出")
        quit_action.triggered.connect(self.quit_application)
        self.tray_icon.setContextMenu(tray_menu)

        self.tray_icon.activated.connect(self.tray_icon_activated)

        self.tray_icon.show()

    def auto_start_tunnels(self):
        if not self.token:
            return

        settings_path_json = get_absolute_path("settings.json")
        try:
            with open(settings_path_json, 'r') as file_contents:
                settings_content = json.load(file_contents)
                auto_start_tunnels = settings_content.get('auto_start_tunnels', [])

            tunnels = API.get_user_tunnels(self.token)
            if tunnels:
                for tunnel in tunnels:
                    if tunnel['name'] in auto_start_tunnels:
                        self.start_tunnel(tunnel)
                        self.logger.info(f"自动启动隧道: {tunnel['name']}")
        except Exception as content:
            self.logger.error(f"自动启动隧道失败: {str(content)}")

    def show_settings(self):
        dialog = SettingsDialog(self)
        dialog.apply_theme(self.dark_theme)
        dialog.exec()

    def show_update(self):
        dialog = UpdateCheckerDialog()
        dialog.apply_theme(self.dark_theme)
        dialog.exec()

    def tray_icon_activated(self, reason):
        if reason == QSystemTrayIcon.ActivationReason.DoubleClick:
            self.show()
            self.raise_()
            self.activateWindow()

    def quit_application(self):
        self.cleanup()
        QApplication.quit()

    def set_taskbar_icon(self):
        icon_path = get_absolute_path("favicon.ico")
        self.setWindowIcon(QIcon(icon_path))

    def check_node_status(self):
        if not self.token:
            return

        tunnels = API.get_user_tunnels(self.token)
        if tunnels is None:
            return

        for tunnel_name, process in list(self.tunnel_processes.items()):
            tunnel_info = next((t for t in tunnels if t['name'] == tunnel_name), None)
            if tunnel_info:
                node_name = tunnel_info['node']
                if not API.is_node_online(node_name, tyen="online"):
                    self.logger.warning(f"节点 {node_name} 离线，停止隧道 {tunnel_name}")
                    self.stop_tunnel({"name": tunnel_name})
                    QMessageBox.warning(self, "节点离线", f"节点 {node_name} 离线，隧道 {tunnel_name} 已停止")
            else:
                self.logger.warning(f"未找到隧道 {tunnel_name} 的信息")

    def update_button_styles(self, selected_button):
        for button in self.tab_buttons:
            if button == selected_button:
                button.setStyleSheet(f"""
					QPushButton {{
						background-color: {self.button_hover_color};
						color: white;
						border: none;
						padding: 5px 10px;
						text-align: center;
						text-decoration: none;
						font-size: 14px;
						margin: 4px 2px;
						border-radius: 4px;
					}}
				""")
            else:
                button.setStyleSheet(f"""
					QPushButton {{
						background-color: {self.button_color};
						color: white;
						border: none;
						padding: 5px 10px;
						text-align: center;
						text-decoration: none;
						font-size: 14px;
						margin: 4px 2px;
						border-radius: 4px;
					}}
					QPushButton:hover {{
						background-color: {self.button_hover_color};
					}}
				""")

    def batch_edit_tunnels(self):
        if not self.selected_tunnels:
            QMessageBox.warning(self, "警告", "请先选择要编辑的隧道")
            return

        dialog = BatchEditDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            changes = dialog.get_changes()
            if not changes:
                QMessageBox.information(self, "提示", "没有进行任何修改")
                return

            for tunnel_info in self.selected_tunnels:
                try:
                    url = "http://cf-v2.uapis.cn/update_tunnel"
                    payload = {
                        "tunnelid": int(tunnel_info["id"]),
                        "token": self.token,
                        "tunnelname": tunnel_info["name"],
                        "node": changes.get("node", tunnel_info["node"]),
                        "localip": tunnel_info["localip"],
                        "porttype": changes.get("type", tunnel_info["type"]),
                        "localport": tunnel_info["nport"],
                        "remoteport": tunnel_info["dorp"],
                        "encryption": tunnel_info["encryption"],
                        "compression": tunnel_info["compression"]
                    }

                    # 验证本地端口是否有效
                    if "nport" in changes:
                        if not enter_inspector.validate_port(tunnel_info["nport"],True):
                            raise ValueError(f"隧道 '{tunnel_info['name']}': 本地端口必须是1-65535之间的整数")
                        payload["localport"] = int(changes["nport"])

                    # 验证远程端口是否有效
                    if "dorp" in changes:
                        if not enter_inspector.validate_port(tunnel_info["dorp"],False):
                            raise ValueError(f"隧道 '{tunnel_info['name']}': 远程端口必须是10000-65535之间的整数")
                        payload["remoteport"] = int(changes["dorp"])

                    headers = get_headers(request_json=True)
                    response = requests.post(url, headers=headers, json=payload)
                    if response.status_code == 200:
                        self.logger.info(f"隧道 {tunnel_info['name']} 更新成功")
                    else:
                        self.logger.error(f"更新隧道 {tunnel_info['name']} 失败: {response.text}")
                except ValueError as ve:
                    self.logger.error(str(ve))
                    QMessageBox.warning(self, "错误", str(ve))
                except Exception as content:
                    self.logger.exception(f"更新隧道 {tunnel_info['name']} 时发生错误")
                    QMessageBox.warning(self, "错误", f"更新隧道 {tunnel_info['name']} 失败: {str(content)}")

            self.load_tunnels()  # 刷新隧道列表
            QMessageBox.information(self, "成功", "批量编辑完成")

    def setup_user_info_page(self):
        user_info_widget = QWidget()
        layout = QVBoxLayout(user_info_widget)

        title_label = QLabel("用户信息")
        title_label.setStyleSheet("font-size: 18px; font-weight: bold; margin-bottom: 10px;")
        layout.addWidget(title_label)

        self.username_input = QLineEdit(self)
        self.username_input.setPlaceholderText('用户名/邮箱')
        self.password_input = QLineEdit(self)
        self.password_input.setPlaceholderText('密码')
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.token_input = QLineEdit(self)
        self.token_input.setPlaceholderText('Token (可选 仅填时为token登录)')
        self.token_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.login_button = QPushButton('登录', self)
        self.login_button.clicked.connect(self.login)
        self.logout_button = QPushButton('退出登录', self)
        self.logout_button.clicked.connect(self.logout)
        self.logout_button.setEnabled(False)

        layout.addWidget(self.username_input)
        layout.addWidget(self.password_input)
        layout.addWidget(self.token_input)
        layout.addWidget(self.login_button)
        layout.addWidget(self.logout_button)

        self.user_info_display = QTextEdit()
        self.user_info_display.setReadOnly(True)
        layout.addWidget(self.user_info_display)

        layout.addStretch(1)

        self.content_stack.addWidget(user_info_widget)

    def on_tunnel_clicked(self, tunnel_info, is_selected):
        if is_selected:
            if tunnel_info not in self.selected_tunnels:
                self.selected_tunnels.append(tunnel_info)
        else:
            self.selected_tunnels = [t for t in self.selected_tunnels if t['id'] != tunnel_info['id']]

        self.update_tunnel_buttons()

    def update_tunnel_buttons(self):
        selected_count = len(self.selected_tunnels)
        self.edit_tunnel_button.setEnabled(selected_count == 1)
        self.delete_tunnel_button.setEnabled(selected_count > 0)
        self.batch_edit_button.setEnabled(selected_count > 0)
        self.view_output_button.setEnabled(selected_count == 1)

    def get_selected_tunnel_count(self):
        count = 0
        layout = self.tunnel_container.layout()
        for i in range(layout.rowCount()):
            for j in range(layout.columnCount()):
                item = layout.itemAtPosition(i, j)
                if item and isinstance(item.widget(), TunnelCard) and item.widget().is_selected:
                    count += 1
        return count

    def on_domain_clicked(self, domain_info):
        for i in range(self.domain_container.layout().count()):
            item = self.domain_container.layout().itemAt(i)
            if item.widget():
                item.widget().setSelected(False)
        self.sender().setSelected(True)
        self.selected_domain = domain_info
        self.edit_domain_button.setEnabled(True)
        self.delete_domain_button.setEnabled(True)

    def setup_tunnel_page(self):
        tunnel_widget = QWidget()
        layout = QVBoxLayout(tunnel_widget)

        # 添加刷新按钮
        button_layout = QHBoxLayout()
        refresh_button = QPushButton("刷新隧道列表")
        refresh_button.clicked.connect(self.load_tunnels)
        button_layout.addWidget(refresh_button)

        # 添加清除frpc进程按钮
        clear_frpc_button = QPushButton("清除frpc进程")
        clear_frpc_button.clicked.connect(self.clear_frpc_processes)
        button_layout.addWidget(clear_frpc_button)

        layout.addLayout(button_layout)

        self.tunnel_container = QWidget()
        self.tunnel_container.setLayout(QGridLayout())

        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setWidget(self.tunnel_container)

        layout.addWidget(scroll_area)

        button_layout = QHBoxLayout()
        add_tunnel_button = QPushButton("添加隧道")
        add_tunnel_button.clicked.connect(self.add_tunnel)
        self.edit_tunnel_button = QPushButton("编辑隧道")
        self.edit_tunnel_button.clicked.connect(self.edit_tunnel)
        self.edit_tunnel_button.setEnabled(False)
        self.delete_tunnel_button = QPushButton("删除隧道")
        self.delete_tunnel_button.clicked.connect(self.delete_tunnel)
        self.delete_tunnel_button.setEnabled(False)
        self.batch_edit_button = QPushButton("批量编辑")
        self.batch_edit_button.clicked.connect(self.batch_edit_tunnels)
        self.batch_edit_button.setEnabled(False)

        self.view_output_button = QPushButton("查看输出")
        self.view_output_button.clicked.connect(self.view_output)
        self.view_output_button.setEnabled(False)

        button_layout.addWidget(add_tunnel_button)
        button_layout.addWidget(self.edit_tunnel_button)
        button_layout.addWidget(self.delete_tunnel_button)
        button_layout.addWidget(self.batch_edit_button)
        button_layout.addWidget(self.view_output_button)

        layout.addLayout(button_layout)

        self.content_stack.addWidget(tunnel_widget)

    def create_tunnel_dialog(self, tunnel_info=None):
        """创建或编辑隧道的对话框"""
        dialog = QDialog(self)
        dialog.setWindowTitle("编辑隧道" if tunnel_info else "添加隧道")
        dialog.setFixedWidth(750)
        layout = QHBoxLayout(dialog)

        form_layout = QFormLayout()
        detail_layout = QVBoxLayout()

        # 初始化表单控件并预填数据
        name_input = QLineEdit(tunnel_info['name'] if tunnel_info else '')
        name_input.setPlaceholderText("若留空则随机")

        local_ip_input = QLineEdit(tunnel_info['localip'] if tunnel_info else '127.0.0.1')
        local_port_input = QLineEdit(str(tunnel_info['nport']) if tunnel_info else '')
        remote_port_input = QLineEdit(str(tunnel_info['dorp']) if tunnel_info else '')
        remote_port_input.setPlaceholderText("若留空则随机(10000-65535)")

        banddomain = ''
        if tunnel_info and tunnel_info['type'] in ['http', 'https']:
            banddomain = tunnel_info.get('dorp', '')
        banddomain_input = QLineEdit(banddomain)

        extra_params_input = QLineEdit(tunnel_info.get('ap', '') if tunnel_info else '')
        extra_params_input.setPlaceholderText("额外参数（可选）")

        node_combo = QComboBox()
        type_combo = QComboBox()
        type_combo.addItems(["tcp", "udp", "http", "https"])

        encryption_checkbox = QCheckBox("开启加密")
        compression_checkbox = QCheckBox("开启压缩")

        # API选择
        api_version_group = QGroupBox("API版本选择")
        api_layout = QVBoxLayout()
        v2_api_radio = QRadioButton("V2 API")
        v1_api_radio = QRadioButton("V1 API（部分参数可能无法修改）")
        api_layout.addWidget(v2_api_radio)
        api_layout.addWidget(v1_api_radio)
        api_version_group.setLayout(api_layout)
        v2_api_radio.setChecked(True)  # 默认选择V2

        # 强制修改选项
        force_update_checkbox = QCheckBox("强制修改（删除后重建）")
        force_update_note = QLabel("注意：强制修改会先删除原隧道再创建新隧道，隧道ID会变更，且可能失败")
        force_update_note.setStyleSheet("color: red; font-size: 10px;")
        force_update_note.setWordWrap(True)

        # 设置复选框状态
        if tunnel_info:
            encryption_checkbox.setChecked(bool(tunnel_info.get("encryption", False)))
            compression_checkbox.setChecked(bool(tunnel_info.get("compression", False)))
            type_combo.setCurrentText(tunnel_info['type'])

        # 获取节点列表并设置当前选中项
        nodes = API.get_nodes()
        for node in nodes:
            node_combo.addItem(node['name'])
        if tunnel_info:
            node_combo.setCurrentText(tunnel_info['node'])

        remote_port_label = QLabel("远程端口:")
        banddomain_label = QLabel("绑定域名:")

        # 添加到表单布局
        form_layout.addRow("隧道名称:", name_input)
        form_layout.addRow("本地IP/主机名:", local_ip_input)
        form_layout.addRow("本地端口:", local_port_input)
        form_layout.addRow(remote_port_label, remote_port_input)
        form_layout.addRow(banddomain_label, banddomain_input)
        form_layout.addRow("节点:", node_combo)
        form_layout.addRow("类型:", type_combo)
        form_layout.addRow(encryption_checkbox)
        form_layout.addRow(compression_checkbox)
        form_layout.addRow("额外参数:", extra_params_input)
        if tunnel_info:
            form_layout.addRow(api_version_group)
            form_layout.addRow(force_update_checkbox)
            form_layout.addRow(force_update_note)

        # 节点详情显示
        detail_label = QLabel("节点详细信息")
        detail_text = QTextEdit()
        detail_text.setReadOnly(True)
        detail_layout.addWidget(detail_label)
        detail_layout.addWidget(detail_text)

        def on_node_changed(index):
            node_name = node_combo.itemText(index)
            for node in nodes:
                if node['name'] == node_name:
                    detail_text.setPlainText(f"""
    节点名称: {node['name']}
    节点地址: {node['area']}
    权限组: {node['nodegroup']}
    是否属于大陆带宽节点: {'是' if node['china'] == 'true' else '否'}
    是否支持web: {'支持' if node['web'] == 'true' else '不支持'}
    是否支持udp: {'支持' if node['udp'] == 'true' else '不支持'} 
    是否有防御: {'有' if node['fangyu'] == 'true' else '无'}
    节点介绍: {node['notes']}
    """)
                    break

        def on_type_changed():
            port_type = type_combo.currentText()
            if port_type in ["tcp", "udp"]:
                remote_port_label.show()
                remote_port_input.show()
                banddomain_label.hide()
                banddomain_input.hide()
            else:
                remote_port_label.hide()
                remote_port_input.hide()
                banddomain_label.show()
                banddomain_input.show()
            dialog.adjustSize()

        node_combo.currentIndexChanged.connect(on_node_changed)
        type_combo.currentTextChanged.connect(on_type_changed)

        # 初始化显示
        on_type_changed()
        on_node_changed(node_combo.currentIndex())

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        form_layout.addRow(buttons)

        layout.addLayout(form_layout)
        layout.addLayout(detail_layout)

        if dialog.exec() == QDialog.DialogCode.Accepted:
            try:
                # 收集表单数据
                port_type = type_combo.currentText()
                remote_port = remote_port_input.text() or str(random.randint(10000, 65535))
                tunnel_name = name_input.text() or ''.join(
                    random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=8))

                payload = {
                    "token": self.token,
                    "tunnelname": tunnel_name,
                    "node": node_combo.currentText(),
                    "localip": local_ip_input.text(),
                    "porttype": port_type,
                    "localport": int(local_port_input.text()),
                    "encryption": encryption_checkbox.isChecked(),
                    "compression": compression_checkbox.isChecked(),
                    "extraparams": extra_params_input.text() or ""
                }

                # 根据类型设置端口或域名
                if port_type in ["tcp", "udp"]:
                    if not enter_inspector.validate_port(remote_port,False):
                        raise ValueError("远程端口必须是10000-65535之间的整数")
                    payload["remoteport"] = int(remote_port)
                elif port_type in ["http", "https"]:
                    if not banddomain_input.text():
                        raise ValueError("绑定域名是必须的")
                    payload["banddomain"] = banddomain_input.text()

                headers = get_headers(request_json=True)

                if tunnel_info:
                    # 获取用户信息（用于V1 API）
                    user_info_response = requests.get(f"http://cf-v2.uapis.cn/userinfo?token={self.token}")
                    if user_info_response.status_code == 200:
                        user_data = user_info_response.json()
                        if user_data["code"] == 200:
                            user_id = user_data["data"]["id"]
                            user_token = user_data["data"]["usertoken"]
                        else:
                            raise Exception("获取用户信息失败")
                    else:
                        raise Exception("获取用户信息请求失败")

                    # 处理强制修改逻辑
                    if force_update_checkbox.isChecked():
                        reply = QMessageBox.warning(
                            dialog,
                            "确认强制修改",
                            "强制修改将删除原隧道并创建新隧道，此操作不可逆且可能失败。是否继续？",
                            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                            QMessageBox.StandardButton.No
                        )

                        if reply == QMessageBox.StandardButton.Yes:
                            # 先删除原隧道
                            delete_success = False
                            try:
                                # 尝试使用V2 API删除
                                v2_url = "http://cf-v2.uapis.cn/deletetunnel"
                                delete_params = {"token": self.token, "tunnelid": tunnel_info["id"]}
                                v2_response = requests.post(v2_url, headers=headers, params=delete_params)
                                if v2_response.status_code == 200:
                                    delete_success = True
                                else:
                                    # 尝试使用V1 API删除
                                    v1_url = "http://cf-v1.uapis.cn/api/deletetl.php"
                                    v1_params = {
                                        "token": user_token,
                                        "userid": user_id,
                                        "nodeid": tunnel_info["id"],
                                    }
                                    v1_response = requests.get(v1_url, params=v1_params, headers=headers)
                                    if v1_response.status_code == 200:
                                        delete_success = True

                            except Exception as e:
                                raise Exception(f"删除原隧道失败: {str(e)}")

                            if not delete_success:
                                raise Exception("无法删除原隧道")

                            # 创建新隧道
                            time.sleep(1)  # 等待删除操作完成
                            create_url = "http://cf-v2.uapis.cn/create_tunnel"
                            response = requests.post(create_url, headers=headers, json=payload)
                            return response.json()
                        else:
                            return None
                    else:
                        # 常规修改逻辑
                        payload["tunnelid"] = tunnel_info["id"]

                        # 根据选择的API版本执行更新
                        if v1_api_radio.isChecked():
                            # 使用V1 API
                            v1_url = "http://cf-v1.uapis.cn/api/cztunnel.php"
                            v1_params = {
                                "usertoken": user_token,
                                "userid": user_id,
                                "tunnelid": tunnel_info["id"],
                                "type": payload["porttype"],
                                "node": payload["node"],
                                "name": payload["tunnelname"],
                                "ap": payload.get("extraparams", ""),
                                "dorp": str(payload.get("remoteport", payload.get("banddomain", ""))),
                                "localip": payload["localip"],
                                "encryption": encryption_checkbox.isChecked(),
                                "compression": compression_checkbox.isChecked(),
                                "nport": str(payload["localport"])
                            }
                            response = requests.get(v1_url, params=v1_params, headers=headers)
                            response_content = response.text
                            try:
                                return {"code": 200,
                                        "msg": response_content} if "success" in response_content.lower() else {
                                    "code": 400, "msg": response_content}
                            except Exception as content:
                                self.logger.error(f"解析V1 API响应时出错: {str(content)}")
                                return {"code": 500, "msg": str(content)}
                        else:
                            # 使用V2 API
                            url = "http://cf-v2.uapis.cn/update_tunnel"
                            response = requests.post(url, headers=headers, json=payload)

                        return response.json()
                else:
                    # 创建新隧道只使用V2 API
                    url = "http://cf-v2.uapis.cn/create_tunnel"
                    response = requests.post(url, headers=headers, json=payload)
                    return response.json()

            except ValueError as ve:
                raise ve
            except Exception as e:
                raise Exception(f"{'更新' if tunnel_info else '创建'}隧道失败: {str(e)}")

        return None

    def clear_frpc_processes(self):
        reply = QMessageBox.question(self, '确认清除frpc进程',
                                     "您确定要清除所有frpc.exe进程吗？",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            reply = QMessageBox.question(self, '再次确认清除frpc进程',
                                         "这将会终止所有frpc.exe进程，您确保所有都准备好了吗？",
                                         QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if reply == QMessageBox.StandardButton.Yes:
                try:
                    subprocess.run(['taskkill', '/f', '/im', 'frpc.exe'], check=True)
                    self.logger.info("所有frpc.exe进程已被清除")
                except subprocess.CalledProcessError:
                    self.logger.info(f"没有找到frpc进程")

    def view_output(self):
        if not self.selected_tunnels:
            QMessageBox.warning(self, "警告", "请先选择一个隧道")
            return

        for tunnel_info in self.selected_tunnels:
            tunnel_name = tunnel_info['name']

            try:
                with QMutexLocker(self.output_mutex):
                    if tunnel_name not in self.tunnel_outputs:
                        QMessageBox.information(self, "提示", "这个隧道还没启动过哦！")
                        continue

                    # 创建新的对话框或显示现有对话框
                    if not self.tunnel_outputs[tunnel_name]['dialog']:
                        self.tunnel_outputs[tunnel_name]['dialog'] = OutputDialog(self)

                    # 更新并显示对话框
                    dialog = self.tunnel_outputs[tunnel_name]['dialog']
                    output_text = self.tunnel_outputs[tunnel_name]['output'].replace('\n', '<br>')
                    dialog.add_output(tunnel_name, output_text,
                                      self.tunnel_outputs[tunnel_name]['run_number'])
                    dialog.show()
                    dialog.raise_()
                    dialog.activateWindow()

            except Exception as content:
                self.logger.error(f"显示输出对话框时发生错误: {str(content)}")
                QMessageBox.warning(self, "错误", f"显示输出时发生错误: {str(content)}")

    def setup_domain_page(self):
        domain_widget = QWidget()
        layout = QVBoxLayout(domain_widget)

        # 添加刷新按钮
        refresh_button = QPushButton("刷新域名列表")
        refresh_button.clicked.connect(self.load_domains)
        layout.addWidget(refresh_button)

        refresh_button = QPushButton("刷新域名列表")
        refresh_button.setObjectName("refreshButton")

        self.domain_container = QWidget()
        self.domain_container.setLayout(QGridLayout())

        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setWidget(self.domain_container)

        layout.addWidget(scroll_area)

        button_layout = QHBoxLayout()
        add_domain_button = QPushButton("添加域名")
        add_domain_button.clicked.connect(self.add_domain)
        self.edit_domain_button = QPushButton("编辑域名")
        self.edit_domain_button.clicked.connect(self.edit_domain)
        self.edit_domain_button.setEnabled(False)
        self.delete_domain_button = QPushButton("删除域名")
        self.delete_domain_button.clicked.connect(self.delete_domain)
        self.delete_domain_button.setEnabled(False)
        button_layout.addWidget(add_domain_button)
        button_layout.addWidget(self.edit_domain_button)
        button_layout.addWidget(self.delete_domain_button)

        layout.addLayout(button_layout)

        self.content_stack.addWidget(domain_widget)

    def setup_node_page(self):
        node_widget = QWidget()
        layout = QVBoxLayout(node_widget)

        self.node_container = QWidget()
        self.node_container.setLayout(QGridLayout())

        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setWidget(self.node_container)

        layout.addWidget(scroll_area)

        button_layout = QHBoxLayout()

        self.refresh_button = QPushButton("刷新节点状态")
        self.refresh_button.clicked.connect(self.refresh_nodes)
        button_layout.addWidget(self.refresh_button)

        self.details_button = QPushButton("查看详细信息")
        self.details_button.clicked.connect(self.show_node_details)
        self.details_button.setEnabled(False)
        button_layout.addWidget(self.details_button)

        self.uptime_button = QPushButton("查看在线率")
        self.uptime_button.clicked.connect(self.show_node_uptime)
        self.uptime_button.setEnabled(False)
        button_layout.addWidget(self.uptime_button)

        layout.addLayout(button_layout)

        self.content_stack.addWidget(node_widget)

    def show_node_uptime(self):
        if not hasattr(self, 'selected_node'):
            QMessageBox.warning(self, "警告", "请先选择一个节点")
            return

        dialog = QDialog(self)
        dialog.setWindowTitle("节点在线率")
        dialog.setMinimumWidth(400)
        layout = QVBoxLayout(dialog)

        # 时间输入框
        time_layout = QHBoxLayout()
        time_input = QLineEdit()
        time_input.setPlaceholderText("输入天数(1-90)")
        time_input.setValidator(QIntValidator(1, 90))
        time_layout.addWidget(QLabel("查询天数:"))
        time_layout.addWidget(time_input)
        layout.addLayout(time_layout)

        # 结果显示区域
        result_text = QTextEdit()
        result_text.setReadOnly(True)
        layout.addWidget(result_text)

        def query_uptime():
            try:
                days = int(time_input.text())
                if not 1 <= days <= 90:
                    raise ValueError("天数必须在1-90之间")

                url = "http://cf-v2.uapis.cn/node_uptime"
                params = {
                    "time": days,
                    "node": self.selected_node['node_name']
                }
                headers = get_headers()
                response = requests.get(url, headers=headers, params=params)
                data = response.json()

                if data['code'] == 200:
                    node_data = data['data'][0]
                    history = node_data['history_uptime']

                    # 基本信息
                    result = f"节点: {node_data['node_name']}\n"
                    result += f"节点组: {node_data['group']}\n"
                    result += f"当前状态: {'在线' if node_data['state'] == 'online' else '离线'}\n"

                    # 计算并显示平均在线率
                    avg_uptime = sum(record['uptime'] for record in history) / len(history)
                    result += f"平均在线率: {avg_uptime:.2f}%\n\n"

                    # 历史在线率记录
                    result += "历史在线率:\n"
                    for record in history:
                        result += f"{record['recorded_at']}: {record['uptime']}%\n"

                    result_text.setPlainText(result)
                else:
                    result_text.setPlainText(f"获取数据失败: {data.get('msg', '未知错误')}")

            except ValueError as ve:
                result_text.setPlainText(f"输入错误: {str(ve)}")
            except Exception as e:
                result_text.setPlainText(f"查询失败: {str(e)}")

        # 查询按钮
        query_button = QPushButton("让我看看")
        query_button.clicked.connect(query_uptime)
        layout.addWidget(query_button)

        # 关闭按钮
        close_button = QPushButton("看好啦")
        close_button.clicked.connect(dialog.close)
        layout.addWidget(close_button)

        dialog.exec()

    def load_credentials(self):
        """从注册表加载凭证"""
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"SOFTWARE\ChmlFrp", 0, winreg.KEY_READ)
            username = winreg.QueryValueEx(key, "username")[0]
            password = winreg.QueryValueEx(key, "password")[0]
            token = winreg.QueryValueEx(key, "token")[0]
            winreg.CloseKey(key)
            self.username_input.setText(username)
            self.password_input.setText(password)
            self.token_input.setText(token)
        except FileNotFoundError:
            # 注册表项不存在，忽略
            pass
        except PermissionError:
            self.logger.error("权限不足，无法读取注册表。请以管理员身份运行程序。")
            QMessageBox.critical(self, "错误", "需要管理员权限读取凭证！")
        except Exception as e:
            self.logger.error(f"从注册表加载凭证失败: {str(e)}")

    def save_credentials(self):
        """保存凭证到注册表"""
        try:
            # 需要管理员权限写入HKEY_CURRENT_USER
            key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"SOFTWARE\ChmlFrp")
            winreg.SetValueEx(key, "username", 0, winreg.REG_SZ, self.username_input.text())
            winreg.SetValueEx(key, "password", 0, winreg.REG_SZ, self.password_input.text())
            winreg.SetValueEx(key, "token", 0, winreg.REG_SZ, self.token_input.text())
            winreg.CloseKey(key)
        except PermissionError:
            self.logger.error("权限不足，无法写入注册表。请以管理员身份运行程序。")
            QMessageBox.critical(self, "错误", "需要管理员权限保存凭证！")
        except Exception as e:
            self.logger.error(f"保存凭证到注册表失败: {str(e)}")
            QMessageBox.warning(self, "错误", f"保存凭证失败: {str(e)}")

    def auto_login(self):
        """自动登录"""
        if self.token_input.text():
            self.token = self.token_input.text()
            self.logger.info("使用保存的Token自动登录")
            self.login_success()
        elif self.username_input.text() and self.password_input.text():

            self.token = API.login(self.username_input.text(), self.password_input.text()).get("data", {}).get("usertoken")
            if self.token:
                logger.info("登录成功")
            else:
                logger.warning("登录失败")

            if self.token:
                self.login_success()
            else:
                self.logger.warning("自动登录失败，请手动登录")

    def login(self):
        """登录功能"""
        user_token = self.token_input.text()
        if user_token:
            try:
                data = API.userinfo(user_token)
                if data['code'] == 200:
                    self.token = user_token
                else:
                    self.logger.error(f"Token登录失败: {data.get('msg', '未知错误')}")
                    QMessageBox.warning(self, "登录失败", f"Token登录失败: {data.get('msg', '未知错误')}")
                    return
            except Exception as content:
                self.logger.error(f"Token验证失败: {str(content)}")
                QMessageBox.warning(self, "登录失败", f"Token验证失败: {str(content)}")
                return
        else:
            try:
                data = API.login(self.username_input.text(), self.password_input.text())

                if data['code'] == 200:
                    self.token = data['data']['usertoken']
                else:
                    self.logger.error(f"登录失败: {data.get('msg', '未知错误')}")
                    QMessageBox.warning(self, "登录失败", f"登录失败: {data.get('msg', '未知错误')}")
                    return
            except Exception as content:
                self.logger.error(f"登录请求失败: {str(content)}")
                QMessageBox.warning(self, "登录失败", f"登录请求失败: {str(content)}")
                return

        if self.token:
            self.logger.info("登录成功")
            self.save_credentials()
            self.login_success()

    def login_success(self):
        """登录成功后的操作"""
        try:
            # 验证token是否有效
            data = API.userinfo(self.token)
            if data['code'] != 200:
                # token无效,执行登出操作
                self.logger.error(f"Token无效: {data.get('msg', '未知错误')}")
                self.logout()
                QMessageBox.warning(self, "登录失败", f"Token无效: {data.get('msg', '未知错误')}")
                return

            time.sleep(1)  # 等待1秒
            # Token有效,继续后续操作
            self.login_button.setEnabled(False)
            self.logout_button.setEnabled(True)
            self.username_input.setEnabled(False)
            self.password_input.setEnabled(False)
            self.token_input.setEnabled(False)
            self.load_user_data()
            self.auto_start_tunnels()
        except Exception as content:
            self.logger.error(f"登录成功后操作失败: {str(content)}")
            self.logger.error(traceback.format_exc())
            QMessageBox.warning(self, "错误", f"登录成功，但加载数据失败: {str(content)}")
            self.logout()

    def logout(self):
        """退出登录"""
        # 停止所有使用token的操作
        self.stop_all_api_operations()

        self.token = None
        self.login_button.setEnabled(True)
        self.logout_button.setEnabled(False)
        self.username_input.setEnabled(True)
        self.password_input.setEnabled(True)
        self.token_input.setEnabled(True)
        self.username_input.clear()
        self.password_input.clear()
        self.token_input.clear()

        # 删除注册表项中的凭证
        try:
            # 需要管理员权限删除注册表项
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"SOFTWARE\ChmlFrp", 0, winreg.KEY_WRITE)
            try:
                winreg.DeleteValue(key, "username")
            except WindowsError:
                pass
            try:
                winreg.DeleteValue(key, "password")
            except WindowsError:
                pass
            try:
                winreg.DeleteValue(key, "token")
            except WindowsError:
                pass
            winreg.CloseKey(key)
        except PermissionError:
            self.logger.error("权限不足，无法删除注册表项")
            QMessageBox.critical(self, "错误", "需要管理员权限清除凭证！")
        except FileNotFoundError:
            pass  # 如果注册表项不存在则忽略
        except Exception as e:
            self.logger.error(f"清除注册表凭证失败: {str(e)}")

        self.clear_user_data()
        self.logger.info("已退出登录")

    def stop_all_api_operations(self):
        """停止所有使用token的API操作"""
        try:
            for tunnel_name in list(self.tunnel_processes.keys()):
                self.stop_tunnel({"name": tunnel_name})

            QApplication.processEvents()
        except Exception as content:
            self.logger.error(f"停止API操作时发生错误: {str(content)}")

    def load_user_data(self):
        """加载用户数据"""
        try:
            self.user_info = API.userinfo(self.token)['data']
            self.load_tunnels()
            self.load_domains()
            self.load_nodes()
            self.display_user_info()
        except Exception as content:
            self.logger.error(f"加载用户数据时发生错误: {str(content)}")
            self.logger.error(traceback.format_exc())
            self.show_error_message(f"加载用户数据时发生错误: {str(content)}")

    def display_user_info(self):
        if self.user_info['term'] == "9999-09-09":
            self.user_info['term'] = "永久有效"
        """显示用户信息"""
        if self.user_info:
            info_text = f"""
		ID: {self.user_info['id']}
		用户名: {self.user_info['username']}
		注册时间: {self.user_info['regtime']}
		邮箱: {self.user_info['email']}
		实名状态: {self.user_info['realname']}
		用户组: {self.user_info['usergroup']}
		国内带宽: {self.user_info['bandwidth']} Mbps
		国外带宽: {int(self.user_info['bandwidth']) * 4} Mbps
		隧道数量: {self.user_info['tunnelCount']} / {self.user_info['tunnel']}
		积分: {self.user_info['integral']}
		到期时间: {self.user_info['term']}
		上传数据: {self.user_info['total_upload']/1024/1024:.2f}MB
		下载数据: {self.user_info['total_download']/1024/1024:.2f}MB
			"""
            self.user_info_display.setPlainText(info_text)
        else:
            self.user_info_display.setPlainText("无法获取用户信息")

    def clear_all_selections(self):
        layout = self.tunnel_container.layout()
        for i in range(layout.rowCount()):
            for j in range(layout.columnCount()):
                item = layout.itemAtPosition(i, j)
                if item and isinstance(item.widget(), TunnelCard):
                    item.widget().is_selected = False
                    item.widget().setSelected(False)

    def load_tunnels(self):
        """加载隧道列表"""
        try:
            if not self.token:
                self.show_error_message("未登录，无法加载隧道列表")
                return

            tunnels = API.get_user_tunnels(self.token)
            if tunnels is None:
                return

            # 清除现有的隧道卡片
            while self.tunnel_container.layout().count():
                item = self.tunnel_container.layout().takeAt(0)
                if item.widget():
                    item.widget().deleteLater()

            if not tunnels:  # 如果隧道列表为空
                self.logger.info("当前没有隧道哦！快点去创建吧！")
                return  # 直接返回，不显示错误

            selected_ids = [t['id'] for t in self.selected_tunnels]

            row, col = 0, 0
            for tunnel in tunnels:
                try:
                    tunnel_widget = TunnelCard(tunnel, self.token)
                    tunnel_widget.clicked.connect(self.on_tunnel_clicked)
                    tunnel_widget.start_stop_signal.connect(self.start_stop_tunnel)

                    if tunnel['id'] in selected_ids:
                        tunnel_widget.is_selected = True
                        tunnel_widget.setSelected(True)

                    self.tunnel_container.layout().addWidget(tunnel_widget, row, col)

                    col += 1
                    if col == 2:  # 每行两个卡片
                        col = 0
                        row += 1

                except Exception as content:
                    self.logger.error(f"创建隧道卡片时发生错误: {str(content)}")
                    self.logger.error(traceback.format_exc())
                    continue

            self.selected_tunnels = [t for t in tunnels if t['id'] in selected_ids]
            self.update_tunnel_buttons()

        except Exception as content:
            self.logger.error(f"加载隧道列表时发生错误: {str(content)}")
            self.logger.error(traceback.format_exc())
            self.show_error_message(f"加载隧道列表时发生错误: {str(content)}")

    @staticmethod
    def clear_error_message(widget):
        """清除错误消息"""
        if isinstance(widget, QListWidget):
            for i in range(widget.count()):
                item = widget.item(i)
                if item.data(Qt.ItemDataRole.UserRole) == "error_message":
                    widget.takeItem(i)
                    break

    def show_error_message(self, message, widget=None):
        QMessageBox.warning(self, "错误", message)
        if widget and isinstance(widget, QListWidget):
            self.clear_error_message(widget)
            error_item = QListWidgetItem(message)
            error_item.setData(Qt.ItemDataRole.UserRole, "error_message")
            error_item.setForeground(Qt.GlobalColor.red)
            widget.addItem(error_item)

    def load_domains(self):
        """加载域名列表"""
        try:
            if not self.token:
                raise ValueError("未登录，无法加载域名列表")

            url = f"http://cf-v2.uapis.cn/get_user_free_subdomains"
            params = {
                "token": self.token
            }
            headers = get_headers()
            response = requests.get(url, headers=headers, params=params)
            response.raise_for_status()
            data = response.json()
            if data['code'] != 200:
                raise ValueError(data.get('msg'))

            domains = data['data']

            # 清除现有的域名卡片
            while self.domain_container.layout().count():
                item = self.domain_container.layout().takeAt(0)
                if item.widget():
                    item.widget().deleteLater()

            row, col = 0, 0
            for domain in domains:
                try:
                    domain_widget = DomainCard(domain)
                    domain_widget.clicked.connect(self.on_domain_clicked)
                    self.domain_container.layout().addWidget(domain_widget, row, col)

                    col += 1
                    if col == 2:  # 每行两个卡片
                        col = 0
                        row += 1

                except Exception as content:
                    self.logger.error(f"创建域名卡片时发生错误: {str(content)}")
                    self.logger.error(traceback.format_exc())
                    continue
        except Exception as content:
            self.logger.error(f"获取域名列表时发生错误: {str(content)}")
            self.logger.error(traceback.format_exc())
            self.show_error_message(self.domain_container, f"获取域名列表时发生错误: {str(content)}")

    def load_nodes(self):
        """加载节点列表"""
        try:
            nodes = API.is_node_online(tyen="all")['data']
            # 清除现有的节点卡片
            while self.node_container.layout().count():
                item = self.node_container.layout().takeAt(0)
                if item.widget():
                    item.widget().deleteLater()

            row, col = 0, 0
            for node in nodes:
                try:
                    node_widget = NodeCard(node)
                    node_widget.clicked.connect(self.on_node_clicked)
                    self.node_container.layout().addWidget(node_widget, row, col)

                    col += 1
                    if col == 2:  # 每行两个卡片
                        col = 0
                        row += 1

                except Exception as content:
                    self.logger.error(f"创建节点卡片时发生错误: {str(content)}")
                    continue

        except Exception as content:
            self.logger.error(f"获取节点列表时发生错误: {str(content)}")
            self.show_error_message(self.node_container, f"获取节点列表时发生错误: {str(content)}")

    def on_node_clicked(self, node_info):
        for i in range(self.node_container.layout().count()):
            item = self.node_container.layout().itemAt(i)
            if item.widget():
                item.widget().setSelected(False)
        self.sender().setSelected(True)
        self.selected_node = node_info
        self.details_button.setEnabled(True)
        self.uptime_button.setEnabled(True)

    def show_node_details(self):
        if hasattr(self, 'selected_node'):
            details = self.format_node_details(self.selected_node)
            QMessageBox.information(self, "节点详细信息", details)
        else:
            QMessageBox.warning(self, "警告", "请先选择一个节点")

    def format_node_details(self, node_info):
        details = f"""节点名称: {node_info.get('node_name', 'N/A')}
状态: {'在线' if node_info.get('state') == 'online' else '离线'}
节点组: {node_info.get('nodegroup', 'N/A')}
是否允许udp: {'允许' if node_info.get('udp') == 'true' else '不允许'}
是否有防御: {'有' if node_info.get('fangyu') == 'true' else '无'}
是否允许建站: {'允许' if node_info.get('web') == 'true' else '不允许'}
是否需要过白: {'需要' if node_info.get('toowhite') == 'true' else '不需要'}
带宽使用率: {node_info.get('bandwidth_usage_percent', 'N/A')}%
CPU使用率: {node_info.get('cpu_usage', 'N/A')}%
当前连接数: {node_info.get('cur_counts', 'N/A')}
客户端数量: {node_info.get('client_counts', 'N/A')}
总流入流量: {self.format_traffic(node_info.get('total_traffic_in', 0))}
总流出流量: {self.format_traffic(node_info.get('total_traffic_out', 0))}"""
        return details

    def start_stop_tunnel(self, tunnel_info, start):
        if start:
            self.start_tunnel(tunnel_info)
        else:
            self.stop_tunnel(tunnel_info)

        # 更新隧道卡片状态
        self.update_tunnel_card_status(tunnel_info['name'], start)

    def start_tunnel(self, tunnel_info):
        try:
            # 检查节点状态
            if not API.is_node_online(tunnel_info['node'], tyen="online"):
                QMessageBox.warning(self, "警告", f"节点 {tunnel_info['node']} 当前不在线")
                return

            with self.process_lock:
                # 检查隧道是否已启动
                if tunnel_info['name'] in self.tunnel_processes:
                    self.logger.warning(f"隧道 {tunnel_info['name']} 已在运行")
                    return

                try:
                    frpc_path = get_absolute_path("frpc.exe")
                    cmd = [
                        frpc_path,
                        "-u", self.token,
                        "-p", str(tunnel_info['id'])
                    ]

                    process = subprocess.Popen(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        creationflags=subprocess.CREATE_NO_WINDOW
                    )

                    self.tunnel_processes[tunnel_info['name']] = process
                    self.logger.info(f"隧道 {tunnel_info['name']} 启动成功")

                    # 启动输出捕获
                    self.capture_output(tunnel_info['name'], process)

                    # 更新UI状态
                    self.update_tunnel_card_status(tunnel_info['name'], True)

                    # 启动状态检查
                    QTimer.singleShot(100, lambda: self.check_tunnel_status(tunnel_info['name']))

                except Exception as e:
                    self.logger.error(f"启动隧道失败: {str(e)}")
                    raise

        except Exception as e:
            self.logger.error(f"启动隧道时发生错误: {str(e)}")
            QMessageBox.warning(self, "错误", f"启动隧道失败: {str(e)}")

    def obfuscate_sensitive_data(self, text):
        obfuscated_text = re.sub(re.escape(self.token), '*******你的token********', text, flags=re.IGNORECASE)
        obfuscated_text = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
                                 lambda x: '{}.***.***.{}'.format(x.group(0).split('.')[0], x.group(0).split('.')[-1]),
                                 obfuscated_text)
        return obfuscated_text

    @staticmethod
    def render_html(text):
        text = re.sub(r'\[I\]', '<span style="color: green;">[I]</span>', text, flags=re.IGNORECASE)
        text = re.sub(r'\[E\]', '<span style="color: red;">[E]</span>', text, flags=re.IGNORECASE)
        text = re.sub(r'\[W\]', '<span style="color: orange;">[W]</span>', text, flags=re.IGNORECASE)
        return text

    def capture_output(self, tunnel_name, process):
        def read_output(pipe, callback):
            try:
                for line in iter(pipe.readline, b''):
                    if not process.poll() is None:  # 检查进程是否已结束
                        break
                    try:
                        callback(line.decode())
                    except Exception as content:
                        self.logger.error(f"处理输出时发生错误: {str(content)}")
            except Exception as content:
                self.logger.error(f"读取输出时发生错误: {str(content)}")
            finally:
                try:
                    pipe.close()
                except Exception as content:
                    self.logger.error(f"关闭管道时发生错误: {str(content)}")


        def update_output(line):
            try:
                with QMutexLocker(self.output_mutex):
                    if tunnel_name in self.tunnel_outputs:
                        obfuscated_line = self.obfuscate_sensitive_data(line)
                        self.tunnel_outputs[tunnel_name]['output'] += self.render_html(obfuscated_line)

                        if (self.tunnel_outputs[tunnel_name]['dialog'] and
                            not self.tunnel_outputs[tunnel_name]['dialog'].isHidden()):
                            try:
                                self.tunnel_outputs[tunnel_name]['dialog'].add_output(
                                    tunnel_name,
                                    self.tunnel_outputs[tunnel_name]['output'],
                                    self.tunnel_outputs[tunnel_name]['run_number']
                                )
                            except Exception as content:
                                self.logger.error(f"更新对话框时发生错误: {str(content)}")
            except Exception as content:
                self.logger.error(f"更新输出时发生错误: {str(content)}")

        # 初始化输出互斥锁
        if not hasattr(self, 'output_mutex'):
            self.output_mutex = QMutex()

        with QMutexLocker(self.output_mutex):
            self.tunnel_outputs[tunnel_name] = {
                'output': '',
                'run_number': self.tunnel_outputs.get(tunnel_name, {}).get('run_number', 0) + 1,
                'dialog': None,
                'process': process
            }

        # 创建并启动输出读取线程
        stdout_thread = threading.Thread(target=read_output, args=(process.stdout, update_output), daemon=True)
        stderr_thread = threading.Thread(target=read_output, args=(process.stderr, update_output), daemon=True)

        stdout_thread.start()
        stderr_thread.start()

        # 启动进程监控
        monitor_thread = threading.Thread(target=self.monitor_process,
                                       args=(tunnel_name, process, stdout_thread, stderr_thread),
                                       daemon=True)
        monitor_thread.start()

    def monitor_process(self, tunnel_name, process, stdout_thread, stderr_thread):
        """监控进程状态"""
        try:
            process.wait()
            exit_code = process.poll()

            # 等待输出线程完成，设置较短的超时时间
            stdout_thread.join(timeout=3)
            stderr_thread.join(timeout=3)

            with QMutexLocker(self.output_mutex):
                if tunnel_name in self.tunnel_outputs:
                    try:
                        if exit_code not in [0, 1]:  # 排除正常退出(0)和用户终止(1)的情况
                            error_message = f"\n[E] 进程异常退出，退出代码: {exit_code}\n"
                            if exit_code == -1073741819:  # 0xC0000005
                                error_message += "[E] 进程访问违规 (可能是由于节点离线或网络问题)\n"
                            self.tunnel_outputs[tunnel_name]['output'] += self.render_html(error_message)

                            # 如果对话框正在显示，使用事件循环安全更新
                            if (self.tunnel_outputs[tunnel_name]['dialog'] and
                                    not self.tunnel_outputs[tunnel_name]['dialog'].isHidden()):
                                dialog = self.tunnel_outputs[tunnel_name]['dialog']
                                output = self.tunnel_outputs[tunnel_name]['output']
                                run_number = self.tunnel_outputs[tunnel_name]['run_number']

                                # 使用QMetaObject.invokeMethod安全地更新UI
                                QMetaObject.invokeMethod(dialog, "add_output",
                                                         Qt.ConnectionType.QueuedConnection,
                                                         Q_ARG(str, tunnel_name),
                                                         Q_ARG(str, output),
                                                         Q_ARG(int, run_number))
                    except Exception as content:
                        self.logger.error(f"处理进程输出时发生错误: {str(content)}")
                    finally:
                        # 清理进程引用
                        self.tunnel_outputs[tunnel_name]['process'] = None

            # 从运行中的隧道列表中移除
            if tunnel_name in self.tunnel_processes:
                del self.tunnel_processes[tunnel_name]

            # 安全地更新UI状态
            QMetaObject.invokeMethod(self, "update_tunnel_card_status",
                                     Qt.ConnectionType.QueuedConnection,
                                     Q_ARG(str, tunnel_name),
                                     Q_ARG(bool, False))

        except Exception as content:
            if process.poll() is None:  # 只在进程仍在运行时输出错误
                self.logger.error(f"监控进程时发生错误(frpc进程可能已退出)")
                print(content)
            # 确保进程被清理
            try:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=1)
            except:
                pass

    def update_output(self, tunnel_name, line):
        obfuscated_line = self.obfuscate_sensitive_data(line)
        self.tunnel_outputs[tunnel_name]['output'] += self.render_html(obfuscated_line)

        if self.tunnel_outputs[tunnel_name]['dialog']:
            self.tunnel_outputs[tunnel_name]['dialog'].add_output(tunnel_name,
                                                                  self.tunnel_outputs[tunnel_name]['output'],
                                                                  self.tunnel_outputs[tunnel_name]['run_number'])

    def update_tunnel_card_status(self, tunnel_name, is_running):
        for i in range(self.tunnel_container.layout().count()):
            widget = self.tunnel_container.layout().itemAt(i).widget()
            if isinstance(widget, TunnelCard) and widget.tunnel_info['name'] == tunnel_name:
                widget.is_running = is_running
                widget.update_status()
                break

    def stop_tunnel(self, tunnel_info):
        with self.process_lock:
            try:
                process = self.tunnel_processes.get(tunnel_info['name'])
                if process:
                    # 尝试正常终止进程
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        # 如果超时则强制结束
                        process.kill()
                        process.wait()

                    del self.tunnel_processes[tunnel_info['name']]
                    self.logger.info(f"隧道 {tunnel_info['name']} 已停止")

                    # 更新UI状态
                    self.update_tunnel_card_status(tunnel_info['name'], False)
                else:
                    self.logger.warning(f"未找到隧道 {tunnel_info['name']} 的运行进程")

            except Exception as e:
                self.logger.error(f"停止隧道时发生错误: {str(e)}")
                raise

    def check_tunnel_status(self, tunnel_name):
        process = self.tunnel_processes.get(tunnel_name)
        if process and process.poll() is None:
            # 进程仍在运行
            self.update_tunnel_card_status(tunnel_name, True)
            # 继续检查
            QTimer.singleShot(100, lambda: self.check_tunnel_status(tunnel_name))
        else:
            # 进程已停止
            self.update_tunnel_card_status(tunnel_name, False)
            if tunnel_name in self.tunnel_processes:
                del self.tunnel_processes[tunnel_name]

    @staticmethod
    def format_traffic(traffic_bytes):
        try:
            traffic_bytes = float(traffic_bytes)
            if traffic_bytes < 1024:
                return f"{traffic_bytes:.2f} B"
            elif traffic_bytes < 1024 * 1024:
                return f"{traffic_bytes / 1024:.2f} KB"
            elif traffic_bytes < 1024 * 1024 * 1024:
                return f"{traffic_bytes / (1024 * 1024):.2f} MB"
            else:
                return f"{traffic_bytes / (1024 * 1024 * 1024):.2f} GB"
        except (ValueError, TypeError):
            return "N/A"

    def clear_user_data(self):
        """清除用户数据"""
        try:
            # 清除隧道列表
            self.clear_layout(self.tunnel_container.layout())
            # 清除域名列表
            self.clear_layout(self.domain_container.layout())
            # 清除节点列表
            self.clear_layout(self.node_container.layout())
            # 清除用户信息显示
            self.user_info_display.clear()
            # 重置其他相关状态
            self.selected_tunnels = []
            self.selected_domain = None
            self.selected_node = None
        except Exception as content:
            self.logger.error(f"清除用户数据时发生错误: {str(content)}")

    def clear_layout(self, layout):
        """清除布局中的所有项目"""
        if layout is not None:
            while layout.count():
                item = layout.takeAt(0)
                widget = item.widget()
                if widget is not None:
                    widget.setParent(None)
                else:
                    self.clear_layout(item.layout())

    def add_tunnel(self):
        try:
            result = self.create_tunnel_dialog()
            if result:
                self.logger.info(f"信息: {result.get('msg', '无额外信息')}")
                QMessageBox.information(self, "成功", f"信息: {result.get('msg')}")
                self.load_tunnels()
        except Exception as e:
            self.logger.error(f"添加隧道失败: {str(e)}")
            QMessageBox.warning(self, "错误", str(e))

    def edit_tunnel(self):
        if not self.selected_tunnels:
            QMessageBox.warning(self, "警告", "请先选择一个隧道")
            return

        if len(self.selected_tunnels) > 1:
            QMessageBox.warning(self, "警告", "编辑隧道时只能选择一个隧道")
            return

        try:
            result = self.create_tunnel_dialog(self.selected_tunnels[0])
            if result:
                self.logger.info("隧道更新成功")
                self.load_tunnels()
        except Exception as e:
            self.logger.error(f"编辑隧道失败: {str(e)}")
            QMessageBox.warning(self, "错误", str(e))

    def delete_tunnel(self):
        """删除隧道"""
        if not self.selected_tunnels:
            QMessageBox.warning(self, "警告", "请先选择要删除的隧道")
            return

        tunnels_to_delete = self.selected_tunnels.copy()

        user_info = API.userinfo(self.token)
        user_id = user_info["data"]["id"]
        user_token = user_info["data"]["usertoken"]

        for tunnel_info in tunnels_to_delete:
            time.sleep(0.8)  # 避免频繁请求导致服务器拒绝连接
            reply = QMessageBox.question(self, '确认删除', f"确定要删除隧道 '{tunnel_info['name']}' 吗？",
                                         QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)

            if reply == QMessageBox.StandardButton.Yes:
                try:

                    url_v2 = f"http://cf-v2.uapis.cn/deletetunnel"
                    params = {"token": self.token, "tunnelid": tunnel_info["id"]}
                    headers = get_headers()
                    response = requests.post(url_v2, headers=headers, params=params)
                    if response.status_code == 200:
                        self.logger.info(f"隧道 '{tunnel_info['name']}' 删除成功 (v2 API)")
                        self.selected_tunnels.remove(tunnel_info)
                    else:
                        self.logger.error(f"v2 API 删除隧道失败")
                        raise Exception(f"v2 API 删除失败")

                except Exception:
                    self.logger.error(f"v2 API 删除失败，尝试 v1 API...")
                    try:
                        url_v1 = f"http://cf-v1.uapis.cn/api/deletetl.php"
                        params = {
                            "token": user_token,
                            "userid": user_id,
                            "nodeid": tunnel_info["id"],
                        }
                        headers = get_headers()
                        response_v1 = requests.get(url_v1, params=params, headers=headers)
                        if response_v1.status_code == 200:
                            self.logger.info(f"隧道 '{tunnel_info['name']}' 删除成功 (v1 API)")
                            self.selected_tunnels.remove(tunnel_info)  # 从选中列表中移除
                        else:
                            self.logger.error(f"v1 API 删除隧道失败: {response_v1.text}")
                            raise Exception(f"v1 API 删除失败: {response_v1.text}")
                    except Exception as e_v1:
                        self.logger.exception("删除隧道时发生错误")
                        QMessageBox.warning(self, "错误", f"删除隧道失败: {str(e_v1)}")

        self.load_tunnels()  # 刷新隧道列表
        self.update_tunnel_buttons()  # 更新按钮状态

    def add_domain(self):
        TTL_OPTIONS = [
            "1分钟", "2分钟", "5分钟", "10分钟", "15分钟", "30分钟",
            "1小时", "2小时", "5小时", "12小时", "1天"
        ]
        dialog = QDialog(self)
        dialog.setWindowTitle("添加域名")
        layout = QFormLayout(dialog)

        main_domain_combo = QComboBox()
        self.load_main_domains(main_domain_combo)
        record_input = QLineEdit()
        type_combo = QComboBox()
        type_combo.addItems(["A", "AAAA", "CNAME", "SRV"])
        target_input = QLineEdit()
        remarks = QLineEdit()
        ttl_combo = QComboBox()
        ttl_combo.addItems(TTL_OPTIONS)
        ttl_combo.setCurrentText("1分钟")

        # SRV输入
        srv_widget = QWidget()
        srv_layout = QFormLayout(srv_widget)
        priority_input = QLineEdit("10")
        weight_input = QLineEdit("10")
        port_input = QLineEdit()
        srv_layout.addRow("优先级:", priority_input)
        srv_layout.addRow("权重:", weight_input)
        srv_layout.addRow("端口:", port_input)
        srv_widget.hide()

        layout.addRow("主域名:", main_domain_combo)
        layout.addRow("子域名:", record_input)
        layout.addRow("类型:", type_combo)
        layout.addRow("目标:", target_input)
        layout.addRow("TTL:", ttl_combo)
        layout.addRow("备注:", remarks)
        layout.addRow(srv_widget)

        ttl_note = QLabel("注意：较慢的TTL可以提升解析稳定度，但会延长更新生效时间。")
        ttl_note.setWordWrap(True)
        layout.addRow(ttl_note)

        def on_type_changed():
            records_type = type_combo.currentText()
            srv_widget.setVisible(records_type == "SRV")
            if records_type == "SRV":
                target_input.setPlaceholderText("域名或IP")
            elif records_type == "CNAME":
                target_input.setPlaceholderText("目标域名")
            else:
                target_input.setPlaceholderText("IP地址")

        type_combo.currentTextChanged.connect(on_type_changed)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addRow(buttons)

        if dialog.exec() == QDialog.DialogCode.Accepted:
            record_type = type_combo.currentText()
            target = enter_inspector.remove_http_https(target_input.text().strip())

            if record_type == "A":
                if enter_inspector.is_valid_domain(target):
                    reply = QMessageBox.question(self, "域名输入",
                                                 "您输入了一个域名。您希望如何处理？yes=解析:no=切换到CNAME",
                                                 QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                                 QMessageBox.StandardButton.No)
                    if reply == QMessageBox.StandardButton.Yes:
                        # 用户选择解析为 IPv4
                        try:
                            ip = socket.gethostbyname(target)
                            if enter_inspector.is_valid_ipv4(ip):
                                target = ip
                            elif enter_inspector.is_valid_ipv6(ip):
                                ipv6_reply = QMessageBox.question(self, "IPv6 检测",
                                                                  "解析结果是 IPv6 地址。是否要切换到 AAAA 记录？",
                                                                  QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
                                if ipv6_reply == QMessageBox.StandardButton.Yes:
                                    record_type = "AAAA"
                                    target = ip
                                else:
                                    QMessageBox.warning(self, "解析失败", "无法将域名解析为 IPv4 地址")
                                    return
                            else:
                                raise Exception("解析失败")
                        except Exception:
                            cname_reply = QMessageBox.question(self, "解析失败",
                                                               "无法将域名解析为 IP 地址。是否要切换到 CNAME 记录？",
                                                               QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
                            if cname_reply == QMessageBox.StandardButton.Yes:
                                record_type = "CNAME"
                            else:
                                return
                    else:
                        # 用户选择使用 CNAME
                        record_type = "CNAME"
                elif enter_inspector.is_valid_ipv6(target):
                    reply = QMessageBox.question(self, "IPv6地址检测",
                                                 "检测到IPv6地址。是否要切换到AAAA记录？",
                                                 QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
                    if reply == QMessageBox.StandardButton.Yes:
                        record_type = "AAAA"
                    else:
                        QMessageBox.warning(self, "无效IP", "A记录必须使用IPv4地址")
                        return
                elif not enter_inspector.is_valid_ipv4(target):
                    QMessageBox.warning(self, "无效 IP", "请输入有效的 IPv4 地址")
                    return

            elif record_type == "AAAA":
                if enter_inspector.is_valid_ipv4(target):
                    reply = QMessageBox.question(self, "IPv4地址检测",
                                                 "检测到IPv4地址。是否要切换到A记录？",
                                                 QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
                    if reply == QMessageBox.StandardButton.Yes:
                        record_type = "A"
                    else:
                        QMessageBox.warning(self, "无效IP", "AAAA记录必须使用IPv6地址")
                        return
                elif enter_inspector.is_valid_domain(target):
                    reply = QMessageBox.question(self, "域名输入",
                                                 "您输入了一个域名。您希望如何处理？yes=解析:no=切换到CNAME",
                                                 QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                                 QMessageBox.StandardButton.No)
                    if reply == QMessageBox.StandardButton.Yes:
                        # 用户选择解析为 IPv6
                        try:
                            ip = socket.getaddrinfo(target, None, socket.AF_INET6)[0][4][0]
                            if enter_inspector.is_valid_ipv6(ip):
                                target = ip
                            elif enter_inspector.is_valid_ipv4(ip):
                                ipv4_reply = QMessageBox.question(self, "IPv4 检测",
                                                                  "解析结果是 IPv4 地址。是否要切换到 A 记录？",
                                                                  QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
                                if ipv4_reply == QMessageBox.StandardButton.Yes:
                                    record_type = "A"
                                    target = ip
                                else:
                                    QMessageBox.warning(self, "解析失败", "无法将域名解析为 IPv6 地址")
                                    return
                            else:
                                raise Exception("解析失败")
                        except Exception:
                            cname_reply = QMessageBox.question(self, "解析失败",
                                                               "无法将域名解析为 IP 地址。是否要切换到 CNAME 记录？",
                                                               QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
                            if cname_reply == QMessageBox.StandardButton.Yes:
                                record_type = "CNAME"
                            else:
                                return
                    else:
                        # 用户选择使用 CNAME
                        record_type = "CNAME"
                elif not enter_inspector.is_valid_ipv6(target):
                    QMessageBox.warning(self, "无效 IP", "请输入有效的 IPv6 地址")
                    return

            elif record_type == "CNAME":
                if enter_inspector.is_valid_ipv4(target):
                    reply = QMessageBox.question(self, "IPv4 地址检测",
                                                 "检测到 IPv4 地址。是否要切换到 A 记录？",
                                                 QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
                    if reply == QMessageBox.StandardButton.Yes:
                        record_type = "A"
                    else:
                        QMessageBox.warning(self, "无效 CNAME", "CNAME 记录不能指向 IP 地址")
                        return
                elif enter_inspector.is_valid_ipv6(target):
                    reply = QMessageBox.question(self, "IPv6 地址检测",
                                                 "检测到 IPv6 地址。是否要切换到 AAAA 记录？",
                                                 QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
                    if reply == QMessageBox.StandardButton.Yes:
                        record_type = "AAAA"
                    else:
                        QMessageBox.warning(self, "无效 CNAME", "CNAME 记录不能指向 IP 地址")
                        return
                elif not enter_inspector.is_valid_domain(target):
                    QMessageBox.warning(self, "无效域名", "请输入有效的域名")
                    return

            elif record_type == "SRV":
                if not all(x.isdigit() and 0 <= int(x) <= 65535 for x in
                           [priority_input.text(), weight_input.text(), port_input.text()]):
                    QMessageBox.warning(self, "无效SRV参数", "优先级、权重和端口必须是0-65535之间的整数")
                    return

                srv_target = target
                if ':' in srv_target:  # 可能是IPv6
                    srv_target = f"[{srv_target}]"

                # 检查目标是否带有端口
                if ':' in srv_target.strip('[]'):
                    srv_target, srv_port = srv_target.rsplit(':', 1)
                    if not port_input.text():
                        port_input.setText(srv_port)
                    srv_target = srv_target.strip('[]')

                if enter_inspector.is_valid_domain(srv_target):
                    srv_target = enter_inspector.remove_http_https(srv_target)
                elif not (enter_inspector.is_valid_ipv4(srv_target) or enter_inspector.is_valid_ipv6(srv_target)):
                    QMessageBox.warning(self, "无效SRV目标", "SRV目标必须是有效的域名或IP地址")
                    return

                target = f"{priority_input.text()} {weight_input.text()} {port_input.text()} {srv_target}"

            try:
                url = "http://cf-v2.uapis.cn/create_free_subdomain"
                payload = {
                    "token": self.token,
                    "domain": main_domain_combo.currentText(),
                    "record": record_input.text(),
                    "type": record_type,
                    "ttl": ttl_combo.currentText(),
                    "target": target,
                    "remarks": remarks.text()
                }

                headers = get_headers(request_json=True)
                response = requests.post(url, headers=headers, json=payload)
                response = response.json()
                if response['code'] == 200:
                    self.logger.info(response["msg"])
                    self.load_domains()  # 刷新域名列表
                else:
                    self.logger.error(f"添加域名失败：{response['msg']}")
                    QMessageBox.warning(self, "错误", f"添加域名失败：{response['msg']}")
            except Exception as content:
                self.logger.exception("添加域名时发生错误")
                QMessageBox.warning(self, "错误", f"添加域名失败: {str(content)}")

    def load_main_domains(self, combo_box):
        """加载主域名到下拉框"""
        try:
            url = "http://cf-v2.uapis.cn/list_available_domains"
            headers = get_headers()
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                if data['code'] == 200:
                    combo_box.clear()
                    for domain_info in data['data']:
                        combo_box.addItem(domain_info['domain'])
                else:
                    self.logger.error(f"获取主域名失败: {data['msg']}")
            else:
                self.logger.error(f"获取主域名请求失败: 状态码 {response.status_code}")
        except Exception:
            self.logger.exception("加载主域名时发生错误")

    def edit_domain(self):
        """编辑域名 - 仅允许修改 TTL 和目标"""
        TTL_OPTIONS = [
            "1分钟", "2分钟", "5分钟", "10分钟", "15分钟", "30分钟",
            "1小时", "2小时", "5小时", "12小时", "1天"
        ]

        if hasattr(self, 'selected_domain'):
            domain_info = self.selected_domain
            dialog = QDialog(self)
            dialog.setWindowTitle("编辑域名")
            layout = QFormLayout(dialog)

            # 只读字段
            domain_label = QLabel(domain_info['domain'])
            record_label = QLabel(domain_info['record'])
            type_label = QLabel(domain_info['type'])

            # 可编辑字段
            target_input = QLineEdit(domain_info['target'])
            ttl_combo = QComboBox()
            ttl_combo.addItems(TTL_OPTIONS)
            ttl_combo.setCurrentText(domain_info['ttl'])

            # 添加字段到布局
            layout.addRow("域名:", domain_label)
            layout.addRow("记录:", record_label)
            layout.addRow("类型:", type_label)
            layout.addRow("目标:", target_input)
            layout.addRow("TTL:", ttl_combo)

            ttl_note = QLabel("注意：较慢的TTL可以提升解析稳定度，但会延长更新生效时间。")
            ttl_note.setWordWrap(True)
            layout.addRow(ttl_note)

            srv_widget = QWidget()
            srv_layout = QFormLayout(srv_widget)
            priority_input = QLineEdit()
            weight_input = QLineEdit()
            port_input = QLineEdit()

            if domain_info['type'] == "SRV":
                priority, weight, port, srv_target = enter_inspector.parse_srv_target(domain_info['target'])
                priority_input.setText(priority or "")
                weight_input.setText(weight or "")
                port_input.setText(port or "")
                target_input.setText(srv_target)

                srv_layout.addRow("优先级:", priority_input)
                srv_layout.addRow("权重:", weight_input)
                srv_layout.addRow("端口:", port_input)
                srv_widget.setVisible(True)
                layout.addRow(srv_widget)

            buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
            buttons.accepted.connect(dialog.accept)
            buttons.rejected.connect(dialog.reject)
            layout.addRow(buttons)

            if dialog.exec() == QDialog.DialogCode.Accepted:
                record_type = domain_info['type']
                target = enter_inspector.remove_http_https(target_input.text().strip())

                # 验证输入
                if record_type == "A" and not enter_inspector.is_valid_ipv4(target):
                    QMessageBox.warning(self, "无效IP", "请输入有效的IPv4地址")
                    return
                elif record_type == "AAAA" and not enter_inspector.is_valid_ipv6(target):
                    QMessageBox.warning(self, "无效IP", "请输入有效的IPv6地址")
                    return
                elif record_type == "CNAME":
                    if enter_inspector.is_valid_ipv4(target) or enter_inspector.is_valid_ipv6(target):
                        QMessageBox.warning(self, "无效CNAME", "CNAME记录不能指向IP地址")
                        return
                    elif not enter_inspector.is_valid_domain(target):
                        QMessageBox.warning(self, "无效域名", "请输入有效的目标域名")
                        return
                elif record_type == "SRV":
                    if not all(x.isdigit() and 0 <= int(x) <= 65535 for x in
                               [priority_input.text(), weight_input.text(), port_input.text()]):
                        QMessageBox.warning(self, "无效SRV参数", "优先级、权重和端口必须是0-65535之间的整数")
                        return

                    srv_target = target
                    if ':' in srv_target:  # 可能是IPv6
                        srv_target = f"[{srv_target}]"

                    if not enter_inspector.is_valid_domain(srv_target) and not enter_inspector.is_valid_ipv4(srv_target) and not enter_inspector.is_valid_ipv6(
                    srv_target.strip('[]')):
                        QMessageBox.warning(self, "无效SRV目标", "SRV目标必须是有效的域名或IP地址")
                        return

                    target = f"{priority_input.text()} {weight_input.text()} {port_input.text()} {srv_target}"

                try:
                    url = "http://cf-v2.uapis.cn/update_free_subdomain"
                    payload = {
                        "token": self.token,
                        "domain": domain_info['domain'],
                        "record": domain_info['record'],
                        "type": record_type,
                        "ttl": ttl_combo.currentText(),
                        "target": target,
                        "remarks": domain_info.get('remarks', '')
                    }

                    headers = get_headers(request_json=True)
                    response = requests.post(url, headers=headers, json=payload)
                    if response.status_code == 200:
                        self.logger.info("域名更新成功")
                        self.load_domains()  # 刷新域名列表
                    else:
                        self.logger.error(f"更新域名失败: {response.text}")
                        QMessageBox.warning(self, "错误", f"更新域名失败: {response.text}")
                except Exception as content:
                    self.logger.exception("更新域名时发生错误")
                    QMessageBox.warning(self, "错误", f"更新域名失败: {str(content)}")
        else:
            QMessageBox.warning(self, "警告", "请先选择一个域名")

    def delete_domain(self):
        """删除域名"""
        if hasattr(self, 'selected_domain'):
            domain_info = self.selected_domain
            reply = QMessageBox.question(self, '确认删除',
                                         f"确定要删除域名 '{domain_info['record']}.{domain_info['domain']}' 吗？",
                                         QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)

            if reply == QMessageBox.StandardButton.Yes:
                try:
                    url = "http://cf-v2.uapis.cn/delete_free_subdomain"
                    payload = {
                        "token": self.token,
                        "domain": domain_info['domain'],
                        "record": domain_info['record']
                    }

                    headers = get_headers(request_json=True)
                    response = requests.post(url, headers=headers, json=payload)
                    if response.status_code == 200:
                        self.logger.info(f"域名 '{domain_info['record']}.{domain_info['domain']}' 删除成功")
                        self.load_domains()  # 刷新域名列表
                    else:
                        self.logger.error(f"删除域名失败: {response.text}")
                except Exception as content:
                    self.logger.exception("删除域名时发生错误")
                    QMessageBox.warning(self, "错误", f"删除域名失败: {str(content)}")
        else:
            QMessageBox.warning(self, "警告", "请先选择一个域名")

    def auto_update(self):
        """自动更新函数"""
        if self.token:
            self.load_nodes()

    def update_log(self, message):
        """更新日志显示"""
        self.log_display.append(message)
        self.log_display.verticalScrollBar().setValue(self.log_display.verticalScrollBar().maximum())

    def check_and_download_files(self):
        """检查并下载所需文件"""
        thread = threading.Thread(target=self._download_files)
        thread.start()

    def _download_files(self):
        required_files = [
            get_absolute_path('frpc.exe'),
        ]
        missing_files = [file for file in required_files if not os.path.exists(file)]

        if missing_files:
            self.logger.info("正在下载所需文件...")
            url = "https://chmlfrp.cn/dw/windows/amd64/frpc.exe"
            try:
                response = requests.get(url, stream=True)
                response.raise_for_status()  # 检查是否成功获取
                zip_path = get_absolute_path("frpc.exe")
                with open(zip_path, "wb") as file_contents:
                    for chunk in response.iter_content(chunk_size=8192):
                        file_contents.write(chunk)

                self.logger.info("文件下载完成")
            except Exception as content:
                self.logger.error(f"下载或处理文件时发生错误: {str(content)}")

    def mousePressEvent(self, event):
        """鼠标按下事件"""
        if event.button() == Qt.MouseButton.LeftButton:
            self.dragging = True
            self.offset = event.position().toPoint()

    def mouseMoveEvent(self, event):
        """鼠标移动事件"""
        try:
            if self.dragging:
                global_pos = event.globalPosition().toPoint()
                self.move(global_pos - self.offset)
        except Exception as content:
            self.logger.error(f"移动窗口时发生错误: {str(content)}")
            self.dragging = False

    def mouseReleaseEvent(self, event):
        """鼠标释放事件"""
        if event.button() == Qt.MouseButton.LeftButton:
            self.dragging = False

    def forcefully_terminate_frpc(self):
        self.logger.info("正在终止当前目录下的 frpc.exe 进程...")
        current_directory = os.path.dirname(os.path.abspath(__file__))  # 获取当前脚本目录
        frpc_path = os.path.join(current_directory, 'frpc.exe')  # 当前目录下的 frpc.exe 完整路径

        # 检查 frpc.exe 是否存在
        if not os.path.exists(frpc_path):
            self.logger.error(f"{frpc_path} 不存在")
            return False

        # 封装进程终止逻辑
        def terminate_process(proc_id):
            try:
                self.logger.info(f"正在终止进程: {proc_id.info['pid']} - {frpc_path}")
                proc_id.terminate()  # 终止进程
                proc_id.wait()  # 等待进程完全结束
                self.logger.info(f"进程 {proc_id.info['pid']} 已终止")
            except psutil.NoSuchProcess:
                self.logger.error(f"进程 {proc_id.info['pid']} 已不存在")
            except psutil.AccessDenied:
                self.logger.error(f"访问被拒绝，无法终止进程 {proc_id.info['pid']}")
            except Exception as _content:
                self.logger.error(f"终止进程 {proc_id.info['pid']} 时发生错误: {str(_content)}")

        try:
            # psutil 获取所有进程
            for proc in psutil.process_iter(['pid', 'exe']):
                # 检查进程路径是否与指定路径匹配
                if proc.info['exe'] and os.path.normpath(proc.info['exe']) == os.path.normpath(frpc_path):
                    terminate_process(proc)  # 调用封装的终止进程函数

            self.logger.info("所有匹配的 frpc.exe 进程已终止")
            return True
        except psutil.NoSuchProcess:
            self.logger.error("未找到指定的 frpc.exe 进程")
            return False
        except psutil.AccessDenied:
            self.logger.error("访问被拒绝。您可能需要以管理员身份运行")
            return False
        except Exception as content:
            self.logger.error(f"终止 frpc.exe 进程时发生错误: {str(content)}")
            return False

    def cleanup(self):
        # 停止所有普通隧道
        for tunnel_name, process in list(self.tunnel_processes.items()):
            self.stop_tunnel({"name": tunnel_name})

        # 强制终止所有 frpc 进程
        self.forcefully_terminate_frpc()

        time.sleep(1)

        # 等待所有线程结束
        QThreadPool.globalInstance().waitForDone()

    @staticmethod
    def is_system_dark_theme():
        if sys.platform == "win32":
            try:
                registry = winreg.ConnectRegistry(None, winreg.HKEY_CURRENT_USER)
                key = winreg.OpenKey(registry, r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize")
                value, _ = winreg.QueryValueEx(key, "AppsUseLightTheme")
                return value == 0
            except:
                return False
        elif sys.platform == "darwin":
            try:
                result = subprocess.run(['defaults', 'read', '-g', 'AppleInterfaceStyle'], capture_output=True,
                                        text=True)
                return result.stdout.strip() == "Dark"
            except:
                return False
        else:
            return False

    def toggle_theme(self):
        self.dark_theme = not self.dark_theme
        self.apply_theme()

        # 更新当前选中的按钮样式
        current_index = self.content_stack.currentIndex()
        if current_index < len(self.tab_buttons):
            self.update_button_styles(self.tab_buttons[current_index])

    def apply_theme(self):
        if self.dark_theme:
            self.button_color = "#0D47A1"
            self.button_hover_color = "#1565C0"
            self.setStyleSheet("""
				QWidget {
					color: #FFFFFF;
					background-color: #2D2D2D;
				}
				#background {
					background-color: #1E1E1E;
					border-radius: 10px;
				}
				QPushButton {
					background-color: #0D47A1;
					color: white;
					border: none;
					padding: 5px 10px;
					text-align: center;
					text-decoration: none;
					font-size: 14px;
					margin: 4px 2px;
					border-radius: 4px;
				}
				QPushButton:hover {
					background-color: #1565C0;
				}
				QPushButton:disabled {
					background-color: #424242;
				}
				QLineEdit, QComboBox, QTextEdit {
					padding: 5px;
					border: 1px solid #424242;
					border-radius: 4px;
					background-color: #1E1E1E;
					color: #FFFFFF;
				}
				NodeCard, TunnelCard, DomainCard {
					background-color: #2D2D2D;
					border: 1px solid #424242;
				}
				NodeCard:hover, TunnelCard:hover, DomainCard:hover {
					background-color: #3D3D3D;
				}
			""")
        else:
            self.button_color = "#4CAF50"
            self.button_hover_color = "#45a049"
            self.setStyleSheet("""
				QWidget {
					color: #333333;
					background-color: #FFFFFF;
				}
				#background {
					background-color: #F0F0F0;
					border-radius: 10px;
				}
				QPushButton {
					background-color: #4CAF50;
					color: white;
					border: none;
					padding: 5px 10px;
					text-align: center;
					text-decoration: none;
					font-size: 14px;
					margin: 4px 2px;
					border-radius: 4px;
				}
				QPushButton:hover {
					background-color: #45a049;
				}
				QPushButton:disabled {
					background-color: #CCCCCC;
				}
				QLineEdit, QComboBox, QTextEdit {
					padding: 5px;
					border: 1px solid #DCDCDC;
					border-radius: 4px;
					background-color: #F0F0F0;
					color: #333333;
				}
				NodeCard, TunnelCard, DomainCard {
					background-color: #FFFFFF;
					border: 1px solid #D0D0D0;
				}
				NodeCard:hover, TunnelCard:hover, DomainCard:hover {
					background-color: #F0F0F0;
				}
			""")
        if self.dark_theme:
            refresh_button_style = """
					QPushButton#refreshButton {
						background-color: #1E90FF;
						color: white;
						border: none;
						padding: 5px 10px;
						border-radius: 4px;
						font-weight: bold;
					}
					QPushButton#refreshButton:hover {
						background-color: #4169E1;
					}
				"""
        else:
            refresh_button_style = """
					QPushButton#refreshButton {
						background-color: #4CAF50;
						color: white;
						border: none;
						padding: 5px 10px;
						border-radius: 4px;
						font-weight: bold;
					}
					QPushButton#refreshButton:hover {
						background-color: #45a049;
					}
				"""

        self.setStyleSheet(self.styleSheet() + refresh_button_style)

    def refresh_nodes(self):
        """刷新节点状态"""
        self.load_nodes()
        self.logger.info("节点状态已刷新")

    def switch_tab(self, tab_name):
        if tab_name == "user_info":
            self.content_stack.setCurrentIndex(0)
        elif tab_name == "tunnel":
            self.content_stack.setCurrentIndex(1)
        elif tab_name == "domain":
            self.content_stack.setCurrentIndex(2)
        elif tab_name == "node":
            self.content_stack.setCurrentIndex(3)


        # 更新所有按钮的样式
        for button in self.tab_buttons:
            button_name = button.text().lower().replace(" ", "_")
            if button_name == tab_name:
                button.setStyleSheet(f"""
                    QPushButton {{
                        background-color: {self.button_hover_color};
                        color: white;
                        border: none;
                        padding: 5px 10px;
                        text-align: center;
                        text-decoration: none;
                        font-size: 14px;
                        margin: 4px 2px;
                        border-radius: 4px;
                    }}
                """)
            else:
                button.setStyleSheet(f"""
                    QPushButton {{
                        background-color: {self.button_color};
                        color: white;
                        border: none;
                        padding: 5px 10px;
                        text-align: center;
                        text-decoration: none;
                        font-size: 14px;
                        margin: 4px 2px;
                        border-radius: 4px;
                    }}
                    QPushButton:hover {{
                        background-color: {self.button_hover_color};
                    }}
                """)

    def stop_single_tunnel(self, tunnel_name):
        with QMutexLocker(self.running_tunnels_mutex):
            if tunnel_name in self.running_tunnels:
                worker = self.running_tunnels[tunnel_name]
                worker.requestInterruption()  # 请求中断
                if not worker.wait(5000):  # 等待最多5秒
                    worker.terminate()
                    worker.wait(2000)
                del self.running_tunnels[tunnel_name]
                self.logger.info(f"隧道 '{tunnel_name}' 已停止")
            else:
                self.logger.warning(f"尝试停止不存在的隧道: {tunnel_name}")


if __name__ == '__main__':
    def exception_hook(exctype, value, main_thread):
        while main_thread:
            main_thread = main_thread.tb_next
        sys.__excepthook__(exctype, value, main_thread)

    sys.excepthook = exception_hook
    try:
        Pre_run_operations.elevation_rights()  # 提权
        Pre_run_operations.document_checking()  # 配置文件检查
        app = QApplication(sys.argv)
        main_window = MainWindow()
        main_window.show()
        sys.exit(app.exec())
    except Exception as e:
        print(f"发生意外错误: {e}")
        traceback.print_exc()
