import ipaddress
import json
import logging
import os
import random
import re
import smtplib
import socket
import subprocess
import sys
import threading
import time
import traceback
import winreg
from logging.handlers import *
import glob

import psutil
import pyperclip
import requests
import markdown
from PyQt6.QtCore import *
from PyQt6.QtGui import *
from PyQt6.QtWidgets import *
from PyQt6.QtNetwork import *
from dns.resolver import Resolver, NoNameservers, NXDOMAIN, NoAnswer, Timeout
import urllib3
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import Tuple, Optional
import html
urllib3.disable_warnings()

# ------------------------------以下为程序信息--------------------
APP_NAME = "CUL" # 程序名称
APP_VERSION = "1.6.5" # 程序版本
PY_VERSION = "3.13.*" # Python 版本
WINDOWS_VERSION = "Windows NT 10.0" # 系统版本
Number_of_tunnels = 0 # 隧道数量
n_of_tunnels = 0 # 节点判断
USER_AGENT = f"{APP_NAME}/{APP_VERSION} (Python/{PY_VERSION}; {WINDOWS_VERSION})" # 生成统一的 User-Agent

# ------------------------------更新的镜像地址--------------------

def exception_hook(exctype, value, main_thread):
    while main_thread:
        main_thread = main_thread.tb_next
    sys.__excepthook__(exctype, value, main_thread)

def get_mirrors():
    """
    获取可用的GitHub镜像站点列表
    返回：按API返回顺序的镜像站点列表（去除http/https前缀），过滤掉速度为0的站点
    """
    # 默认备用镜像列表
    DEFAULT_MIRRORS = [
        "github.tbedu.top",
        "gitproxy.click",
        "github.moeyy.xyz",
        "ghproxy.net",
        "gh.llkk.cc"
    ]
    try:
        # 发起请求获取镜像站点信息
        response = requests.get("https://api.akams.cn/github")
        response.raise_for_status()  # 如果请求失败会抛出异常
        data = response.json()  # 解析JSON响应
        # 检查API返回状态码
        if data.get("code") == 200:
            mirrors = data.get("data", [])  # 获取镜像数据，如果不存在则返回空列表
            # 过滤掉速度为0的镜像
            valid_mirrors = [mirror for mirror in mirrors if mirror.get("speed", 0) > 0]
            # 提取镜像URL并去除协议前缀
            MIRROR_PREFIXES = [
                mirror["url"].replace("https://", "").replace("http://", "").strip()
                for mirror in valid_mirrors
            ]
            return MIRROR_PREFIXES
        else:
            print(f"API返回错误代码：{data.get('code')}")
            return DEFAULT_MIRRORS  # 返回默认镜像列表

    except requests.RequestException as e:
        print(f"请求API失败：{e}")
        return DEFAULT_MIRRORS  # 请求失败时返回默认镜像列表
    except ValueError as e:
        print(f"解析JSON响应失败：{e}")
        return DEFAULT_MIRRORS  # JSON解析失败时返回默认镜像列表
    except Exception as e:
        print(f"未知错误：{e}")
        return DEFAULT_MIRRORS  # 未知错误时返回默认镜像列表

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

def get_headers(request_json=False):
    # 生成统一的请求头
    headers = {'User-Agent': USER_AGENT}
    if request_json:
        headers['Content-Type'] = 'application/json'
    return headers

class message_push():
    CONFIG_MAP = {
        'qq.com': ('smtp.qq.com', 465),
        '163.com': ('smtp.163.com', 465),
        'aliyun.com': ('smtp.aliyun.com', 465),
        '126.com': ('smtp.126.com', 465),
        'foxmail.com': ('smtp.exmail.qq.com', 465),
        'sina.com': ('smtp.sina.com', 465),
        'sohu.com': ('smtp.sohu.com', 465),
        'yeah.net': ('smtp.yeah.net', 465),
        '21cn.com': ('smtp.21cn.com', 465),
        'vip.qq.com': ('smtp.vip.qq.com', 465),
        '263.net': ('smtp.263.net', 465),
        'exmail.qq.com': ('smtp.exmail.qq.com', 465)
    }

    def __init__(self, sender_email: str, password: str, receiver_email: str,
                 smtp_server: Optional[str] = None, port: Optional[int] = None):
        """
        初始化邮件通知器

        :param sender_email: 发件人邮箱
        :param password: 邮箱密码/授权码
        :param receiver_email: 收件人邮箱
        :param smtp_server: SMTP服务器地址(可选，自动检测)
        :param port: SMTP端口(可选，自动检测)
        """
        self.sender_email = sender_email
        self.password = password
        self.receiver_email = receiver_email

        # 自动检测SMTP配置
        if smtp_server is None or port is None:
            self.smtp_server, self.port = self.auto_detect_config()
        else:
            self.smtp_server = smtp_server
            self.port = port

    @staticmethod
    def get_computer_name() -> str:
        """获取计算机名"""
        return socket.gethostname()

    @staticmethod
    def get_current_time(format_str: str = "%Y-%m-%d %H:%M:%S") -> str:
        """获取当前时间"""
        return datetime.now().strftime(format_str)

    def auto_detect_config(self) -> Tuple[str, int]:
        """
        根据邮箱地址自动检测SMTP配置

        :return: (smtp_server, port)
        :raises ValueError: 不支持的邮箱服务商
        """
        domain = self.sender_email.split('@')[-1].lower()

        for key, value in self.CONFIG_MAP.items():
            if domain.endswith(key):  # 支持子域名
                return value

        if domain.endswith('.com') and 'exmail' in domain:
            return ('smtp.exmail.qq.com', 465)

        raise ValueError(f"不支持的邮箱服务商: {domain}，请手动配置SMTP信息")

    def send(self, subject: str, body: str) -> Tuple[bool, str]:
        """
        发送邮件

        :param subject: 邮件主题
        :param body: 邮件正文
        :return: (成功标志, 状态信息)
        """
        message = MIMEMultipart()
        message["From"] = self.sender_email
        message["To"] = self.receiver_email
        message["Subject"] = subject

        # 使用 html.unescape 替换 HTML 实体
        clean_body = html.unescape(body)
        message.attach(MIMEText(clean_body, "plain", "utf-8"))

        try:
            # 尝试使用端口 465 发送
            server = smtplib.SMTP_SSL(self.smtp_server, 465, timeout=15)
            server.login(self.sender_email, self.password)
            server.sendmail(self.sender_email, self.receiver_email, message.as_string())
            server.quit()
            return True, "邮件发送成功"
        except Exception as e465:
            # 如果端口 465 发送失败，尝试使用端口 587
            try:
                server = smtplib.SMTP(self.smtp_server, 587, timeout=15)
                server.starttls()
                server.login(self.sender_email, self.password)
                server.sendmail(self.sender_email, self.receiver_email, message.as_string())
                server.quit()
                return True, "邮件发送成功（使用端口 587）"
            except smtplib.SMTPAuthenticationError as e:
                return False, f"认证失败：{str(e)}，请检查邮箱用户名或密码"
            except smtplib.SMTPConnectError as e:
                return False, f"连接服务器失败：{str(e)}，请检查网络设置"
            except smtplib.SMTPException as e:
                return False, f"SMTP协议错误：{str(e)}"
            except socket.timeout:
                return False, "连接超时，请检查网络设置"
            except Exception as e:
                return False, f"未知错误：{str(e)}"

        except smtplib.SMTPAuthenticationError as e:
            return False, f"认证失败：{str(e)}，请检查邮箱用户名或密码"
        except smtplib.SMTPConnectError as e:
            return False, f"连接服务器失败：{str(e)}，请检查网络设置"
        except smtplib.SMTPException as e:
            return False, f"SMTP协议错误：{str(e)}"
        except socket.timeout:
            return False, "连接超时，请检查网络设置"
        except Exception as e:
            return False, f"未知错误：{str(e)}"

class ProgramUpdates():
    def __init__(self):
        super().__init__()

    @classmethod
    def check_update(cls, current_version):
        """检测更新，返回最新版本、更新内容和所有镜像下载链接"""
        try:
            # 更新全局配置
            DNS_CONFIG = {
                "servers": [
                    "1.1.1.1",  # Cloudflare
                    "8.8.8.8",  # Google
                    "114.114.114.114",  # 114DNS
                    "223.5.5.5",  # AliDNS
                    "9.9.9.9"  # Quad9
                ],
                "timeout": 10,
                "domain": "api.github.com"
            }
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
                return current_version, "当前版本比最新发布版本", []
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
    def document_checking(cls):
        # 初始化内容
        default_settings = {
            "auto_start_tunnels": [],  # 设置为空列表
            "theme": "light",
            "log_size_mb": 10,
            "backup_count": 30,  # 设置为30
            "mail": {
                "sender_email": "",  # 设置为空字符串
                "password": "",  # 设置为空字符串
                "smtp_server": "",  # 设置为空字符串
                "smtp_port": "",  # 设置为空字符串
                "notifications": {
                    "tunnel_offline": False,  # 设置为False
                    "node_offline": False,  # 设置为False
                    "tunnel_start": False,  # 设置为False
                    "node_online": False,  # 设置为False
                    "node_added": False,  # 设置为False
                    "node_removed": False  # 设置为False
                }
            }
        }

        # 检查并创建settings.json
        settings_path = get_absolute_path("settings.json")

        # 如果文件不存在或者为空，创建/初始化文件
        if not os.path.exists(settings_path) or os.path.getsize(settings_path) == 0:
            try:
                with open(settings_path, 'w', encoding='utf-8') as f:
                    json.dump(default_settings, f, indent=4, ensure_ascii=False)
            except Exception as e:
                print(f"处理settings.json文件时出错: {e}")

        # 检查并创建tunnel_comments.json
        comments_path = get_absolute_path("tunnel_comments.json")
        if not os.path.exists(comments_path):
            try:
                with open(comments_path, 'w', encoding='utf-8') as f:
                    json.dump({}, f, indent=4, ensure_ascii=False)
                print("已创建隧道备注配置文件")
            except Exception as e:
                print(f"创建隧道备注配置文件时出错: {e}")
        elif os.path.getsize(comments_path) == 0:
            try:
                with open(comments_path, 'w', encoding='utf-8') as f:
                    json.dump({}, f, indent=4, ensure_ascii=False)
            except Exception as e:
                print(f"初始化空的隧道备注配置文件时出错: {e}")

        # 迁移旧的凭证文件到注册表
        credentials_path = get_absolute_path("credentials.json")
        if os.path.exists(credentials_path):
            try:
                # 读取凭证文件内容
                credentials = {}
                if os.path.getsize(credentials_path) > 0:
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
            if tyen:
                return 0 < port_num <= 65535
            elif not tyen:
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
    def __init__(self, tunnel_info, user_token, parent=None):
        super().__init__()
        self.backup_status_label = None
        self.start_stop_button = None
        self.link_label = None
        self.status_label = None
        self.comment_label = None
        self.tunnel_info = tunnel_info
        self.token = user_token
        self.parent = parent
        self.node_domain = None
        self.is_running = False
        self.is_selected = False
        self.initUI()
        self.updateStyle()
        self.fetch_node_info()
        self.update_backup_status()
        self.load_comment()

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
        # 添加备用节点状态标签
        self.backup_status_label = QLabel("备用节点: 正在加载...")
        # 添加备注标签
        self.comment_label = QLabel("备注: 无")
        self.comment_label.setWordWrap(True)
        self.comment_label.setStyleSheet("color: #666666; font-style: italic;")

        self.start_stop_button = QPushButton("启动")
        self.start_stop_button.clicked.connect(self.toggle_start_stop)

        layout.addWidget(name_label)
        layout.addWidget(type_label)
        layout.addWidget(local_label)
        layout.addWidget(remote_label)
        layout.addWidget(node_label)
        layout.addWidget(self.status_label)
        layout.addWidget(self.link_label)
        layout.addWidget(self.backup_status_label)
        layout.addWidget(self.comment_label)
        layout.addWidget(self.start_stop_button)

        self.setLayout(layout)
        self.setFixedSize(250, 280)

    def load_comment(self):
        """Load and display the comment for this tunnel"""
        if hasattr(self.parent, 'get_tunnel_comment') and self.tunnel_info.get('id'):
            comment = self.parent.get_tunnel_comment(self.tunnel_info['id'])
            if comment:
                self.comment_label.setText(f"备注: {comment}")
            else:
                self.comment_label.setText("备注: 无")
        else:
            self.comment_label.setText("备注: 无")

    def get_backup_config(self, tunnel_id):
        """获取隧道的备用节点配置"""
        if not tunnel_id:
            self.logger.error("获取备用节点配置失败: 隧道ID为空")
            return None

        config_path = get_absolute_path("backup_config.json")
        if os.path.exists(config_path):
            try:
                if os.path.getsize(config_path) == 0:
                    with open(config_path, 'w') as f:
                        json.dump({}, f)
                    return None

                with open(config_path, 'r') as f:
                    try:
                        configs = json.load(f)
                        tunnel_id_str = str(tunnel_id)
                        if tunnel_id_str in configs:
                            config = configs[tunnel_id_str]
                            if not isinstance(config, dict):
                                self.logger.error(f"隧道 {tunnel_id} 的备用节点配置无效")
                                return None

                            return config
                        else:
                            return None

                    except json.JSONDecodeError:
                        self.logger.error(f"备用节点配置文件格式错误，重新初始化")
                        with open(config_path, 'w') as f:
                            json.dump({}, f)
                        return None

            except Exception as e:
                self.logger.error(f"读取备用节点配置失败: {str(e)}")
        else:
            try:
                with open(config_path, 'w') as f:
                    json.dump({}, f)
                self.logger.info("已创建备用节点配置文件")
            except Exception as e:
                self.logger.error(f"创建备用节点配置文件失败: {str(e)}")

        return None

    def get_domain_status(self, tunnel_id):
        """获取隧道域名状态"""
        config = self.get_backup_config(tunnel_id)
        if not config or 'domain' not in config:
            return None

        domain_config = config['domain']
        last_updated = domain_config.get('last_updated', '未知')

        # 获取域名和记录
        domain = domain_config.get('domain', '')
        record = domain_config.get('record', '')

        # 构建域名显示文本
        domain_text = f"{record}.{domain}"

        # 返回格式化的状态信息
        return f"域名: {domain_text} (更新: {last_updated})"

    def update_backup_status(self):
        """更新备用节点配置状态"""
        if hasattr(self.parent, 'get_backup_config_status'):
            status = self.parent.get_backup_config_status(self.tunnel_info['id'])

            # 检查域名状态
            if hasattr(self.parent, 'get_domain_status'):
                domain_status = self.parent.get_domain_status(self.tunnel_info['id'])
                if domain_status:
                    status += f"\n{domain_status}"

            self.backup_status_label.setText(f"备用节点: {status}")
        else:
            self.backup_status_label.setText("备用节点: 无法获取")

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
        self.parent = parent
        self.node_detail_text = None
        self.force_update_checkbox = None
        self.comment_checkbox = None  # 添加备注编辑复选框
        self.comment_input = None  # 添加备注输入框
        self.v1_api_radio = None
        self.v2_api_radio = None
        self.setWindowTitle("批量编辑隧道")
        self.setMinimumWidth(750)  # 增加宽度以容纳更多内容
        self.initUI()

    def initUI(self):
        # 使用水平布局
        main_layout = QHBoxLayout(self)
        # 左侧编辑区域
        left_layout = QVBoxLayout()
        # API版本选择
        api_version_group = QGroupBox("API版本选择")
        api_layout = QVBoxLayout()
        self.v2_api_radio = QRadioButton("V2 API")
        self.v1_api_radio = QRadioButton("V1 API（部分参数可能无法修改）")
        api_layout.addWidget(self.v2_api_radio)
        api_layout.addWidget(self.v1_api_radio)
        api_version_group.setLayout(api_layout)
        self.v2_api_radio.setChecked(True)  # 默认选择V2
        left_layout.addWidget(api_version_group)
        # 强制修改选项
        self.force_update_checkbox = QCheckBox("强制修改（删除后重建）")
        force_update_note = QLabel("注意：强制修改会先删除原隧道再创建新隧道，隧道ID会变更，且可能失败")
        force_update_note.setStyleSheet("color: red; font-size: 10px;")
        force_update_note.setWordWrap(True)
        left_layout.addWidget(self.force_update_checkbox)
        left_layout.addWidget(force_update_note)
        # 备注设置组
        comment_group = QGroupBox("备注设置")
        comment_layout = QVBoxLayout()

        self.comment_checkbox = QCheckBox("修改备注")
        self.comment_input = QLineEdit()
        self.comment_input.setPlaceholderText("新的备注内容（会应用到所有选中的隧道）")
        self.comment_input.setEnabled(False)  # 初始禁用

        self.comment_checkbox.toggled.connect(self.on_comment_toggled)

        comment_layout.addWidget(self.comment_checkbox)
        comment_layout.addWidget(self.comment_input)
        comment_group.setLayout(comment_layout)
        left_layout.addWidget(comment_group)

        form_layout = QFormLayout()

        self.node_combo = QComboBox()
        self.node_combo.addItem("不修改")
        self.node_combo.addItems([node['name'] for node in API.get_nodes()])
        self.node_combo.currentIndexChanged.connect(self.on_node_changed)

        self.type_combo = QComboBox()
        self.type_combo.addItem("不修改")
        self.type_combo.addItems(["tcp", "udp", "http", "https"])
        # 移除类型变化监听器，因为不再需要动态更新域名输入框
        self.local_ip_input = QLineEdit()
        self.local_ip_input.setPlaceholderText("不修改")

        self.local_port_input = QLineEdit()
        self.local_port_input.setPlaceholderText("不修改")
        # 加密和压缩选项
        self.encryption_combo = QComboBox()
        self.encryption_combo.addItems(["不修改", "开启", "关闭"])

        self.compression_combo = QComboBox()
        self.compression_combo.addItems(["不修改", "开启", "关闭"])

        form_layout.addRow("节点:", self.node_combo)
        form_layout.addRow("类型:", self.type_combo)
        form_layout.addRow("本地IP/主机名:", self.local_ip_input)
        form_layout.addRow("本地端口:", self.local_port_input)

        # 添加提示说明
        port_domain_note = QLabel("注意：TCP/UDP的远程端口和HTTP/HTTPS的绑定域名在批量编辑中将保持原值")
        port_domain_note.setStyleSheet("color: #FF6600; font-size: 10px;")
        port_domain_note.setWordWrap(True)
        form_layout.addRow(port_domain_note)
        form_layout.addRow("加密:", self.encryption_combo)
        form_layout.addRow("压缩:", self.compression_combo)

        left_layout.addLayout(form_layout)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        left_layout.addWidget(buttons)

        # 右侧节点详情区域
        right_layout = QVBoxLayout()
        detail_label = QLabel("节点详细信息")
        self.node_detail_text = QTextEdit()
        self.node_detail_text.setReadOnly(True)
        self.node_detail_text.setMinimumWidth(300)
        right_layout.addWidget(detail_label)
        right_layout.addWidget(self.node_detail_text)
        # 将两部分添加到主布局
        main_layout.addLayout(left_layout)
        main_layout.addLayout(right_layout)
        # 初始化节点详情
        self.on_node_changed(self.node_combo.currentIndex())

    def on_comment_toggled(self, checked):
        """启用或禁用备注输入框"""
        self.comment_input.setEnabled(checked)

    def on_node_changed(self, index):
        """当节点选择变化时更新节点详情"""
        if index == 0:
            # "不修改"选项
            self.node_detail_text.clear()
            return

        node_name = self.node_combo.itemText(index)
        nodes = API.get_nodes()

        for node in nodes:
            if node['name'] == node_name:
                detail_text = f"""
节点名称: {node['name']}
节点地址: {node['area']}
权限组: {node['nodegroup']}
是否属于大陆带宽节点: {'是' if node['china'] == 'true' else '否'}
是否支持web: {'支持' if node['web'] == 'true' else '不支持'}
是否支持udp: {'支持' if node['udp'] == 'true' else '不支持'} 
是否有防御: {'有' if node['fangyu'] == 'true' else '无'}
节点介绍: {node['notes']}
"""
                self.node_detail_text.setPlainText(detail_text)
                break

    def get_changes(self):
        changes = {}

        # 获取基本信息
        if self.node_combo.currentIndex() != 0:
            changes['node'] = self.node_combo.currentText()
        if self.type_combo.currentIndex() != 0:
            changes['type'] = self.type_combo.currentText()
        if self.local_ip_input.text():
            changes['localip'] = self.local_ip_input.text()
        if self.local_port_input.text():
            changes['nport'] = self.local_port_input.text()
        # 不再收集远程端口/绑定域名的更改

        # 加密和压缩
        if self.encryption_combo.currentIndex() != 0:
            changes['encryption'] = (self.encryption_combo.currentText() == "开启")
        if self.compression_combo.currentIndex() != 0:
            changes['compression'] = (self.compression_combo.currentText() == "开启")

        # API版本和强制修改标志
        changes['use_v1_api'] = self.v1_api_radio.isChecked()
        changes['force_update'] = self.force_update_checkbox.isChecked()

        # 处理备注修改
        if self.comment_checkbox.isChecked() and self.comment_input.text():
            changes['comment'] = self.comment_input.text()

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
    """隧道输出对话框"""
    output_update_signal = pyqtSignal(str, str, int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.setWindowTitle("隧道运行输出")
        self.resize(800, 600)
        self.setup_ui()
        self.output_update_signal.connect(self.add_output)

    def setup_ui(self):
        """设置UI"""
        layout = QVBoxLayout(self)
        run_layout = QHBoxLayout()

        run_layout.addWidget(QLabel("运行记录:"))
        self.run_selector = QComboBox()
        self.run_selector.currentIndexChanged.connect(self.on_run_changed)
        run_layout.addWidget(self.run_selector)
        run_layout.addStretch()
        layout.addLayout(run_layout)

        self.output_browser = QTextBrowser()
        self.output_browser.setOpenExternalLinks(True)
        layout.addWidget(self.output_browser)

        button_layout = QHBoxLayout()
        clear_button = QPushButton("清除输出")
        clear_button.clicked.connect(self.clear_output)
        close_button = QPushButton("关闭")
        close_button.clicked.connect(self.reject)
        button_layout.addWidget(clear_button)
        button_layout.addStretch()
        button_layout.addWidget(close_button)
        layout.addLayout(button_layout)
        self.current_tunnel = None
        self.runs_data = {}

    def add_output(self, tunnel_name, output_text, run_number):
        """添加输出内容"""
        if self.current_tunnel != tunnel_name:
            self.current_tunnel = tunnel_name
            self.runs_data = {}
            self.run_selector.blockSignals(True)
            self.run_selector.clear()
            self.run_selector.blockSignals(False)

        self.runs_data[run_number] = output_text

        current_runs = [self.run_selector.itemData(i) for i in range(self.run_selector.count())]
        if run_number not in current_runs:
            self.update_run_selector()
        else:
            if self.run_selector.currentData() == run_number:
                self.output_browser.setHtml(output_text)
                self.output_browser.verticalScrollBar().setValue(
                    self.output_browser.verticalScrollBar().maximum()
                )

    def update_run_selector(self):
        """更新运行记录选择器"""
        self.run_selector.blockSignals(True)
        self.run_selector.clear()
        run_numbers = sorted(self.runs_data.keys())
        for run_number in run_numbers:
            self.run_selector.addItem(f"运行 #{run_number}", run_number)
        if self.run_selector.count() > 0:
            latest_run = max(run_numbers) if run_numbers else None

            if latest_run is not None:
                latest_index = self.run_selector.findData(latest_run)
                if latest_index >= 0:
                    self.run_selector.setCurrentIndex(latest_index)

                    self.output_browser.setHtml(self.runs_data[latest_run])
                    self.output_browser.verticalScrollBar().setValue(
                        self.output_browser.verticalScrollBar().maximum()
                    )

        self.run_selector.blockSignals(False)

    def on_run_changed(self, index):
        """当选择的运行记录改变时"""
        if index < 0:
            return

        run_number = self.run_selector.itemData(index)
        if run_number in self.runs_data:
            self.output_browser.setHtml(self.runs_data[run_number])
            self.output_browser.verticalScrollBar().setValue(
                self.output_browser.verticalScrollBar().maximum()
            )

    def clear_output(self):
        """清除当前输出"""
        if self.current_tunnel and self.run_selector.currentData():
            run_number = self.run_selector.currentData()
            if run_number in self.runs_data:
                self.runs_data[run_number] = ""
                self.output_browser.setHtml("")
                self.parent.logger.info(f"已清除隧道 {self.current_tunnel} 运行 #{run_number} 的输出")

    def showEvent(self, event):
        """对话框显示时触发"""
        super().showEvent(event)
        if self.runs_data and self.run_selector.count() > 0:
            latest_run = max(self.runs_data.keys())
            latest_index = self.run_selector.findData(latest_run)

            if latest_index >= 0 and latest_index != self.run_selector.currentIndex():
                self.run_selector.setCurrentIndex(latest_index)

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
                            <li style="margin: 8px 0;"><a href="https://github.com/FengXiangqaq/Xingcheng-Chmlfrp-Lanucher" style="color: #0066cc; text-decoration: none;">▸ 枫相的xcl2</a></li>
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

        # === 消息推送标签页 ===
        notification_tab = QWidget()
        notification_layout = QVBoxLayout(notification_tab)

        # 邮件服务器配置
        mail_group = QGroupBox("邮件服务器配置")
        mail_layout = QFormLayout()

        # 预设邮箱服务选择
        self.mail_service_combo = QComboBox()
        self.mail_service_combo.addItem("自定义配置")
        self.mail_service_combo.addItems(message_push.CONFIG_MAP.keys())
        self.mail_service_combo.currentIndexChanged.connect(self.update_mail_config)

        # 邮件账号配置
        self.sender_email_input = QLineEdit()
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.smtp_server_input = QLineEdit()
        self.smtp_port_input = QLineEdit()
        self.smtp_port_input.setValidator(QIntValidator(1, 65535))

        # 测试按钮
        test_button = QPushButton("发送测试邮件")
        test_button.clicked.connect(self.send_test_email)

        mail_layout.addRow("预设服务:", self.mail_service_combo)
        mail_layout.addRow("发件邮箱:", self.sender_email_input)
        mail_layout.addRow("密码/授权码:", self.password_input)
        mail_layout.addRow("SMTP服务器:", self.smtp_server_input)
        mail_layout.addRow("SMTP端口:", self.smtp_port_input)
        mail_layout.addRow(test_button)
        mail_group.setLayout(mail_layout)

        # 通知选项
        notify_group = QGroupBox("通知设置")
        notify_layout = QVBoxLayout()

        self.tunnel_offline_check = QCheckBox("隧道离线通知")
        self.tunnel_start_check = QCheckBox("隧道启动通知")

        self.node_offline_check = QCheckBox("节点离线通知")
        self.node_online_check = QCheckBox("节点上线通知")
        self.node_added_check = QCheckBox("节点上架通知")
        self.node_removed_check = QCheckBox("节点下架通知")

        notify_layout.addWidget(self.tunnel_offline_check)
        notify_layout.addWidget(self.tunnel_start_check)
        notify_layout.addWidget(self.node_offline_check)
        notify_layout.addWidget(self.node_online_check)
        notify_layout.addWidget(self.node_added_check)
        notify_layout.addWidget(self.node_removed_check)
        notify_group.setLayout(notify_layout)

        notification_layout.addWidget(mail_group)
        notification_layout.addWidget(notify_group)
        notification_layout.addStretch()

        tab_widget.addTab(notification_tab, "消息推送")

    def update_mail_config(self, index):
        """当选择预设服务时自动填充配置"""
        if index == 0:  # 自定义
            return

        service = self.mail_service_combo.currentText()
        server, port = message_push.CONFIG_MAP[service]
        self.smtp_server_input.setText(server)
        self.smtp_port_input.setText(str(port))

    def send_test_email(self):
        """发送测试邮件"""
        config = self.get_mail_config()
        if not config.get("sender_email") or not config.get("password"):
            QMessageBox.warning(self, "错误", "请先填写邮箱和密码")
            return

        try:
            notifier = message_push(
                sender_email=config["sender_email"],
                password=config["password"],
                receiver_email=config["sender_email"],  # 发件和收件相同
                smtp_server=config.get("smtp_server"),
                port=config.get("smtp_port")
            )
            success, msg = notifier.send(
                subject="测试邮件",
                body=f"这是一封来自{APP_NAME}的测试邮件\n发送时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            )
            if success:
                QMessageBox.information(self, "成功", "测试邮件发送成功！")
            else:
                QMessageBox.warning(self, "失败", f"发送失败：{msg}")
        except Exception as e:
            QMessageBox.critical(self, "错误", f"发送测试邮件时发生异常：{str(e)}")

    def get_mail_config(self):
        """获取邮件配置"""
        return {
            "sender_email": self.sender_email_input.text(),
            "password": self.password_input.text(),
            "smtp_server": self.smtp_server_input.text(),
            "smtp_port": self.smtp_port_input.text(),
            "notifications": {
                "tunnel_offline": self.tunnel_offline_check.isChecked(),
                "tunnel_start": self.tunnel_start_check.isChecked(),
                "node_offline": self.node_offline_check.isChecked(),
                "node_online": self.node_online_check.isChecked(),
                "node_added": self.node_added_check.isChecked(),
                "node_removed": self.node_removed_check.isChecked()
            }
        }

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

            # 获取自动启动的隧道ID列表
            auto_start_tunnels = settings_content.get('auto_start_tunnels', [])

            if self.parent.token:
                # 获取用户的隧道列表
                tunnels = API.get_user_tunnels(self.parent.token)
                if tunnels:
                    for tunnel in tunnels:
                        # 创建带有隧道名称和备注的项目
                        tunnel_id = str(tunnel['id'])
                        tunnel_name = tunnel['name']
                        comment = self.parent.get_tunnel_comment(tunnel_id)

                        # 设置显示文本：如果有备注则显示名称和备注，否则只显示名称
                        display_text = tunnel_name
                        if comment:
                            display_text += f" ({comment})"

                        item = QListWidgetItem(display_text)
                        item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)

                        # 将隧道ID存储为用户数据
                        item.setData(Qt.ItemDataRole.UserRole, tunnel_id)

                        # 设置选中状态
                        item.setCheckState(
                            Qt.CheckState.Checked if tunnel_id in auto_start_tunnels
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

        # 加载邮件配置
        mail_config = settings_content.get('mail', {})
        self.sender_email_input.setText(mail_config.get('sender_email', ''))
        self.password_input.setText(mail_config.get('password', ''))
        self.smtp_server_input.setText(mail_config.get('smtp_server', ''))
        self.smtp_port_input.setText(str(mail_config.get('smtp_port', 465)))

        # 加载通知设置
        notify_settings = mail_config.get('notifications', {})
        self.tunnel_offline_check.setChecked(notify_settings.get('tunnel_offline', False))
        self.node_offline_check.setChecked(notify_settings.get('node_offline', False))
        self.tunnel_start_check.setChecked(notify_settings.get('tunnel_start', False))
        self.node_online_check.setChecked(notify_settings.get('node_online', False))
        self.node_added_check.setChecked(notify_settings.get('node_added', False))
        self.node_removed_check.setChecked(notify_settings.get('node_removed', False))


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

            # 保存自动启动隧道的ID而非名称
            auto_start_tunnels = []
            for i in range(self.tunnel_list.count()):
                item = self.tunnel_list.item(i)
                if item.flags() & Qt.ItemFlag.ItemIsUserCheckable:
                    if item.checkState() == Qt.CheckState.Checked:
                        # 存储隧道ID而不是名称
                        tunnel_id = item.data(Qt.ItemDataRole.UserRole)
                        auto_start_tunnels.append(tunnel_id)

            settings_pathway = get_absolute_path("settings.json")
            settings_content = {'auto_start_tunnels': auto_start_tunnels, 'theme': self.get_selected_theme(),
                                'log_size_mb': log_size, 'backup_count': backup_count, 'mail': self.get_mail_config()}

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

        self.local_update_timer = QTimer(self)
        self.local_update_timer.timeout.connect(self.check_local_updates)
        self.local_update_timer.start(1000)

        if os.path.exists("favicon.ico"):
            self.setWindowIcon(QIcon("favicon.ico"))

        self.init_ui()
        QTimer.singleShot(0, self.check_for_updates)
        self.check_local_updates()  # Initial check

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(15)

        version_layout = QFormLayout()
        self.current_version_label = QLabel(APP_VERSION)
        self.latest_version_label = QLabel("检查中...")
        version_layout.addRow("当前版本:", self.current_version_label)
        version_layout.addRow("最新版本:", self.latest_version_label)
        layout.addLayout(version_layout)

        buttons_layout = QHBoxLayout()

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

        self.refresh_mirrors_button = QPushButton("刷新镜像源")
        self.refresh_mirrors_button.setStyleSheet("""
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
        """)
        self.refresh_mirrors_button.clicked.connect(self.refresh_mirrors)

        buttons_layout.addWidget(self.check_button)
        buttons_layout.addWidget(self.refresh_mirrors_button)
        layout.addLayout(buttons_layout)

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

        download_group = QGroupBox("下载更新")
        download_layout = QVBoxLayout(download_group)

        self.mirror_combo = QComboBox()
        self.mirror_combo.addItem("请选择下载源...")
        self.mirror_combo.setStyleSheet("""
            QComboBox {
                border-radius: 5px;
                padding: 5px;
            }
        """)
        download_layout.addWidget(self.mirror_combo)

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

    def refresh_mirrors(self):
        """手动刷新镜像源"""
        self.update_content.setPlainText("正在刷新镜像源列表...")
        self.refresh_mirrors_button.setEnabled(False)

        self.mirror_thread = QThread()
        self.mirror_worker = MirrorRefreshWorker()
        self.mirror_worker.moveToThread(self.mirror_thread)

        self.mirror_worker.finished.connect(self.handle_mirror_refresh)
        self.mirror_worker.error.connect(self.handle_mirror_error)
        self.mirror_thread.started.connect(self.mirror_worker.run)
        self.mirror_thread.finished.connect(self.mirror_thread.deleteLater)

        self.mirror_thread.start()

    def handle_mirror_refresh(self, mirrors):
        """处理成功的刷新"""
        self.mirror_thread.quit()
        self.mirror_thread.wait()

        global MIRROR_PREFIXES
        MIRROR_PREFIXES = mirrors

        self.update_content.setPlainText(f"镜像源已刷新，获取到 {len(mirrors)} 个镜像源:\n\n" + "\n".join(mirrors))
        self.refresh_mirrors_button.setEnabled(True)

        if self.download_links:
            self.populate_mirror_combo()

    def handle_mirror_error(self, error_msg):
        """处理失败的刷新"""
        self.mirror_thread.quit()
        self.mirror_thread.wait()

        self.update_content.setPlainText(f"刷新镜像源失败:\n{error_msg}")
        self.refresh_mirrors_button.setEnabled(True)

    def populate_mirror_combo(self):
        """填充镜像链接"""
        self.mirror_combo.clear()
        self.mirror_combo.addItem("请选择下载源...")

        original_url = None
        for url in self.download_links:
            if "github.com" in url:
                original_url = url
                break

        if original_url:
            self.mirror_combo.addItem("GitHub 官方源", original_url)

            for i, prefix in enumerate(MIRROR_PREFIXES):
                mirror_url = original_url
                self.mirror_combo.addItem(f"镜像 {i + 1}: {prefix}", mirror_url)
        else:
            for i, url in enumerate(self.download_links):
                self.mirror_combo.addItem(f"下载源 {i + 1}", url)

    def check_local_updates(self):
        """检查本地是否有可用的更新程序包"""
        local_updates = glob.glob("CUL*.zip")
        if local_updates:
            latest_file = max(local_updates, key=lambda x: [
                int(num) for num in re.findall(r'CUL(\d+)\.(\d+)\.(\d+)\.zip', x)[0]
            ])
            version = re.search(r'CUL(\d+\.\d+\.\d+)\.zip', latest_file).group(1)

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
        """下载or更新"""
        if self.download_button.text() == "开始下载":
            self.start_download()
        else:
            self.start_update()

    def start_update(self):
        """执行更新进程"""
        reply = QMessageBox.question(
            self, "确认更新",
            "即将关闭程序并执行更新，是否继续?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.No:
            return

        try:
            subprocess.Popen(
                ["start", "CUL_update.exe"],
                shell=True
            )
            time.sleep(2)
            self.cleanup()
        except Exception as e:
            QMessageBox.critical(
                self, "更新错误",
                f"无法启动更新程序: {str(e)}"
            )

    def cleanup(self):
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

            subprocess.run(["taskkill", "/f", "/im", "frpc.exe"],
                           stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)

        except Exception as e:
            logger.error(f"清理进程时出错: {str(e)}")

        QApplication.quit()

    def apply_theme(self, is_dark):
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
        self.thread.quit()
        self.thread.wait()

        self.check_button.setEnabled(True)
        self.latest_version_label.setText(latest_version)

        html = markdown.markdown(update_content or "无更新说明", extensions=['nl2br'])
        self.update_content.setHtml(html)

        self.download_links = download_links

        if latest_version == APP_VERSION:
            QMessageBox.information(self, "检查更新", "当前已是最新版本！")
            return

        if not download_links:
            self.mirror_combo.addItem("无可用下载链接")
            return

        self.populate_mirror_combo()

        self.mirror_combo.currentIndexChanged.connect(self.enable_download_button)

        current = tuple(map(int, re.sub(r"[^0-9.]", "", APP_VERSION).split(".")))
        latest = tuple(map(int, re.sub(r"[^0-9.]", "", latest_version).split(".")))

        if latest > current:
            QMessageBox.information(self, "发现新版本",
                                    f"发现新版本 {latest_version}，请下载更新！")

    def handle_update_error(self, error_msg):
        self.thread.quit()
        self.thread.wait()

        self.check_button.setEnabled(True)
        self.latest_version_label.setText("检查失败")
        self.update_content.setPlainText(f"检查更新时出错:\n{error_msg}")
        self.mirror_combo.addItem("无法获取下载链接")

        QMessageBox.warning(self, "检查更新失败", error_msg)

    def enable_download_button(self, index):
        self.download_button.setEnabled(index > 0)

    def start_download(self):
        index = self.mirror_combo.currentIndex()
        if index <= 0:
            return

        url = self.mirror_combo.itemData(index)
        version = self.latest_version_label.text()
        filename = f"CUL{version}.zip"
        save_path = os.path.join(os.getcwd(), filename)

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
        if bytes_total > 0:
            progress = int((bytes_received / bytes_total) * 100)
            self.progress_bar.setValue(progress)
            self.progress_bar.setFormat(
                f"下载中... {progress}% ({bytes_received / 1024 / 1024:.1f}MB/{bytes_total / 1024 / 1024:.1f}MB)")

    def download_finished(self, save_path):
        try:
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

class MirrorRefreshWorker(QObject):
    """刷新镜像链接"""
    finished = pyqtSignal(list)
    error = pyqtSignal(str)

    def __init__(self):
        super().__init__()

    def run(self):
        try:
            mirrors = get_mirrors()
            self.finished.emit(mirrors)
        except Exception as e:
            self.error.emit(f"刷新镜像源失败: {str(e)}")

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

class ApiStatusCard(QFrame):
    """显示API服务器状态的卡片"""
    clicked = pyqtSignal(object)
    def __init__(self, api_info=None):
        super().__init__()
        self.api_info = api_info or {}
        self.is_selected = False
        self.initUI()
        self.updateStyle()
        self.startAutoRefresh()

    def initUI(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(10, 10, 10, 10)

        # 标题和服务器名称
        name_label = QLabel(f"<b>API服务器: {self.api_info.get('serverName', '未知')}</b>")
        name_label.setObjectName("nameLabel")
        layout.addWidget(name_label)

        # 总负载
        self.load_label = QLabel(f"总负载: {self.api_info.get('load', 0):.2f}")
        layout.addWidget(self.load_label)

        # 指标显示
        metrics = self.api_info.get('metrics', {})
        self.cpu_label = QLabel(f"CPU使用率: {metrics.get('cpu', 0):.2f}%")
        self.memory_label = QLabel(f"内存使用率: {metrics.get('memory', 0):.2f}%")

        layout.addWidget(self.cpu_label)
        layout.addWidget(self.memory_label)

        self.setLayout(layout)
        self.setFixedSize(250, 150)  # 与NodeCard保持一致的尺寸

    def updateStyle(self):
        self.setStyleSheet("""
            ApiStatusCard {
                border: 1px solid #d0d0d0;
                border-radius: 5px;
                padding: 10px;
                margin: 5px;
            }
            ApiStatusCard:hover {
                background-color: rgba(240, 240, 240, 50);
            }
            #nameLabel {
                font-size: 16px;
                font-weight: bold;
            }
        """)

    def startAutoRefresh(self):
        """开始自动刷新定时器"""
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.refreshApiStatus)
        self.timer.start(30000)  # 每30秒刷新一次

    def refreshApiStatus(self):
        """刷新API服务器状态"""
        try:
            url = "http://cf-v2.uapis.cn/api/server-status"
            headers = get_headers()
            response = requests.get(url, headers=headers, timeout=5)

            if response.status_code == 200:
                self.api_info = response.json()
                self.updateDisplay()
            else:
                self.markAsOffline()
        except Exception as e:
            print(f"获取API状态时出错: {e}")
            self.markAsOffline()

    def updateDisplay(self):
        """更新显示的API状态信息"""
        if not self.api_info:
            self.markAsOffline()
            return

        # 更新标题
        for i, child in enumerate(self.children()):
            if isinstance(child, QLabel) and i == 1:  # 第一个标签是标题
                child.setText(f"<b>API服务器: {self.api_info.get('serverName', '未知')}</b>")
                break

        # 更新数据标签
        metrics = self.api_info.get('metrics', {})
        self.load_label.setText(f"总负载: {self.api_info.get('load', 0):.2f}")
        self.cpu_label.setText(f"CPU使用率: {metrics.get('cpu', 0):.2f}%")
        self.memory_label.setText(f"内存使用率: {metrics.get('memory', 0):.2f}%")

        self.update()  # 触发重绘

    def markAsOffline(self):
        """标记API服务器为离线状态"""
        # 更新标题
        for i, child in enumerate(self.children()):
            if isinstance(child, QLabel) and i == 1:  # 第一个标签是标题
                child.setText("<b>API服务器: 离线</b>")
                break

        self.load_label.setText("总负载: 未知")
        self.cpu_label.setText("CPU使用率: 未知")
        self.memory_label.setText("内存使用率: 未知")
        self.update()

    def paintEvent(self, event):
        super().paintEvent(event)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        # 状态指示器 (同NodeCard)
        if self.api_info and 'load' in self.api_info:
            load = self.api_info.get('load', 0)
            if load < 0.3:
                color = QColor(0, 255, 0)  # 绿色
            elif load < 0.7:
                color = QColor(255, 165, 0)  # 橙色
            else:
                color = QColor(255, 0, 0)  # 红色
        else:
            color = QColor(255, 0, 0)  # 红色 (离线)

        painter.setPen(QPen(color, 2))
        painter.setBrush(color)
        painter.drawEllipse(self.width() - 20, 10, 10, 10)

    def setSelected(self, selected):
        """设置选中状态 (与NodeCard兼容)"""
        self.is_selected = selected
        if selected:
            self.setStyleSheet(
                self.styleSheet() + "ApiStatusCard { border: 2px solid #0066cc; background-color: rgba(224, 224, 224, 50); }")
        else:
            self.setStyleSheet(self.styleSheet().replace(
                "ApiStatusCard { border: 2px solid #0066cc; background-color: rgba(224, 224, 224, 50); }", ""))

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit(self.api_info)
        super().mousePressEvent(event)

class BackupNodeConfigDialog(QDialog):
    def __init__(self, tunnel_info, token, parent=None):
        super().__init__(parent)
        self.tunnel_info = tunnel_info
        self.token = token
        self.parent = parent
        self.backup_nodes = []
        self.domain_info = None

        self.setWindowTitle(f"配置隧道 '{tunnel_info['name']}' 的备用节点")
        self.setMinimumWidth(600)

        self.init_ui()
        self.load_existing_config()

    def get_tunnel_target(self, tunnel_info, node_info):
        try:
            if not tunnel_info or not node_info:
                self.logger.error(f"无法获取隧道目标: tunnel_info={bool(tunnel_info)}, node_info={bool(node_info)}")
                return None

            tunnel_type = tunnel_info.get('type', '').lower()

            if tunnel_type in ['http', 'https']:
                return tunnel_info.get('dorp', '')
            else:
                node_domain = node_info.get('ip', node_info.get('name', ''))
                return node_domain
        except Exception as e:
            self.logger.error(f"获取隧道目标时发生错误: {str(e)}")
            return None

    def apply_theme(self, dark_theme):
        if dark_theme:
            self.setStyleSheet("""
                QDialog { background-color: #2D2D2D; color: #FFFFFF; }
                QLabel { color: #FFFFFF; }
                QPushButton { background-color: #0D6EFD; color: white; border-radius: 4px; padding: 6px 12px; }
                QPushButton:hover { background-color: #0B5ED7; }
                QGroupBox { color: #FFFFFF; border: 1px solid #444444; border-radius: 4px; margin-top: 8px; }
                QGroupBox::title { subcontrol-origin: margin; left: 8px; padding: 0 3px; }
                QComboBox, QLineEdit { background-color: #3D3D3D; color: #FFFFFF; border: 1px solid #555555; border-radius: 4px; padding: 4px; }
                QListWidget { background-color: #3D3D3D; color: #FFFFFF; border: 1px solid #555555; border-radius: 4px; }
                QCheckBox { color: #FFFFFF; }
                QCheckBox::indicator { width: 15px; height: 15px; }
            """)
        else:
            self.setStyleSheet("""
                QDialog { background-color: #FFFFFF; color: #212529; }
                QLabel { color: #212529; }
                QPushButton { background-color: #0D6EFD; color: white; border-radius: 4px; padding: 6px 12px; }
                QPushButton:hover { background-color: #0B5ED7; }
                QGroupBox { color: #212529; border: 1px solid #DEE2E6; border-radius: 4px; margin-top: 8px; }
                QGroupBox::title { subcontrol-origin: margin; left: 8px; padding: 0 3px; }
                QComboBox, QLineEdit { background-color: #FFFFFF; color: #212529; border: 1px solid #CED4DA; border-radius: 4px; padding: 4px; }
                QListWidget { background-color: #FFFFFF; color: #212529; border: 1px solid #CED4DA; border-radius: 4px; }
                QCheckBox { color: #212529; }
                QCheckBox::indicator { width: 15px; height: 15px; }
            """)

    def init_ui(self):
        layout = QVBoxLayout(self)

        node_group = QGroupBox("选择备用节点")
        node_layout = QVBoxLayout()

        self.node_list = QListWidget()
        self.node_list.setSelectionMode(QListWidget.SelectionMode.MultiSelection)

        nodes = API.get_nodes()
        current_node = self.tunnel_info['node']
        for node in nodes:
            if node['name'] != current_node:
                item = QListWidgetItem(node['name'])
                self.node_list.addItem(item)

        node_layout.addWidget(QLabel("选择备用节点 (可多选):"))
        node_layout.addWidget(self.node_list)
        node_group.setLayout(node_layout)
        layout.addWidget(node_group)

        domain_group = QGroupBox("域名绑定配置")
        self.domain_layout = QVBoxLayout()

        self.use_domain_checkbox = QCheckBox("为此隧道绑定域名")
        self.domain_layout.addWidget(self.use_domain_checkbox)

        domain_form = QFormLayout()

        self.domain_type_combo = QComboBox()
        self.domain_type_combo.addItems(["使用现有域名", "创建新域名"])
        domain_form.addRow("域名类型:", self.domain_type_combo)

        self.existing_domain_combo = QComboBox()
        self.load_domains_for_combo()
        domain_form.addRow("选择域名:", self.existing_domain_combo)

        self.new_domain_widget = QWidget()
        new_domain_layout = QFormLayout(self.new_domain_widget)

        self.main_domain_combo = QComboBox()
        self.load_main_domains()

        self.subdomain_input = QLineEdit()

        new_domain_layout.addRow("主域名:", self.main_domain_combo)
        new_domain_layout.addRow("子域名:", self.subdomain_input)

        self.domain_layout.addLayout(domain_form)
        self.domain_layout.addWidget(self.new_domain_widget)
        self.new_domain_widget.hide()

        domain_group.setLayout(self.domain_layout)
        layout.addWidget(domain_group)

        self.use_domain_checkbox.toggled.connect(self.toggle_domain_config)
        self.domain_type_combo.currentIndexChanged.connect(self.toggle_domain_type)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.save_config)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self.toggle_domain_config(False)

    def toggle_domain_config(self, checked):
        self.domain_type_combo.setEnabled(checked)
        self.existing_domain_combo.setEnabled(checked)
        self.new_domain_widget.setVisible(checked and self.domain_type_combo.currentIndex() == 1)

    def toggle_domain_type(self, index):
        self.existing_domain_combo.setVisible(index == 0)
        self.new_domain_widget.setVisible(index == 1)

    def load_domains_for_combo(self):
        try:
            url = f"http://cf-v2.uapis.cn/get_user_free_subdomains"
            params = {"token": self.token}
            headers = get_headers()
            response = requests.get(url, headers=headers, params=params)
            data = response.json()

            if data['code'] == 200:
                self.existing_domain_combo.clear()
                for domain in data['data']:
                    if domain['type'] == 'CNAME':
                        domain_text = f"{domain['record']}.{domain['domain']}"
                        self.existing_domain_combo.addItem(domain_text, domain)
            else:
                self.parent.logger.error(f"获取域名列表失败: {data.get('msg')}")
        except Exception as e:
            self.parent.logger.error(f"加载域名列表失败: {str(e)}")

    def load_main_domains(self):
        """将可用的主域加载到组合框"""
        try:
            url = "http://cf-v2.uapis.cn/list_available_domains"
            headers = get_headers()
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                if data['code'] == 200:
                    self.main_domain_combo.clear()
                    for domain_info in data['data']:
                        self.main_domain_combo.addItem(domain_info['domain'])
                else:
                    self.parent.logger.error(f"获取主域名失败: {data['msg']}")
            else:
                self.parent.logger.error(f"获取主域名请求失败: 状态码 {response.status_code}")
        except Exception as e:
            self.parent.logger.error(f"加载主域名时发生错误: {str(e)}")

    def get_node_info(self, node_name):
        """获取节点信息"""
        try:
            url = f"http://cf-v2.uapis.cn/nodeinfo"
            params = {
                'token': self.token,
                'node': node_name
            }
            headers = get_headers()
            response = requests.get(url, headers=headers, params=params)
            data = response.json()
            if data['code'] == 200:
                return data['data']
            else:
                self.logger.error(f"获取节点信息失败: {data.get('msg', '')}")
                return None
        except Exception as e:
            self.logger.error(f"获取节点信息时发生错误: {str(e)}")
            return None

    def check_domain_target(self, domain_config, node_name, tunnel_info):
        try:
            if not domain_config or not node_name or not tunnel_info:
                self.logger.error(
                    f"Missing required data for domain check: domain_config={bool(domain_config)}, node_name={bool(node_name)}")
                return False
            url = "http://cf-v2.uapis.cn/get_user_free_subdomains"
            params = {"token": self.token}

            domain = domain_config.get('domain', '')
            record = domain_config.get('record', '')
            if not domain or not record:
                self.logger.error(f"Domain config is missing required fields: {domain_config}")
                return False

            headers = get_headers()
            try:
                response = requests.get(url, headers=headers, params=params)
                data = response.json()

                if 'code' not in data:
                    self.logger.error(f"API返回格式错误，缺少'code'字段: {data}")
                    return False

                if data['code'] != 200:
                    self.logger.error(f"获取域名信息失败: {data.get('msg', '')}")
                    return False

                if 'data' not in data or not isinstance(data['data'], list):
                    self.logger.error(f"API返回格式错误，'data'字段不是列表: {data}")
                    return False
            except requests.exceptions.RequestException as e:
                self.logger.error(f"请求域名信息失败: {str(e)}")
                return False
            except ValueError as e:
                self.logger.error(f"解析API响应失败: {str(e)}")
                return False

            domain_record = None
            for item in data['data']:
                if (item.get('domain') == domain and
                        item.get('record') == record):
                    domain_record = item
                    break

            if not domain_record:
                self.logger.error(f"未找到域名记录: {record}.{domain}")
                return False
            current_target = domain_record.get('target', '')
            node_info = self.get_node_info(node_name)
            if not node_info:
                self.logger.error(f"无法获取节点 {node_name} 的信息")
                return False
            expected_target = self.get_tunnel_target(tunnel_info, node_info)
            if not expected_target:
                self.logger.error(f"无法计算隧道 {tunnel_info.get('name', 'unknown')} 的预期目标")
                return False
            if current_target == expected_target:
                self.logger.info(f"域名 {record}.{domain} 当前指向正确的节点目标: {current_target}")
                return True
            else:
                self.logger.info(f"域名指向不正确: 当前目标={current_target}, 预期目标={expected_target}")
                return False

        except Exception as e:
            self.logger.error(f"检查域名目标时发生错误: {str(e)}")
            return False

    def check_domain_target_status(self, domain_info):
        """检查域名指向状态并显示结果"""
        if not domain_info or not self.parent:
            return

        # 获取当前隧道信息和节点
        tunnel_info = self.tunnel_info
        if not tunnel_info:
            return

        node_name = tunnel_info.get('node')
        if not node_name:
            return

        # 调用父窗口的check_domain_target方法来检查域名指向
        is_correct = self.check_domain_target(domain_info, node_name, tunnel_info)

        # 显示检查结果
        if is_correct:
            QMessageBox.information(
                self,
                "域名检查",
                f"域名 {domain_info.get('record', '')}.{domain_info.get('domain', '')} 已正确指向节点 {node_name}"
            )
        else:
            QMessageBox.warning(
                self,
                "域名检查",
                f"域名 {domain_info.get('record', '')}.{domain_info.get('domain', '')} 未正确指向节点 {node_name}"
            )

    def load_existing_config(self):
        """在BackupNodeConfigDialog中加载现有备用节点配置，并显示域名更新状态"""
        config_path = get_absolute_path("backup_config.json")
        if os.path.exists(config_path):
            try:
                if os.path.getsize(config_path) == 0:
                    with open(config_path, 'w') as f:
                        json.dump({}, f)
                    return

                with open(config_path, 'r') as f:
                    try:
                        configs = json.load(f)
                    except json.JSONDecodeError:
                        self.parent.logger.error(f"备用节点配置文件格式错误，重新初始化")
                        with open(config_path, 'w') as f:
                            json.dump({}, f)
                        return

                    tunnel_id = str(self.tunnel_info['id'])
                    if tunnel_id in configs:
                        config = configs[tunnel_id]

                        backup_nodes = config.get('backup_nodes', [])
                        for i in range(self.node_list.count()):
                            item = self.node_list.item(i)
                            if item.text() in backup_nodes:
                                item.setSelected(True)

                        domain_info = config.get('domain')
                        if domain_info:
                            self.use_domain_checkbox.setChecked(True)

                            if domain_info.get('is_new', False):
                                self.domain_type_combo.setCurrentIndex(1)
                                self.subdomain_input.setText(domain_info.get('record', ''))
                                main_domain = domain_info.get('domain', '')
                                index = self.main_domain_combo.findText(main_domain)
                                if index >= 0:
                                    self.main_domain_combo.setCurrentIndex(index)
                            else:
                                self.domain_type_combo.setCurrentIndex(0)
                                domain_text = f"{domain_info.get('record', '')}.{domain_info.get('domain', '')}"
                                index = self.existing_domain_combo.findText(domain_text)
                                if index >= 0:
                                    self.existing_domain_combo.setCurrentIndex(index)

                            # 添加域名更新状态显示
                            if domain_info.get('last_updated'):
                                last_updated = domain_info.get('last_updated')
                                domain_status = QLabel(f"上次域名更新: {last_updated}")
                                domain_status.setStyleSheet("color: #0066cc; font-size: 10px;")
                                self.domain_layout.addWidget(domain_status)

                                # 添加域名指向状态检查
                                self.check_domain_target = QPushButton("检查域名指向")
                                self.check_domain_target.clicked.connect(
                                    lambda: self.check_domain_target_status(domain_info))
                                self.domain_layout.addWidget(self.check_domain_target)

                            self.toggle_domain_config(True)
                            self.toggle_domain_type(self.domain_type_combo.currentIndex())
            except Exception as e:
                self.parent.logger.error(f"加载备用节点配置失败: {str(e)}")
        else:
            try:
                with open(config_path, 'w') as f:
                    json.dump({}, f)
                self.parent.logger.info("已创建备用节点配置文件")
            except Exception as e:
                self.parent.logger.error(f"创建备用节点配置文件失败: {str(e)}")

    def save_config(self):
        try:
            selected_nodes = []
            for item in self.node_list.selectedItems():
                selected_nodes.append(item.text())

            domain_config = None
            if self.use_domain_checkbox.isChecked():
                if self.domain_type_combo.currentIndex() == 0:  # Existing domain
                    if self.existing_domain_combo.count() == 0:
                        QMessageBox.warning(self, "警告", "没有可用的域名")
                        return

                    domain_data = self.existing_domain_combo.currentData()
                    if domain_data:
                        domain_config = {
                            'domain': domain_data['domain'],
                            'record': domain_data['record'],
                            'is_new': False
                        }
                else:
                    if not self.subdomain_input.text():
                        QMessageBox.warning(self, "警告", "请输入子域名")
                        return

                    domain_config = {
                        'domain': self.main_domain_combo.currentText(),
                        'record': self.subdomain_input.text(),
                        'is_new': True
                    }

            if not selected_nodes:
                config_path = get_absolute_path("backup_config.json")
                configs = {}
                if os.path.exists(config_path):
                    try:
                        with open(config_path, 'r') as f:
                            configs = json.load(f)
                    except:
                        configs = {}

                tunnel_id = str(self.tunnel_info['id'])
                if tunnel_id in configs:
                    del configs[tunnel_id]

                with open(config_path, 'w') as f:
                    json.dump(configs, f, indent=4)
                self.accept()
                return

            config_path = get_absolute_path("backup_config.json")
            configs = {}
            if os.path.exists(config_path):
                try:
                    with open(config_path, 'r') as f:
                        configs = json.load(f)
                except:
                    configs = {}

            tunnel_id = str(self.tunnel_info['id'])
            configs[tunnel_id] = {
                'backup_nodes': selected_nodes,
                'domain': domain_config
            }

            with open(config_path, 'w') as f:
                json.dump(configs, f, indent=4)

            self.accept()
        except Exception as e:
            self.parent.logger.error(f"保存备用节点配置失败: {str(e)}")
            QMessageBox.warning(self, "错误", f"保存配置失败: {str(e)}")


class MainWindow(QMainWindow):
    """主窗口"""
    def __init__(self):
        super().__init__()
        self.a = []
        self.b = []
        self.last_node_list = []
        self.current_nodes = []
        self.previous_nodes = []
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

        self.mail_notifier = None
        self.load_mail_config()
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

        self.node_check_timer = QTimer(self)
        self.node_check_timer.timeout.connect(self.check_node_status_changes)
        self.node_check_timer.start(100)

        self.update_timer = QTimer(self)
        self.update_timer.timeout.connect(self.auto_update)
        self.update_timer.start(40000)  # 40秒更新一次

        self.user_info = None
        self.node_list = QWidget()

        self.running_tunnels = {}
        self.running_tunnels_mutex = QMutex()

        # 设置两个不同的计时器


        self.tunnel_check_timer = QTimer(self)
        self.tunnel_check_timer.timeout.connect(self.check_node_status)
        self.tunnel_check_timer.start(600000)  # 每10分钟处理隧道切换

        # 初始化UI
        self.initUI()
        # 确保在初始化后立即应用主题
        self.apply_theme()
        # 加载凭证和自动登录
        self.load_credentials()
        self.auto_login()

    def initUI(self):
        # 设置窗口标题和大小
        self.setWindowTitle(APP_NAME + "-ChmlFrp第三方启动器")
        self.setGeometry(100, 100, 800, 600)
        # 设置无边框窗口
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint)
        # 设置背景透明
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)

        # 创建中央窗口部件
        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)

        # 设置主布局
        main_layout = QVBoxLayout(central_widget)

        # 创建背景框架
        self.background_frame = QFrame(self)
        self.background_frame.setObjectName("background")
        background_layout = QVBoxLayout(self.background_frame)
        main_layout.addWidget(self.background_frame)

        # 创建带有图标的标题栏
        title_bar = QWidget()
        title_layout = QHBoxLayout(title_bar)

        # 在标题左侧添加favicon图标
        icon_label = QLabel()
        # 加载favicon.ico图标
        icon_pixmap = QPixmap(get_absolute_path("favicon-d.ico"))
        if not icon_pixmap.isNull():
            # 将图标缩放到24x24像素，保持纵横比
            icon_pixmap = icon_pixmap.scaled(25, 25, Qt.AspectRatioMode.KeepAspectRatio,
                                             Qt.TransformationMode.SmoothTransformation)
            icon_label.setPixmap(icon_pixmap)
        else:
            # 图标加载失败时记录错误
            self.logger.error("无法加载图标: favicon-d.ico")
        # 将图标添加到标题布局中
        title_layout.addWidget(icon_label)

        # 添加标题文本
        title_label = QLabel(APP_NAME + "-ChmlFrp第三方启动器")
        title_layout.addWidget(title_label)
        title_layout.addStretch(1)

        # 添加设置按钮
        self.settings_button = QPushButton("设置")
        self.settings_button.clicked.connect(self.show_settings)
        title_layout.addWidget(self.settings_button)

        # 添加检测更新按钮
        self.settings_button = QPushButton("检测更新")
        self.settings_button.clicked.connect(self.show_update)
        title_layout.addWidget(self.settings_button)

        # 添加最小化和关闭按钮
        min_button = QPushButton("－")
        min_button.clicked.connect(self.showMinimized)
        close_button = QPushButton("×")
        close_button.clicked.connect(self.close)

        title_layout.addWidget(min_button)
        title_layout.addWidget(close_button)
        background_layout.addWidget(title_bar)

        # 设置内容布局
        content_layout = QHBoxLayout()

        # 创建左侧菜单
        menu_widget = QWidget()
        menu_layout = QVBoxLayout(menu_widget)

        # 创建菜单按钮
        self.user_info_button = QPushButton("用户信息")
        self.tunnel_button = QPushButton("隧道管理")
        self.domain_button = QPushButton("域名管理")
        self.node_button = QPushButton("节点状态")

        # 连接按钮点击事件
        self.user_info_button.clicked.connect(lambda: self.switch_tab("user_info"))
        self.tunnel_button.clicked.connect(lambda: self.switch_tab("tunnel"))
        self.domain_button.clicked.connect(lambda: self.switch_tab("domain"))
        self.node_button.clicked.connect(lambda: self.switch_tab("node"))

        # 将按钮添加到菜单布局
        menu_layout.addWidget(self.user_info_button)
        menu_layout.addWidget(self.tunnel_button)
        menu_layout.addWidget(self.domain_button)
        menu_layout.addWidget(self.node_button)
        menu_layout.addStretch(1)  # 添加弹性空间，使按钮位于顶部

        # 将菜单添加到内容布局
        content_layout.addWidget(menu_widget)

        # 创建内容堆栈部件，用于切换不同页面
        self.content_stack = QStackedWidget()
        content_layout.addWidget(self.content_stack, 1)

        # 将内容布局添加到背景布局
        background_layout.addLayout(content_layout)

        # 添加日志显示框
        background_layout.addWidget(self.log_display)

        # 添加作者信息
        author_info = QLabel("本程序基于ChmlFrp apiv2开发 作者: boring_student")
        author_info.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignBottom)
        author_info.setStyleSheet("font-size: 7pt; color: #888888; background: transparent; padding: 2px;")
        author_info.setProperty("author_info", True)
        author_info.setFixedHeight(18)

        # 创建底部布局
        bottom_layout = QHBoxLayout()
        bottom_layout.addStretch(1)
        bottom_layout.addWidget(author_info)
        bottom_layout.setContentsMargins(0, 0, 5, 2)
        background_layout.addLayout(bottom_layout)

        # 设置各页面
        self.setup_user_info_page()
        self.setup_tunnel_page()
        self.setup_domain_page()
        self.setup_node_page()

        # 默认显示用户信息页面
        self.switch_tab("user_info")

        # 保存所有标签按钮的引用
        self.tab_buttons = [
            self.user_info_button,
            self.tunnel_button,
            self.domain_button,
            self.node_button
        ]

    def configure_backup_nodes(self):
        """打开备用节点配置对话框"""
        if not self.selected_tunnels:
            QMessageBox.warning(self, "警告", "请先选择一个隧道")
            return
        if len(self.selected_tunnels) > 1:
            QMessageBox.warning(self, "警告", "一次只能配置一个隧道的备用节点")
            return
        tunnel_info = self.selected_tunnels[0]
        dialog = BackupNodeConfigDialog(tunnel_info, self.token, self)
        # 应用当前主题
        if hasattr(self, 'dark_theme'):
            dialog.apply_theme(self.dark_theme)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.logger.info(f"隧道 '{tunnel_info['name']}' 的备用节点配置已保存")
            # 配置保存后刷新隧道列表，显示更新后的备用节点状态
            self.load_tunnels()

    def get_backup_config(self, tunnel_id):
        """获取隧道的备用节点配置"""
        if not tunnel_id:
            self.logger.error("获取备用节点配置失败: 隧道ID为空")
            return None
        config_path = get_absolute_path("backup_config.json")
        if os.path.exists(config_path):
            try:
                if os.path.getsize(config_path) == 0:
                    with open(config_path, 'w') as f:
                        json.dump({}, f)
                    return None
                with open(config_path, 'r') as f:
                    try:
                        configs = json.load(f)
                        tunnel_id_str = str(tunnel_id)
                        if tunnel_id_str in configs:
                            config = configs[tunnel_id_str]
                            if not isinstance(config, dict):
                                self.logger.error(f"隧道 {tunnel_id} 的备用节点配置无效")
                                return None
                            return config
                        else:
                            return None
                    except json.JSONDecodeError:
                        self.logger.error(f"备用节点配置文件格式错误，重新初始化")
                        with open(config_path, 'w') as f:
                            json.dump({}, f)
                        return None
            except Exception as e:
                self.logger.error(f"读取备用节点配置失败: {str(e)}")
        else:
            try:
                with open(config_path, 'w') as f:
                    json.dump({}, f)
                self.logger.info("已创建备用节点配置文件")
            except Exception as e:
                self.logger.error(f"创建备用节点配置文件失败: {str(e)}")
        return None

    def load_tunnel_comments(self):
        comments_path = get_absolute_path("tunnel_comments.json")
        if os.path.exists(comments_path):
            try:
                with open(comments_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                self.logger.error(f"加载隧道备注失败: {str(e)}")
        return {}

    def save_tunnel_comments(self, comments):
        comments_path = get_absolute_path("tunnel_comments.json")
        try:
            with open(comments_path, 'w', encoding='utf-8') as f:
                json.dump(comments, f, indent=4, ensure_ascii=False)
            return True
        except Exception as e:
            self.logger.error(f"保存隧道备注失败: {str(e)}")
            return False

    def get_tunnel_comment(self, tunnel_id):
        comments = self.load_tunnel_comments()
        return comments.get(str(tunnel_id), "")

    def set_tunnel_comment(self, tunnel_id, comment):
        comments = self.load_tunnel_comments()
        comments[str(tunnel_id)] = comment
        return self.save_tunnel_comments(comments)

    def delete_tunnel_comment(self, tunnel_id):
        comments = self.load_tunnel_comments()
        if str(tunnel_id) in comments:
            del comments[str(tunnel_id)]
            return self.save_tunnel_comments(comments)
        return True

    def get_backup_config_status(self, tunnel_id):
        """获取备用配置状态描述"""
        config = self.get_backup_config(tunnel_id)
        if not config:
            return "无备用配置"
        nodes = config.get('backup_nodes', [])
        domain = config.get('domain')
        status = f"{len(nodes)}个备用节点"
        if domain:
            status += ", 已配置域名"
        return status

    def get_node_info(self, node_name):
        """获取节点信息"""
        try:
            url = f"http://cf-v2.uapis.cn/nodeinfo"
            params = {
                'token': self.token,
                'node': node_name
            }
            headers = get_headers()
            response = requests.get(url, headers=headers, params=params)
            data = response.json()
            if data['code'] == 200:
                return data['data']
            else:
                self.logger.error(f"获取节点信息失败: {data.get('msg', '')}")
                return None
        except Exception as e:
            self.logger.error(f"获取节点信息时发生错误: {str(e)}")
            return None

    def cleanup_backup_configs(self):
        """清理备用节点配置"""
        try:
            config_path = get_absolute_path("backup_config.json")
            if not os.path.exists(config_path):
                with open(config_path, 'w') as f:
                    json.dump({}, f)
                self.logger.info("已创建备用节点配置文件")
                return
            if os.path.getsize(config_path) == 0:
                with open(config_path, 'w') as f:
                    json.dump({}, f)
                return
            try:
                with open(config_path, 'r') as f:
                    configs = json.load(f)
            except json.JSONDecodeError:
                self.logger.error(f"备用节点配置文件格式错误，重新初始化")
                with open(config_path, 'w') as f:
                    json.dump({}, f)
                return
            tunnels = API.get_user_tunnels(self.token)
            if tunnels is None:
                return
            tunnel_ids = [str(t['id']) for t in tunnels]
            modified = False
            for tunnel_id in list(configs.keys()):
                if tunnel_id not in tunnel_ids:
                    del configs[tunnel_id]
                    modified = True
            if modified:
                with open(config_path, 'w') as f:
                    json.dump(configs, f, indent=4)
        except Exception as e:
            self.logger.error(f"清理备用节点配置时发生错误: {str(e)}")
            try:
                with open(config_path, 'w') as f:
                    json.dump({}, f)
            except:
                pass

    def load_mail_config(self):
        """加载邮件配置"""
        settings_path = get_absolute_path("settings.json")
        if os.path.exists(settings_path):
            with open(settings_path, 'r') as f:
                settings = json.load(f)
                mail_config = settings.get('mail', {})
                if mail_config.get('sender_email') and mail_config.get('password'):
                    self.mail_notifier = message_push(
                        sender_email=mail_config['sender_email'],
                        password=mail_config['password'],
                        receiver_email=mail_config['sender_email'],
                        smtp_server=mail_config.get('smtp_server'),
                        port=mail_config.get('smtp_port')
                    )

                # 设置通知配置，确保包含所有可能的通知类型
                default_notify_settings = {
                    'tunnel_offline': False,
                    'tunnel_start': False,
                    'node_offline': False,
                    'node_online': False,
                    'node_added': False,
                    'node_removed': False
                }

                # 使用配置文件中的设置或默认值
                self.notify_settings = {**default_notify_settings, **(mail_config.get('notifications', {}))}

    def send_notification(self, event_type, message, node_name):
        """发送通知

        Args:
            event_type: 事件类型，如 "node_online", "node_offline", "node_added", "node_removed" 等
            message: 通知内容
            node_name: 相关节点名称
        """
        if not self.mail_notifier or not self.notify_settings.get(event_type, False):
            return

        computer_name = message_push.get_computer_name()
        current_time = message_push.get_current_time()

        # 根据事件类型设置适当的主题
        if event_type == "node_online":
            subject_prefix = f"节点上线通知"
        elif event_type == "node_offline":
            subject_prefix = f"节点离线通知"
        elif event_type == "node_added":
            subject_prefix = f"节点上架通知"
        elif event_type == "node_removed":
            subject_prefix = f"节点下架通知"
        elif event_type == "tunnel_offline":
            subject_prefix = f"{node_name}隧道离线通知"
        elif event_type == "tunnel_start":
            subject_prefix = f"{node_name}隧道启动通知"
        else:
            subject_prefix = f"系统通知 - {event_type}"

        subject = f"{APP_NAME} {subject_prefix}"

        body = f"""
        通知类型：{subject_prefix}
        发生时间：{current_time}
        计算机名称：{computer_name}

        详细信息：
        {message}

        此邮件由 {APP_NAME} v{APP_VERSION} 自动发送
        """

        # 在子线程中发送邮件避免阻塞UI
        threading.Thread(
            target=self.mail_notifier.send,
            args=(subject, body),
            daemon=True
        ).start()

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
                    if str(tunnel['id']) in [str(id) for id in auto_start_tunnels]:
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

    def check_domain_target(self, domain_config, node_name, tunnel_info):
        """检查域名是否指向正确的节点，返回是否匹配"""
        try:
            # 首先，检查所有必需的数据是否可用
            if not domain_config or not node_name or not tunnel_info:
                self.logger.error(
                    f"域名检查缺少必要数据: domain_config={bool(domain_config)}, node_name={bool(node_name)}")
                return False

            # 验证域名和记录存在
            domain = domain_config.get('domain', '')
            record = domain_config.get('record', '')
            if not domain or not record:
                self.logger.error(f"域名配置缺少必要字段: {domain_config}")
                return False

            # 使用 get_user_free_subdomains API
            url = "http://cf-v2.uapis.cn/get_user_free_subdomains"
            params = {"token": self.token}

            headers = get_headers()
            try:
                response = requests.get(url, headers=headers, params=params)
                data = response.json()
                if 'code' not in data:
                    self.logger.error(f"API返回格式错误，缺少'code'字段: {data}")
                    return False

                if data['code'] != 200:
                    self.logger.error(f"获取域名信息失败: {data.get('msg', '')}")
                    return False
                if 'data' not in data:
                    self.logger.error(f"API返回格式错误，缺少'data'字段: {data}")
                    return False

                found_record = None
                if isinstance(data['data'], list):
                    for item in data['data']:
                        if (item.get('domain') == domain and
                                item.get('record') == record):
                            found_record = item
                            break
                elif isinstance(data['data'], dict):
                    if (data['data'].get('domain') == domain and
                            data['data'].get('record') == record):
                        found_record = data['data']

                if not found_record:
                    self.logger.error(f"未找到域名记录: {record}.{domain}")
                    return False

                current_target = found_record.get('target', '')

            except requests.exceptions.RequestException as e:
                self.logger.error(f"请求域名信息失败: {str(e)}")
                return False
            except ValueError as e:
                self.logger.error(f"解析API响应失败: {str(e)}")
                return False

            # 获取节点信息
            node_info = self.get_node_info(node_name)
            if not node_info:
                self.logger.error(f"无法获取节点 {node_name} 的信息")
                return False

            # 计算预期目标
            expected_target = self.get_tunnel_target(tunnel_info, node_info)
            if not expected_target:
                self.logger.error(f"无法计算隧道 {tunnel_info.get('name', 'unknown')} 的预期目标")
                return False

            # 检查当前目标是否与预期目标匹配
            return current_target == expected_target

        except Exception as e:
            self.logger.error(f"检查域名目标时发生错误: {str(e)}")
            return False

    def check_domains_for_all_tunnels(self):
        """检查所有隧道的域名配置是否需要更新"""
        if not self.token:
            return
        try:
            tunnels = API.get_user_tunnels(self.token)
            if not tunnels:
                return
            for tunnel in tunnels:
                if not isinstance(tunnel, dict) or not tunnel.get('id'):
                    continue
                backup_config = self.get_backup_config(tunnel.get('id'))
                if not backup_config:
                    continue
                domain_config = backup_config.get('domain')
                if not domain_config or not isinstance(domain_config, dict):
                    continue
                if not domain_config.get('domain') or not domain_config.get('record'):
                    self.logger.error(f"隧道 {tunnel.get('name', 'unknown')} 的域名配置不完整")
                    continue

                node_name = tunnel.get('node')
                if not node_name:
                    self.logger.error(f"隧道 {tunnel.get('name', 'unknown')} 没有节点信息")
                    continue
                if self.check_domain_target(domain_config, node_name, tunnel):
                    continue

                self.update_domain_for_backup(domain_config, tunnel, node_name)

        except Exception as e:
            self.logger.error(f"检查域名配置时发生错误: {str(e)}")

    def check_node_status(self):
        """检查节点状态并处理隧道切换 - 保持原有逻辑不变"""
        if not self.token or not self.current_nodes:
            return

        # 获取当前在线节点名称
        online_nodes = set(node['node_name'] for node in self.current_nodes if node['state'] == 'online')

        tunnels = API.get_user_tunnels(self.token)
        if tunnels is None:
            return

        for tunnel_name, process in list(self.tunnel_processes.items()):
            tunnel_info = next((t for t in tunnels if t['name'] == tunnel_name), None)
            if tunnel_info:
                node_name = tunnel_info['node']
                # 检查节点是否在当前在线节点列表中
                if node_name not in online_nodes:
                    self.logger.warning(f"节点 {node_name} 离线，尝试切换到备用节点")
                    # 尝试切换到备用节点
                    switched = self.switch_to_backup_node(tunnel_info, process)
                    # 停止当前隧道
                    self.stop_tunnel({"name": tunnel_name})
                    # 记录切换结果
                    if switched:
                        self.logger.info(f"隧道 {tunnel_name} 已成功切换到备用节点")
                    else:
                        self.logger.error(f"隧道 {tunnel_name} 切换备用节点失败")
                else:
                    # 节点在线，检查域名是否需要更新
                    self.check_domain_for_tunnel(tunnel_info)
            else:
                self.logger.warning(f"未找到隧道 {tunnel_name} 的信息")

        # 每10分钟检查一次所有隧道的域名配置
        current_time = time.time()
        last_check = getattr(self, 'last_domain_check_time', 0)

        if current_time - last_check > 600:  # 每10分钟
            self.last_domain_check_time = current_time
            self.check_domains_for_all_tunnels()

    def check_domain_for_tunnel(self, tunnel_info):
        """检查单个隧道的域名配置是否需要更新"""
        try:
            if not tunnel_info:
                self.logger.error("检查隧道域名配置失败: 隧道信息为空")
                return
            backup_config = self.get_backup_config(tunnel_info.get('id'))
            if not backup_config:
                return
            domain_config = backup_config.get('domain')
            if not domain_config:
                return
            if not domain_config.get('domain') or not domain_config.get('record'):
                self.logger.error(f"隧道 {tunnel_info.get('name', 'unknown')} 的域名配置不完整")
                return
            last_updated = domain_config.get('last_updated')
            if last_updated:
                try:
                    last_time = datetime.strptime(last_updated, '%Y-%m-%d %H:%M:%S')
                    if (datetime.now() - last_time).total_seconds() < 86400:  # 24 hours
                        return
                except (ValueError, TypeError):
                    self.logger.warning(f"无法解析上次更新时间: {last_updated}")
                    pass
            node_name = tunnel_info.get('node')
            if not node_name:
                self.logger.error(f"隧道 {tunnel_info.get('name', 'unknown')} 没有节点信息")
                return
            if self.check_domain_target(domain_config, node_name, tunnel_info):
                return
            self.update_domain_for_backup(domain_config, tunnel_info, node_name)
        except Exception as e:
            self.logger.error(f"检查隧道域名配置时发生错误: {str(e)}")

    def check_node_status_changes(self):
        """检测节点状态变化并发送相应通知"""
        if not self.current_nodes or not self.previous_nodes:
            return  # 没有足够的数据进行比较

        # 创建字典，便于通过节点名查找节点信息
        previous_nodes_dict = {node['node_name']: node for node in self.previous_nodes}
        current_nodes_dict = {node['node_name']: node for node in self.current_nodes}

        # 获取节点名称集合
        previous_node_names = set(previous_nodes_dict.keys())
        current_node_names = set(current_nodes_dict.keys())

        # 初始化持久化跟踪器（如果不存在）
        if not hasattr(self, 'last_known_states'):
            self.last_known_states = {}
            # 初始化时，记录所有当前节点的状态
            for node_name, node in current_nodes_dict.items():
                self.last_known_states[node_name] = node.get('state', '')

        # 检查每个节点是否相对于上次记录的状态发生了变化
        nodes_went_offline = []
        nodes_came_online = []

        # 检查哪些节点刚刚离线
        for node_name in current_node_names:
            current_state = current_nodes_dict[node_name].get('state', '')
            last_known_state = self.last_known_states.get(node_name, '')

            if current_state != 'online' and last_known_state == 'online':
                # 节点刚刚从在线变为离线
                nodes_went_offline.append(node_name)
                self.logger.info(f"节点离线: {node_name} (上次已知状态: {last_known_state}, 当前状态: {current_state})")
            elif current_state == 'online' and last_known_state != 'online' and last_known_state != '':
                # 节点刚刚从离线变为在线
                nodes_came_online.append(node_name)
                self.logger.info(f"节点上线: {node_name} (上次已知状态: {last_known_state}, 当前状态: {current_state})")

            # 更新跟踪器中的状态
            self.last_known_states[node_name] = current_state

        if nodes_went_offline:
            self.logger.info(f"检测到 {len(nodes_went_offline)} 个节点刚刚离线: {', '.join(nodes_went_offline)}")

        # 为每个新离线节点发送通知
        for node_name in nodes_went_offline:
            message = f"节点 {node_name} 离线\n离线时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"

            # 检查通知设置
            if hasattr(self, 'notify_settings') and self.notify_settings.get('node_offline', False):
                try:
                    self.send_notification("node_offline", message, node_name)
                except Exception:
                    # 尝试直接发送
                    if hasattr(self, 'mail_notifier') and self.mail_notifier is not None:
                        try:
                            computer_name = message_push.get_computer_name()
                            subject = f"{APP_NAME} 节点离线通知"
                            body = f"""
                            通知类型：节点离线通知
                            发生时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                            计算机名称：{computer_name}

                            详细信息：
                            {message}

                            此邮件由 {APP_NAME} v{APP_VERSION} 自动发送
                            """
                            self.mail_notifier.send(subject, body)
                        except Exception:
                            pass

        if nodes_came_online:
            self.logger.info(f"检测到 {len(nodes_came_online)} 个节点刚刚上线: {', '.join(nodes_came_online)}")

        # 为每个新上线节点发送通知
        for node_name in nodes_came_online:
            message = f"节点 {node_name} 重新上线\n上线时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"

            # 检查通知设置
            if hasattr(self, 'notify_settings') and self.notify_settings.get('node_online', False):
                try:
                    self.send_notification("node_online", message, node_name)
                except Exception:
                    # 尝试直接发送
                    if hasattr(self, 'mail_notifier') and self.mail_notifier is not None:
                        try:
                            computer_name = message_push.get_computer_name()
                            subject = f"{APP_NAME} 节点上线通知"
                            body = f"""
                            通知类型：节点上线通知
                            发生时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                            计算机名称：{computer_name}

                            详细信息：
                            {message}

                            此邮件由 {APP_NAME} v{APP_VERSION} 自动发送
                            """
                            self.mail_notifier.send(subject, body)
                        except Exception:
                            pass

    def batch_edit_tunnels(self):
        """批量编辑隧道"""
        if not self.selected_tunnels:
            QMessageBox.warning(self, "警告", "请先选择要编辑的隧道")
            return

        dialog = BatchEditDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            changes = dialog.get_changes()
            if not changes:
                QMessageBox.information(self, "提示", "没有进行任何修改")
                return

            # 从API更改中分离出备注更改
            comment_change = None
            if 'comment' in changes:
                comment_change = changes.pop('comment')  # 从API更改中移除备注

            # 存储API操作是否成功的隧道
            successful_tunnels = []

            for tunnel_info in self.selected_tunnels:
                try:
                    tunnel_type = changes.get("type", tunnel_info["type"])
                    tunnel_id = tunnel_info["id"]

                    # 处理API更改
                    if changes and changes != {'use_v1_api': False, 'force_update': False}:  # 如果有实际的API更改
                        # 构建基本请求负载
                        payload = {
                            "tunnelid": int(tunnel_id),
                            "token": self.token,
                            "tunnelname": tunnel_info["name"],
                            "node": changes.get("node", tunnel_info["node"]),
                            "localip": changes.get("localip", tunnel_info["localip"]),
                            "porttype": tunnel_type,
                            "localport": tunnel_info["nport"],
                            "encryption": changes.get("encryption", tunnel_info["encryption"]),
                            "compression": changes.get("compression", tunnel_info["compression"])
                        }

                        # 验证本地端口是否有效
                        if "nport" in changes:
                            if not enter_inspector.validate_port(changes["nport"], True):
                                raise ValueError(f"隧道 '{tunnel_info['name']}': 本地端口必须是1-65535之间的整数")
                            payload["localport"] = int(changes["nport"])

                        # 根据隧道类型设置正确的远程端口/绑定域名参数
                        if tunnel_type.lower() in ["tcp", "udp"]:
                            # TCP/UDP类型使用remoteport参数
                            try:
                                payload["remoteport"] = int(tunnel_info["dorp"])
                            except (ValueError, TypeError):
                                raise ValueError(f"隧道 '{tunnel_info['name']}': 远程端口必须是整数")
                        else:
                            # HTTP/HTTPS类型使用banddomain参数
                            payload["banddomain"] = tunnel_info["dorp"]

                        # 发送请求
                        headers = get_headers(request_json=True)
                        url = "http://cf-v2.uapis.cn/update_tunnel"
                        response = requests.post(url, headers=headers, json=payload)

                        if response.status_code == 200:
                            result = response.json()
                            if result.get('code') == 200:
                                self.logger.info(f"隧道 {tunnel_info['name']} 更新成功")
                                successful_tunnels.append(tunnel_id)
                            else:
                                self.logger.error(
                                    f"更新隧道 {tunnel_info['name']} 失败: {result.get('msg', '未知错误')}")
                                QMessageBox.warning(self, "错误",
                                                    f"更新隧道 {tunnel_info['name']} 失败: {result.get('msg', '未知错误')}")
                        else:
                            self.logger.error(f"更新隧道 {tunnel_info['name']} 失败: HTTP {response.status_code}")
                            QMessageBox.warning(self, "错误",
                                                f"更新隧道 {tunnel_info['name']} 失败: HTTP {response.status_code}")
                    else:
                        # 没有API更改，但可能有备注更改
                        successful_tunnels.append(tunnel_id)
                    # 无论API操作是否成功，都处理备注变更
                    if comment_change is not None:
                        self.set_tunnel_comment(tunnel_id, comment_change)

                except Exception as e:
                    self.logger.exception(f"更新隧道 {tunnel_info['name']} 时发生错误")
                    QMessageBox.warning(self, "错误", f"更新隧道 {tunnel_info['name']} 失败: {str(e)}")

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

        # 添加消息和黑名单按钮
        self.messages_button = QPushButton('系统消息', self)
        self.messages_button.clicked.connect(self.show_messages)

        self.blacklist_button = QPushButton('黑名单查询', self)
        self.blacklist_button.clicked.connect(self.show_blacklist)

        # 布局按钮
        button_layout = QHBoxLayout()
        button_layout.addWidget(self.login_button)
        button_layout.addWidget(self.logout_button)
        button_layout.addWidget(self.messages_button)
        button_layout.addWidget(self.blacklist_button)

        layout.addWidget(self.username_input)
        layout.addWidget(self.password_input)
        layout.addWidget(self.token_input)
        layout.addLayout(button_layout)

        self.user_info_display = QTextEdit()
        self.user_info_display.setReadOnly(True)
        layout.addWidget(self.user_info_display)

        layout.addStretch(1)

        self.content_stack.addWidget(user_info_widget)

    # 添加显示消息对话框方法
    def show_messages(self):
        """显示系统消息对话框"""
        dialog = MessageDialog(self.token, self)
        if hasattr(self, 'dark_theme'):
            dialog.apply_theme(self.dark_theme)
        dialog.exec()

    # 添加显示黑名单对话框方法
    def show_blacklist(self):
        """显示黑名单对话框"""
        dialog = BlacklistDialog(self)
        if hasattr(self, 'dark_theme'):
            dialog.apply_theme(self.dark_theme)
        dialog.exec()

    # 自动检查消息方法
    def auto_check_messages(self):
        """自动检查是否有未读消息"""
        if not self.token:
            return
        try:
            url = f"http://cf-v2.uapis.cn/messages?token={self.token}"
            headers = get_headers()
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                if data['code'] == 200:
                    messages = data.get('data', [])
                    # 检查是否有个人消息
                    personal_messages = [m for m in messages if m.get('quanti') == 'no']
                    if personal_messages:
                        QTimer.singleShot(3000, lambda: self.show_message_notification(len(personal_messages)))
        except Exception as e:
            self.logger.error(f"检查消息时发生错误: {str(e)}")

    # 显示消息通知方法
    def show_message_notification(self, count):
        """显示消息通知"""
        notification = QMessageBox(self)
        notification.setWindowTitle("新消息提醒")
        notification.setText(f"您有 {count} 条未读个人消息，请及时查看。")
        notification.setIcon(QMessageBox.Icon.Information)
        view_button = notification.addButton("查看消息", QMessageBox.ButtonRole.AcceptRole)
        notification.exec()
        if notification.clickedButton() == view_button:
            self.show_messages()

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

    def on_domain_clicked(self, domain_info):
        for i in range(self.domain_container.layout().count()):
            item = self.domain_container.layout().itemAt(i)
            if item.widget():
                item.widget().setSelected(False)
        self.sender().setSelected(True)
        self.selected_domain = domain_info
        self.edit_domain_button.setEnabled(True)
        self.delete_domain_button.setEnabled(True)

    def edit_tunnel_comment(self):
        """编辑选中隧道的备注"""
        if not self.selected_tunnels or len(self.selected_tunnels) != 1:
            return

        tunnel = self.selected_tunnels[0]
        current_comment = self.get_tunnel_comment(tunnel['id'])

        dialog = QDialog(self)
        dialog.setWindowTitle(f"编辑隧道备注: {tunnel['name']}")
        layout = QVBoxLayout(dialog)

        # 添加说明标签
        info_label = QLabel(f"正在编辑 '{tunnel['name']}' 的备注")
        info_label.setStyleSheet("font-weight: bold;")
        layout.addWidget(info_label)

        # 添加备注输入框
        comment_input = QLineEdit(current_comment)
        comment_input.setPlaceholderText("输入隧道备注")

        layout.addWidget(QLabel("备注:"))
        layout.addWidget(comment_input)

        # 添加说明文本
        help_text = QLabel("备注仅保存在本地，不会上传到服务器。\n可用于记录隧道用途、特殊配置等。")
        help_text.setStyleSheet("color: gray; font-size: 10px;")
        help_text.setWordWrap(True)
        layout.addWidget(help_text)

        # 添加按钮
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)

        # 设置对话框样式
        if hasattr(self, 'dark_theme') and self.dark_theme:
            dialog.setStyleSheet("""
                QDialog { background-color: #2D2D2D; color: #FFFFFF; }
                QLabel { color: #FFFFFF; }
                QLineEdit { background-color: #3D3D3D; color: #FFFFFF; border: 1px solid #555555; padding: 5px; }
                QPushButton { background-color: #0D6EFD; color: white; border-radius: 4px; padding: 6px 12px; }
                QPushButton:hover { background-color: #0B5ED7; }
            """)

        if dialog.exec() == QDialog.DialogCode.Accepted:
            new_comment = comment_input.text().strip()
            if new_comment != current_comment:
                self.set_tunnel_comment(tunnel['id'], new_comment)
                self.logger.info(f"已更新隧道 '{tunnel['name']}' 的备注")
                self.load_tunnels()  # 刷新以显示更新后的备注

    # 添加这些辅助方法用于启动和停止选中的隧道
    def start_selected_tunnels(self):
        """启动所有选中的隧道"""
        for tunnel in self.selected_tunnels:
            self.start_tunnel(tunnel)

        self.logger.info(f"已启动 {len(self.selected_tunnels)} 个选中的隧道")

    def stop_selected_tunnels(self):
        """停止所有选中的隧道"""
        for tunnel in self.selected_tunnels:
            self.stop_tunnel(tunnel)

        self.logger.info(f"已停止 {len(self.selected_tunnels)} 个选中的隧道")

    def show_tunnel_context_menu(self, position):
        """显示隧道右键菜单"""
        # 检查是否有选中的隧道
        if not self.selected_tunnels:
            return
        menu = QMenu()
        # 只有选中一个隧道时才添加编辑备注选项
        if len(self.selected_tunnels) == 1:
            edit_comment_action = menu.addAction("编辑备注")
            edit_comment_action.triggered.connect(self.edit_tunnel_comment)

        # 添加其他右键菜单选项
        start_action = menu.addAction("启动选中隧道")
        start_action.triggered.connect(self.start_selected_tunnels)

        stop_action = menu.addAction("停止选中隧道")
        stop_action.triggered.connect(self.stop_selected_tunnels)

        # 添加备用节点配置选项（如果只选中一个隧道）
        if len(self.selected_tunnels) == 1:
            backup_config_action = menu.addAction("配置备用节点")
            backup_config_action.triggered.connect(self.configure_backup_nodes)

        # 添加分隔线
        menu.addSeparator()

        # 添加编辑和删除选项
        if len(self.selected_tunnels) == 1:
            edit_action = menu.addAction("编辑隧道")
            edit_action.triggered.connect(self.edit_tunnel)

        delete_action = menu.addAction("删除隧道")
        delete_action.triggered.connect(self.delete_tunnel)

        # 显示菜单
        menu.exec(self.tunnel_container.mapToGlobal(position))

    def setup_tunnel_page(self):
        """设置隧道页面"""
        tunnel_widget = QWidget()
        layout = QVBoxLayout(tunnel_widget)

        # 添加刷新和备用节点配置按钮
        button_layout = QHBoxLayout()
        refresh_button = QPushButton("刷新隧道列表")
        refresh_button.clicked.connect(self.load_tunnels)
        button_layout.addWidget(refresh_button)

        # 添加备用节点配置按钮
        backup_config_button = QPushButton("隧道备用节点配置")
        backup_config_button.clicked.connect(self.configure_backup_nodes)
        button_layout.addWidget(backup_config_button)

        # 添加清除frpc进程按钮
        clear_frpc_button = QPushButton("清除frpc进程")
        clear_frpc_button.clicked.connect(self.clear_frpc_processes)
        button_layout.addWidget(clear_frpc_button)

        layout.addLayout(button_layout)

        self.tunnel_container = QWidget()
        self.tunnel_container.setLayout(QGridLayout())

        # 添加右键菜单支持
        self.tunnel_container.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tunnel_container.customContextMenuRequested.connect(self.show_tunnel_context_menu)

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

        # 添加备注输入框
        comment_input = QLineEdit()
        if tunnel_info and tunnel_info.get('id'):
            comment_input.setText(self.get_tunnel_comment(tunnel_info['id']))
        comment_input.setPlaceholderText("可选，添加隧道备注")

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
        form_layout.addRow("备注:", comment_input)  # 添加备注字段
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
                    if not enter_inspector.validate_port(remote_port, False):
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

                            # 创建新隧道前，保存之前的备注
                            old_comment = self.get_tunnel_comment(tunnel_info["id"])
                            self.delete_tunnel_comment(tunnel_info["id"])

                            # 创建新隧道
                            time.sleep(1)  # 等待删除操作完成
                            create_url = "http://cf-v2.uapis.cn/create_tunnel"
                            response = requests.post(create_url, headers=headers, json=payload)
                            response_data = response.json()

                            # 如果成功创建，找到新隧道ID并保存备注
                            if response_data['code'] == 200 and (comment_input.text().strip() or old_comment):
                                # 尝试找回新的隧道ID
                                time.sleep(1)  # 等待API刷新
                                tunnels = API.get_user_tunnels(self.token)
                                for tunnel in tunnels:
                                    if tunnel['name'] == payload['tunnelname']:
                                        # 保存之前的备注或新备注
                                        self.set_tunnel_comment(tunnel['id'],
                                                                comment_input.text().strip() or old_comment)
                                        break

                            return response_data
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
                                result = {"code": 200,
                                          "msg": response_content} if "success" in response_content.lower() else {
                                    "code": 400, "msg": response_content}

                                # 保存备注信息
                                if result["code"] == 200 and comment_input.text().strip():
                                    self.set_tunnel_comment(tunnel_info["id"], comment_input.text().strip())

                                return result
                            except Exception as content:
                                self.logger.error(f"解析V1 API响应时出错: {str(content)}")
                                return {"code": 500, "msg": str(content)}
                        else:
                            # 使用V2 API
                            url = "http://cf-v2.uapis.cn/update_tunnel"
                            response = requests.post(url, headers=headers, json=payload)
                            response_data = response.json()

                            # 保存备注信息
                            if response_data['code'] == 200 and comment_input.text().strip():
                                self.set_tunnel_comment(tunnel_info["id"], comment_input.text().strip())

                            return response_data
                else:
                    # 创建新隧道只使用V2 API
                    url = "http://cf-v2.uapis.cn/create_tunnel"
                    response = requests.post(url, headers=headers, json=payload)
                    response_data = response.json()

                    # 如果创建成功，保存备注
                    if response_data['code'] == 200 and comment_input.text().strip():
                        # 查找新创建的隧道ID
                        time.sleep(1)  # 稍微等待API刷新
                        tunnels = API.get_user_tunnels(self.token)
                        for tunnel in tunnels:
                            if tunnel['name'] == payload['tunnelname']:
                                self.set_tunnel_comment(tunnel['id'], comment_input.text().strip())
                                break

                    return response_data

            except ValueError as ve:
                raise ve
            except Exception as e:
                raise Exception(f"{'更新' if tunnel_info else '创建'}隧道失败: {str(e)}")

        return None

    def clear_frpc_processes(self):
        """清除frpc进程并显示详细终止信息"""
        reply = QMessageBox.question(self, '确认清除frpc进程',
                                     "您确定要清除所有frpc.exe进程吗？",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            reply = QMessageBox.question(self, '再次确认清除frpc进程',
                                         "这将会终止所有frpc.exe进程，您确保所有都准备好了吗？",
                                         QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if reply == QMessageBox.StandardButton.Yes:
                try:
                    # 使用subprocess获取更详细的输出信息
                    startupinfo = subprocess.STARTUPINFO()
                    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                    process = subprocess.Popen(
                        ['taskkill', '/f', '/im', 'frpc.exe'],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        startupinfo=startupinfo
                    )
                    stdout, stderr = process.communicate()

                    # 分析输出，统计终止的进程数量
                    if process.returncode == 0:
                        # 计算终止的进程数量
                        terminated_count = stdout.count("成功")
                        # 记录详细日志
                        self.logger.info(f"已成功终止 {terminated_count} 个frpc.exe进程")

                    else:
                        if "找不到" in stderr:
                            self.logger.info("没有找到frpc.exe进程")

                except subprocess.CalledProcessError as e:
                    if "没有找到" in str(e) or "not found" in str(e).lower():
                        self.logger.info("没有找到frpc.exe进程")
                        QMessageBox.information(self, "清除结果", "没有找到正在运行的frpc.exe进程")
                    else:
                        self.logger.error(f"清除frpc.exe进程失败: {str(e)}")
                        QMessageBox.warning(self, "清除失败", f"清除frpc.exe进程失败: {str(e)}")

                except Exception as e:
                    self.logger.error(f"清除frpc.exe进程时发生未知错误: {str(e)}")
                    QMessageBox.critical(self, "错误", f"清除frpc.exe进程时发生未知错误: {str(e)}")

    def view_output(self):
        """显示隧道输出对话框"""
        if not self.selected_tunnels:
            QMessageBox.warning(self, "警告", "请先选择一个隧道")
            return

        tunnel_info = self.selected_tunnels[0]
        tunnel_name = tunnel_info['name']

        with QMutexLocker(self.output_mutex):
            if tunnel_name not in self.tunnel_outputs:
                QMessageBox.information(self, "提示", "这个隧道还没启动过哦！")
                return

            if not self.tunnel_outputs[tunnel_name]['dialog']:
                self.tunnel_outputs[tunnel_name]['dialog'] = OutputDialog(self)

            dialog = self.tunnel_outputs[tunnel_name]['dialog']
            current_run = self.tunnel_outputs[tunnel_name]['run_number']

            output_text = self.tunnel_outputs[tunnel_name]['output']

        dialog.add_output(tunnel_name, output_text, current_run)
        dialog.setWindowTitle(f"隧道 {tunnel_name} 运行输出")
        dialog.show()
        dialog.raise_()
        dialog.activateWindow()

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
        """查看节点在线率 (修改支持API节点)"""
        if not hasattr(self, 'selected_node'):
            QMessageBox.warning(self, "警告", "请先选择一个节点")
            return

        # 如果是API节点，显示特定信息
        if self.selected_node.get('node_name') == 'API服务器':
            dialog = QDialog(self)
            dialog.setWindowTitle("API服务器性能")
            dialog.setMinimumWidth(400)
            layout = QVBoxLayout(dialog)

            # 结果显示区域
            result_text = QTextEdit()
            result_text.setReadOnly(True)
            layout.addWidget(result_text)

            api_info = self.selected_node
            metrics = api_info.get('metrics', {})

            # 构建API服务器性能信息
            info = f"""API服务器: {api_info.get('serverName', '未知')}

    性能指标:
    - CPU负载: {metrics.get('cpu', 0):.2f}%
    - 内存压力: {metrics.get('memory', 0):.2f}%
    - IO延迟: {metrics.get('ioLatency', 0)}
    - 资源抢占: {metrics.get('steal', 0):.2f}
    - 线程征用: {metrics.get('threadContention', 0):.2f}
    - 总负载指数: {api_info.get('load', 0):.2f}

    负载级别:
    - <0.3: 良好
    - 0.3-0.7: 正常
    - >0.7: 繁忙

    ChmlFrp API拥有多个服务器节点，用于容灾和自动切换。
    当前API节点会根据负载情况自动切换，保证API服务的稳定性。
    """
            result_text.setPlainText(info)

            # 关闭按钮
            close_button = QPushButton("关闭")
            close_button.clicked.connect(dialog.close)
            layout.addWidget(close_button)

            dialog.exec()
            return

        # 原有的节点在线率逻辑
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

            # 添加自动检查消息
            QTimer.singleShot(2000, self.auto_check_messages)

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
        if self.user_info['term'] >= "9999-09-09":
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

    def load_tunnels(self):
        """加载隧道列表"""
        try:
            if not self.token:
                self.show_error_message("未登录，无法加载隧道列表")
                return

            tunnels = API.get_user_tunnels(self.token)
            if tunnels is None:
                return

            # 清理备用节点配置
            self.cleanup_backup_configs()

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
                    tunnel_widget = TunnelCard(tunnel, self.token, self)  # 传递self作为父对象
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
            if n_of_tunnels==0:
                # 获取节点状态数据
                response = API.is_node_online(tyen="all")
                if response and 'data' in response and isinstance(response['data'], list):
                    nodes = response['data']

                    # 在更新当前状态前存储之前的状态
                    self.previous_nodes = self.current_nodes.copy() if self.current_nodes else []
                    self.current_nodes = nodes

                    # 保持last_node_list以向后兼容，提取节点名称
                    self.last_node_list = [node['node_name'] for node in nodes]

                    # 清除现有的节点卡片
                    while self.node_container.layout().count():
                        item = self.node_container.layout().takeAt(0)
                        if item.widget():
                            item.widget().deleteLater()

                    row, col = 0, 0

                    # 首先加载API状态卡片
                    try:
                        api_status = self.get_api_status()
                        api_widget = ApiStatusCard(api_status)
                        api_widget.clicked.connect(self.on_api_clicked)
                        self.node_container.layout().addWidget(api_widget, row, col)

                        col += 1
                        if col == 2:  # 每行两个卡片
                            col = 0
                            row += 1
                    except Exception as e:
                        self.logger.error(f"创建API状态卡片时发生错误: {str(e)}")

                    # 放置普通节点卡片
                    for node in nodes:
                        try:
                            # 确保node包含所有必需的字段
                            if all(key in node for key in
                                   ['node_name', 'state', 'nodegroup', 'bandwidth_usage_percent', 'cpu_usage']):
                                node_widget = NodeCard(node)
                                node_widget.clicked.connect(self.on_node_clicked)
                                self.node_container.layout().addWidget(node_widget, row, col)

                                col += 1
                                if col == 2:  # 每行两个卡片
                                    col = 0
                                    row += 1
                            else:
                                self.logger.warning(f"节点数据缺少必要字段: {node}")

                        except Exception as content:
                            self.logger.error(f"创建节点卡片时发生错误: {str(content)}")
                            continue
                else:
                    self.logger.error("获取节点数据失败或格式不正确")

            # 获取节点状态数据
            response = API.is_node_online(tyen="all")
            if response and 'data' in response and isinstance(response['data'], list):
                nodes = response['data']

                # 在更新当前状态前存储之前的状态
                self.previous_nodes = self.current_nodes.copy() if self.current_nodes else []
                self.current_nodes = nodes

                # 保持last_node_list以向后兼容，提取节点名称
                self.last_node_list = [node['node_name'] for node in nodes]

                # 清除现有的节点卡片
                while self.node_container.layout().count():
                    item = self.node_container.layout().takeAt(0)
                    if item.widget():
                        item.widget().deleteLater()

                row, col = 0, 0

                # 首先加载API状态卡片
                try:
                    api_status = self.get_api_status()
                    api_widget = ApiStatusCard(api_status)
                    api_widget.clicked.connect(self.on_api_clicked)
                    self.node_container.layout().addWidget(api_widget, row, col)

                    col += 1
                    if col == 2:  # 每行两个卡片
                        col = 0
                        row += 1
                except Exception as e:
                    self.logger.error(f"创建API状态卡片时发生错误: {str(e)}")

                # 放置普通节点卡片
                for node in nodes:
                    try:
                        # 确保node包含所有必需的字段
                        if all(key in node for key in
                               ['node_name', 'state', 'nodegroup', 'bandwidth_usage_percent', 'cpu_usage']):
                            node_widget = NodeCard(node)
                            node_widget.clicked.connect(self.on_node_clicked)
                            self.node_container.layout().addWidget(node_widget, row, col)

                            col += 1
                            if col == 2:  # 每行两个卡片
                                col = 0
                                row += 1
                        else:
                            self.logger.warning(f"节点数据缺少必要字段: {node}")

                    except Exception as content:
                        self.logger.error(f"创建节点卡片时发生错误: {str(content)}")
                        continue
            else:
                self.logger.error("获取节点数据失败或格式不正确")

        except Exception as content:
            self.logger.error(f"获取节点列表时发生错误: {str(content)}")
            self.show_error_message(self.node_container, f"获取节点列表时发生错误: {str(content)}")

    def get_api_status(self):
        """获取API服务器状态"""
        try:
            url = "http://cf-v2.uapis.cn/api/server-status"
            headers = get_headers()
            response = requests.get(url, headers=headers, timeout=5)

            if response.status_code == 200:
                return response.json()
            else:
                self.logger.error(f"获取API状态失败: HTTP {response.status_code}")
                return None
        except Exception as e:
            self.logger.error(f"获取API状态时发生错误: {str(e)}")
            return None

    def on_api_clicked(self, api_info):
        """当API状态卡片被点击时"""
        # 清除其他选中状态
        for i in range(self.node_container.layout().count()):
            item = self.node_container.layout().itemAt(i)
            if item.widget():
                item.widget().setSelected(False)
        self.sender().setSelected(True)

        # 设置当前选中的节点为API信息
        self.selected_node = {'node_name': 'API服务器', 'nodegroup': 'API', 'state': 'online'}
        self.selected_node.update(api_info)

        # 启用详情和在线率按钮
        self.details_button.setEnabled(True)
        self.uptime_button.setEnabled(True)

    def format_node_details(self, node_info):
        """格式化节点详细信息 (修改支持API节点)"""
        if node_info.get('node_name') == 'API服务器':
            # API服务器详情
            metrics = node_info.get('metrics', {})
            details = f"""API服务器: {node_info.get('serverName', '未知')}
    状态: 在线
    节点组: API
    总负载: {node_info.get('load', 0):.2f}

    CPU负载: {metrics.get('cpu', 0):.2f}%
    内存压力: {metrics.get('memory', 0):.2f}%
    IO延迟: {metrics.get('ioLatency', 0):.4f}
    资源抢占: {metrics.get('steal', 0):.2f}
    线程征用: {metrics.get('threadContention', 0):.2f}

    ChmlFrp API拥有多个服务器节点，用于容灾和自动切换。
    目前您正在连接的是上述API节点。"""
            return details
        else:
            # 普通节点详情 (原有逻辑)
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
            # 检查节点状态是否在线
            if not API.is_node_online(tunnel_info['node'], tyen="online"):
                # 检查是否有备用节点配置
                backup_config = self.get_backup_config(tunnel_info['id'])
                if backup_config and backup_config.get('backup_nodes'):
                    # 尝试找到一个在线的备用节点
                    for backup_node in backup_config['backup_nodes']:
                        if API.is_node_online(backup_node, tyen="online"):
                            self.logger.info(f"节点 {tunnel_info['node']} 离线，正在切换到备用节点 {backup_node}")

                            # 创建一个修改过的tunnel_info，使用备用节点
                            modified_tunnel = tunnel_info.copy()
                            modified_tunnel['node'] = backup_node

                            # 如果配置了域名，更新域名指向备用节点
                            domain_config = backup_config.get('domain')
                            if domain_config:
                                self.update_domain_for_backup(domain_config, modified_tunnel, backup_node)

                            # 使用备用节点启动隧道
                            self._start_tunnel_process(modified_tunnel)
                            return

                    # 如果代码执行到这里，说明没有在线的备用节点
                    QMessageBox.warning(self, "警告", f"节点 {tunnel_info['node']} 和所有备用节点都不在线")
                    return
                else:
                    # 没有备用节点配置
                    QMessageBox.warning(self, "警告", f"节点 {tunnel_info['node']} 当前不在线")
                    return

            # 节点在线，在启动隧道前检查域名配置
            backup_config = self.get_backup_config(tunnel_info['id'])
            if backup_config and backup_config.get('domain'):
                domain_config = backup_config.get('domain')
                # 检查域名是否指向正确的节点
                if not self.check_domain_target(domain_config, tunnel_info['node'], tunnel_info):
                    self.logger.info(
                        f"域名 {domain_config.get('record')}.{domain_config.get('domain')} 不指向当前节点，正在更新...")
                    # 更新域名以指向当前节点
                    self.update_domain_for_backup(domain_config, tunnel_info, tunnel_info['node'])

            # 使用当前节点启动隧道
            self._start_tunnel_process(tunnel_info)

        except Exception as e:
            self.logger.error(f"启动隧道时发生错误: {str(e)}")
            QMessageBox.warning(self, "错误", f"启动隧道失败: {str(e)}")

    def _start_tunnel_process(self, tunnel_info):
        """内部方法，启动隧道进程"""
        with self.process_lock:
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

                self.capture_output(tunnel_info['name'], process)

                self.update_tunnel_card_status(tunnel_info['name'], True)

                self.start_frequent_tunnel_monitor(tunnel_info['name'])

                self.send_notification("tunnel_start",
                                       f"隧道 {tunnel_info['name']} 已成功启动\n节点：{tunnel_info['node']}",
                                       tunnel_info['name'])

            except Exception as e:
                self.logger.error(f"启动隧道失败: {str(e)}")
                raise

    def start_frequent_tunnel_monitor(self, tunnel_name):
        """开始以高频率监控隧道进程状态"""
        QTimer.singleShot(100, lambda: self.check_tunnel_status_frequent(tunnel_name))

    def check_tunnel_status_frequent(self, tunnel_name):
        """检查隧道状态"""
        try:
            if tunnel_name not in self.tunnel_processes:
                QTimer.singleShot(0, lambda: self.update_tunnel_card_status(tunnel_name, False))
                return

            process = self.tunnel_processes[tunnel_name]

            if process.poll() is not None:
                exit_code = process.returncode
                self.logger.info(f"隧道 {tunnel_name} 已停止运行, 退出代码: {exit_code}")

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

                        # 获取完整HTML格式的日志
                        log_html = self.tunnel_outputs[tunnel_name]['output']
                        # 限制日志长度
                        max_log_length = 2000
                        if len(log_html) > max_log_length:
                            log_html = "..." + log_html[-max_log_length:]

                with self.process_lock:
                    if tunnel_name in self.tunnel_processes:
                        del self.tunnel_processes[tunnel_name]

                QTimer.singleShot(0, lambda: self.update_tunnel_card_status(tunnel_name, False))

                # 发送带有HTML格式日志的通知
                notification_html = f"""
                <h3>隧道 {tunnel_name} 异常停止</h3>
                <p><b>退出代码:</b> {exit_code}</p>
                <p><b>时间:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p><b>错误信息:</b> <span style="color: red;">{error_message}</span></p>
                <p><b>日志内容:</b></p>
                <div style="border: 1px solid #ddd; padding: 8px; background-color: #f8f8f8; max-height: 300px; overflow-y: auto;">
                {log_html}
                </div>
                """

                self.send_notification("tunnel_offline", notification_html, tunnel_name)

                QTimer.singleShot(100, self.load_tunnels)
                return

            QTimer.singleShot(0, lambda: self.update_tunnel_card_status(tunnel_name, True))

            QTimer.singleShot(100, lambda: self.check_tunnel_status_frequent(tunnel_name))

        except Exception as e:
            self.logger.error(f"监控隧道状态失败: {str(e)}")
            QTimer.singleShot(0, lambda: self.update_tunnel_card_status(tunnel_name, False))

    def obfuscate_sensitive_data(self, text):
        obfuscated_text = re.sub(re.escape(self.token), '*******你的token********', text, flags=re.IGNORECASE)
        obfuscated_text = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
                                 lambda x: '{}.***.***.{}'.format(x.group(0).split('.')[0], x.group(0).split('.')[-1]),
                                 obfuscated_text)
        return obfuscated_text

    def switch_to_backup_node(self, tunnel_info, current_process):
        """当节点离线时切换到备用节点"""
        try:
            backup_config = self.get_backup_config(tunnel_info.get('id'))
            if not backup_config:
                self.logger.info(f"隧道 {tunnel_info.get('name', 'unknown')} 的节点离线，但没有备用节点配置")
                return False
            backup_nodes = backup_config.get('backup_nodes')
            if not backup_nodes:
                self.logger.info(f"隧道 {tunnel_info.get('name', 'unknown')} 的节点离线，但没有备用节点配置")
                return False
            tunnel_name = tunnel_info.get('name', 'unknown')
            if current_process and current_process.poll() is None:
                current_process.terminate()
                try:
                    current_process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    current_process.kill()
            if tunnel_name in self.tunnel_processes:
                del self.tunnel_processes[tunnel_name]

            self.logger.info(f"隧道 {tunnel_name} 的节点离线，尝试切换到备用节点")
            for backup_node in backup_nodes:
                if API.is_node_online(backup_node, tyen="online"):
                    self.logger.info(f"正在切换到备用节点 {backup_node}")
                    modified_tunnel = tunnel_info.copy()
                    modified_tunnel['node'] = backup_node
                    success = True
                    domain_config = backup_config.get('domain')
                    if domain_config and isinstance(domain_config, dict):
                        if domain_config.get('domain') and domain_config.get('record'):
                            domain_result = self.update_domain_for_backup(domain_config, modified_tunnel, backup_node)
                            if not domain_result:
                                self.logger.warning(f"切换到备用节点 {backup_node} 时更新域名失败，但仍将继续启动隧道")
                        else:
                            self.logger.warning(f"域名配置不完整，无法更新域名记录")
                    if success:
                        QTimer.singleShot(0, lambda: self._start_tunnel_process(modified_tunnel))
                        return True
            self.logger.warning(f"隧道 {tunnel_name} 的所有备用节点都不在线")
            return False
        except Exception as e:
            self.logger.error(f"切换到备用节点时发生错误: {str(e)}")
            return False

    def update_domain_for_backup(self, domain_config, tunnel_info, node_name):
        try:
            if not domain_config or not tunnel_info or not node_name:
                self.logger.error(
                    f"更新域名缺少必要参数: domain_config={bool(domain_config)}, tunnel_info={bool(tunnel_info)}, node_name={bool(node_name)}")
                return False

            if domain_config.get('is_new', False):
                self.logger.info(
                    f"正在为备用节点创建新域名: {domain_config.get('record', '')}.{domain_config.get('domain', '')}")

                if not domain_config.get('domain') or not domain_config.get('record'):
                    self.logger.error(f"域名配置缺少必要字段: {domain_config}")
                    return False

                result = self.create_cname_domain_for_tunnel(
                    domain_config.get('domain', ''),
                    domain_config.get('record', ''),
                    tunnel_info,
                    node_name
                )
                return result
            else:
                self.logger.info(
                    f"正在更新域名 {domain_config.get('record', '')}.{domain_config.get('domain', '')} 指向备用节点")

                if not domain_config.get('domain') or not domain_config.get('record'):
                    self.logger.error(f"域名配置缺少必要字段: {domain_config}")
                    return False

                result = self.update_cname_domain_for_tunnel(
                    domain_config.get('domain', ''),
                    domain_config.get('record', ''),
                    tunnel_info,
                    node_name
                )
                return result
        except Exception as e:
            self.logger.error(f"更新备用节点域名失败: {str(e)}")
            return False

    def update_backup_domain_config(self, tunnel_id, domain, record, is_new=False):
        """更新备用配置中的域名信息"""
        try:
            config_path = get_absolute_path("backup_config.json")
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    configs = json.load(f)

                # 更新域名配置
                if str(tunnel_id) in configs:
                    configs[str(tunnel_id)]['domain'] = {
                        'domain': domain,
                        'record': record,
                        'is_new': is_new,
                        'last_updated': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    }

                    # 保存更新后的配置
                    with open(config_path, 'w') as f:
                        json.dump(configs, f, indent=4)

                    self.logger.info(f"已更新隧道 {tunnel_id} 的域名配置信息")
        except Exception as e:
            self.logger.error(f"更新备用域名配置时发生错误: {str(e)}")

    def update_domain_last_updated(self, tunnel_id, domain, record):
        """更新域名最后更新时间"""
        try:
            config_path = get_absolute_path("backup_config.json")
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    configs = json.load(f)

                # 更新最后更新时间
                if str(tunnel_id) in configs and 'domain' in configs[str(tunnel_id)]:
                    configs[str(tunnel_id)]['domain']['last_updated'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

                    # 保存更新后的配置
                    with open(config_path, 'w') as f:
                        json.dump(configs, f, indent=4)
        except Exception as e:
            self.logger.error(f"更新域名最后更新时间时发生错误: {str(e)}")

    def create_cname_domain_for_tunnel(self, domain, record, tunnel_info, node_name):
        """为使用备用节点的隧道创建新的CNAME记录，返回是否成功"""
        try:
            if not domain or not record or not tunnel_info or not node_name:
                self.logger.error(
                    f"创建CNAME记录缺少必要参数: domain={bool(domain)}, record={bool(record)}, tunnel_info={bool(tunnel_info)}, node_name={bool(node_name)}")
                return False

            node_info = self.get_node_info(node_name)
            if not node_info:
                self.logger.error(f"无法获取节点 {node_name} 的信息")
                return False

            target = self.get_tunnel_target(tunnel_info, node_info)
            if not target:
                self.logger.error(f"无法获取隧道 {tunnel_info.get('name', 'unknown')} 的目标")
                return False

            url = "http://cf-v2.uapis.cn/create_free_subdomain"
            payload = {
                "token": self.token,
                "domain": domain,
                "record": record,
                "type": "CNAME",
                "ttl": "1分钟",
                "target": target,
                "remarks": f"备用节点 {node_name} 的域名"
            }

            headers = get_headers(request_json=True)
            response = requests.post(url, headers=headers, json=payload)
            response_data = response.json()

            if response_data['code'] == 200:
                self.logger.info(f"创建备用节点域名成功: {response_data.get('msg', '')}")

                if tunnel_info.get('id'):
                    self.update_backup_domain_config(tunnel_info['id'], domain, record, False)
                else:
                    self.logger.warning(f"无法更新本地配置: 隧道ID缺失")

                return True
            else:
                self.logger.error(f"创建备用节点域名失败: {response_data.get('msg', '')}")
                return False

        except Exception as e:
            self.logger.error(f"创建备用节点域名时发生错误: {str(e)}")
            return False

    def update_cname_domain_for_tunnel(self, domain, record, tunnel_info, node_name):
        """更新现有CNAME记录指向备用节点，返回是否成功"""
        try:
            if not domain or not record or not tunnel_info or not node_name:
                self.logger.error(
                    f"更新CNAME记录缺少必要参数: domain={bool(domain)}, record={bool(record)}, tunnel_info={bool(tunnel_info)}, node_name={bool(node_name)}")
                return False

            node_info = self.get_node_info(node_name)
            if not node_info:
                self.logger.error(f"无法获取节点 {node_name} 的信息")
                return False

            target = self.get_tunnel_target(tunnel_info, node_info)
            if not target:
                self.logger.error(f"无法获取隧道 {tunnel_info.get('name', 'unknown')} 的目标")
                return False

            url = "http://cf-v2.uapis.cn/update_free_subdomain"
            payload = {
                "token": self.token,
                "domain": domain,
                "record": record,
                "type": "CNAME",
                "ttl": "1分钟",
                "target": target,
                "remarks": f"备用节点 {node_name} 的域名 (自动更新)"
            }

            headers = get_headers(request_json=True)
            response = requests.post(url, headers=headers, json=payload)
            response_data = response.json()

            if response_data['code'] == 200:
                self.logger.info(f"更新备用节点域名成功: {response_data.get('msg', '')}")

                if tunnel_info.get('id'):
                    self.update_domain_last_updated(tunnel_info['id'], domain, record)
                else:
                    self.logger.warning(f"无法更新本地配置: 隧道ID缺失")

                return True
            elif "子域名不存在" in response_data.get('msg', ''):
                # 域名不存在，尝试创建新域名
                self.logger.info(f"域名 {record}.{domain} 不存在，正在尝试创建...")
                return self.create_cname_domain_for_tunnel(domain, record, tunnel_info, node_name)
            else:
                self.logger.error(f"更新备用节点域名失败: {response_data.get('msg', '')}")
                return False

        except Exception as e:
            self.logger.error(f"更新备用节点域名时发生错误: {str(e)}")
            return False

    def get_tunnel_target(self, tunnel_info, node_info):
        try:
            if not tunnel_info or not node_info:
                self.logger.error(f"无法获取隧道目标: tunnel_info={bool(tunnel_info)}, node_info={bool(node_info)}")
                return None

            tunnel_type = tunnel_info.get('type', '').lower()

            if tunnel_type in ['http', 'https']:
                return tunnel_info.get('dorp', '')
            else:
                node_domain = node_info.get('ip', node_info.get('name', ''))
                return node_domain
        except Exception as e:
            self.logger.error(f"获取隧道目标时发生错误: {str(e)}")
            return None

    @staticmethod
    def render_html_with_colors(text):
        """将文本转换为HTML，处理ANSI颜色代码和日志级别"""
        # 首先处理日志级别的颜色
        text = re.sub(r'\[I\]', '<span style="color: green;">[I]</span>', text)
        text = re.sub(r'\[W\]', '<span style="color: orange;">[W]</span>', text)
        text = re.sub(r'\[E\]', '<span style="color: red;">[E]</span>', text)
        text = re.sub(r'\[D\]', '<span style="color: blue;">[D]</span>', text)

        # 处理所有常见的ANSI颜色代码
        text = re.sub(r'\033\[0;30m(.*?)(\033\[0m|\033\[0;)', r'<span style="color: black;">\1</span>', text)
        text = re.sub(r'\033\[0;31m(.*?)(\033\[0m|\033\[0;)', r'<span style="color: red;">\1</span>', text)
        text = re.sub(r'\033\[0;32m(.*?)(\033\[0m|\033\[0;)', r'<span style="color: green;">\1</span>', text)
        text = re.sub(r'\033\[0;33m(.*?)(\033\[0m|\033\[0;)', r'<span style="color: yellow;">\1</span>', text)
        text = re.sub(r'\033\[0;34m(.*?)(\033\[0m|\033\[0;)', r'<span style="color: blue;">\1</span>', text)
        text = re.sub(r'\033\[0;35m(.*?)(\033\[0m|\033\[0;)', r'<span style="color: magenta;">\1</span>', text)
        text = re.sub(r'\033\[0;36m(.*?)(\033\[0m|\033\[0;)', r'<span style="color: cyan;">\1</span>', text)
        text = re.sub(r'\033\[0;37m(.*?)(\033\[0m|\033\[0;)', r'<span style="color: white;">\1</span>', text)
        text = re.sub(r'\033\[0m', '', text)
        return text

    def find_tunnel_by_name(self, tunnel_name):
        """根据隧道名称查找隧道信息"""
        if not self.token:
            return None

        try:
            tunnels = API.get_user_tunnels(self.token)
            if tunnels:
                for tunnel in tunnels:
                    if tunnel['name'] == tunnel_name:
                        return tunnel
        except Exception as e:
            self.logger.error(f"查找隧道信息时发生错误: {str(e)}")

        return None

    def capture_output(self, tunnel_name, process):
        """捕获隧道进程的输出"""
        try:
            if tunnel_name not in self.tunnel_outputs:
                self.tunnel_outputs[tunnel_name] = {
                    'output': '',
                    'run_number': 0,
                    'dialog': None,
                    'outputs_history': {}
                }

            current_run = self.tunnel_outputs[tunnel_name]['run_number'] + 1
            self.tunnel_outputs[tunnel_name]['run_number'] = current_run

            self.tunnel_outputs[tunnel_name]['outputs_history'][current_run] = ''
            self.tunnel_outputs[tunnel_name]['output'] = ''

            def update_output(line):
                try:
                    with QMutexLocker(self.output_mutex):
                        if tunnel_name in self.tunnel_outputs:
                            obfuscated_line = self.obfuscate_sensitive_data(line)

                            formatted_line = self.render_html_with_colors(obfuscated_line) + "<br>"

                            self.tunnel_outputs[tunnel_name]['output'] += formatted_line

                            if current_run in self.tunnel_outputs[tunnel_name]['outputs_history']:
                                self.tunnel_outputs[tunnel_name]['outputs_history'][current_run] += formatted_line

                            if ("node" in line.lower() and "offline" in line.lower()) or "节点离线" in line:
                                found_tunnel = self.find_tunnel_by_name(tunnel_name)
                                if found_tunnel:
                                    self.switch_to_backup_node(found_tunnel, process)

                            dialog = self.tunnel_outputs[tunnel_name]['dialog']
                            if dialog and not dialog.isHidden():
                                try:
                                    output_copy = self.tunnel_outputs[tunnel_name]['outputs_history'][current_run]
                                    dialog.output_update_signal.emit(tunnel_name, output_copy, current_run)
                                except Exception as content:
                                    self.logger.error(f"更新对话框时发生错误: {str(content)}")
                except Exception as content:
                    self.logger.error(f"更新输出时发生错误: {str(content)}")

            def read_output(pipe, callback):
                try:
                    for line in iter(pipe.readline, b''):
                        decoded_line = line.decode('utf-8', errors='replace').rstrip()
                        callback(decoded_line)
                    pipe.close()
                except Exception as e:
                    self.logger.error(f"读取进程输出时发生错误: {str(e)}")

            threading.Thread(
                target=read_output,
                args=(process.stdout, update_output),
                daemon=True
            ).start()

            threading.Thread(
                target=read_output,
                args=(process.stderr, update_output),
                daemon=True
            ).start()

        except Exception as e:
            self.logger.error(f"设置输出捕获时发生错误: {str(e)}")

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
        """检查隧道状态"""
        try:
            if tunnel_name not in self.tunnel_processes:
                self.update_tunnel_card_status(tunnel_name, False)
                return

            process = self.tunnel_processes[tunnel_name]

            if process.poll() is not None:
                exit_code = process.returncode
                self.logger.info(f"隧道 {tunnel_name} 已停止, 退出代码: {process.returncode}")

                # 获取隧道的日志内容
                log_html = ""
                with QMutexLocker(self.output_mutex):
                    if tunnel_name in self.tunnel_outputs:
                        # 保留HTML格式的日志内容
                        log_html = self.tunnel_outputs[tunnel_name]['output']
                        # 限制日志长度
                        max_log_length = 2000
                        if len(log_html) > max_log_length:
                            log_html = "..." + log_html[-max_log_length:]

                with self.process_lock:
                    if tunnel_name in self.tunnel_processes:
                        del self.tunnel_processes[tunnel_name]

                self.update_tunnel_card_status(tunnel_name, False)

                # 发送带有HTML格式日志的通知
                notification_html = f"""
                <h3>隧道 {tunnel_name} 已停止运行</h3>
                <p><b>退出代码:</b> {exit_code}</p>
                <p><b>时间:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p><b>日志内容:</b></p>
                <div style="border: 1px solid #ddd; padding: 8px; background-color: #f8f8f8; max-height: 300px; overflow-y: auto;">
                {log_html}
                </div>
                """

                self.send_notification("tunnel_offline", notification_html, tunnel_name)
            else:
                QTimer.singleShot(1000, lambda: self.check_tunnel_status(tunnel_name))

        except Exception as e:
            self.logger.error(f"检查隧道状态失败: {str(e)}")

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
                if isinstance(result, dict):
                    if "code" in result and result["code"] != 200:
                        if "error" in result:
                            api_message = result["error"]
                            is_success = False
                        elif "msg" in result:
                            api_message = result["msg"]
                            is_success = False
                        else:
                            api_message = str(result)
                            is_success = False
                    else:
                        api_message = result.get("msg", "隧道添加成功")
                        is_success = True
                elif isinstance(result, str):
                    try:
                        parsed = json.loads(result)
                        if isinstance(parsed, dict):
                            if "error" in parsed:
                                api_message = parsed["error"]
                                is_success = False
                            elif "msg" in parsed:
                                api_message = parsed["msg"]
                                is_success = (parsed.get("code", 0) == 200)
                            else:
                                api_message = result
                                is_success = True
                        else:
                            api_message = result
                            is_success = True
                    except json.JSONDecodeError:
                        api_message = result
                        is_success = True
                else:
                    api_message = str(result)
                    is_success = True
                if isinstance(api_message, str) and '\\u' in api_message:
                    try:
                        api_message = api_message.encode('latin1').decode('unicode_escape')
                    except Exception as decode_error:
                        self.logger.warning(f"无法解码API消息: {str(decode_error)}")
                if is_success:
                    self.logger.info(f"添加隧道成功: {api_message}")
                    QMessageBox.information(self, "隧道添加", api_message)
                else:
                    self.logger.warning(f"添加隧道失败: {api_message}")
                    QMessageBox.warning(self, "隧道添加", api_message)

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
                if isinstance(result, dict):
                    if "code" in result and result["code"] != 200:
                        if "error" in result:
                            api_message = result["error"]
                            is_success = False
                        elif "msg" in result:
                            api_message = result["msg"]
                            is_success = False
                        else:
                            api_message = str(result)
                            is_success = False
                    else:
                        api_message = result.get("msg", "隧道更新成功")
                        is_success = True
                elif isinstance(result, str):
                    try:
                        parsed = json.loads(result)
                        if isinstance(parsed, dict):
                            if "error" in parsed:
                                api_message = parsed["error"]
                                is_success = False
                            elif "msg" in parsed:
                                api_message = parsed["msg"]
                                is_success = (parsed.get("code", 0) == 200)
                            else:
                                api_message = result
                                is_success = True
                        else:
                            api_message = result
                            is_success = True
                    except json.JSONDecodeError:
                        api_message = result
                        is_success = True
                else:
                    api_message = str(result)
                    is_success = True

                if isinstance(api_message, str) and '\\u' in api_message:
                    try:
                        api_message = api_message.encode('latin1').decode('unicode_escape')
                    except Exception as decode_error:
                        self.logger.warning(f"无法解码API消息: {str(decode_error)}")

                if is_success:
                    self.logger.info(f"隧道更新成功: {api_message}")
                    QMessageBox.information(self, "隧道更新", api_message)
                else:
                    self.logger.warning(f"隧道更新失败: {api_message}")
                    QMessageBox.warning(self, "隧道更新", api_message)

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
                    # 保存隧道ID用于稍后删除本地备注
                    tunnel_id = tunnel_info["id"]

                    url_v2 = f"http://cf-v2.uapis.cn/deletetunnel"
                    params = {"token": self.token, "tunnelid": tunnel_id}
                    headers = get_headers()
                    response = requests.post(url_v2, headers=headers, params=params)
                    if response.status_code == 200:
                        self.logger.info(f"隧道 '{tunnel_info['name']}' 删除成功 (v2 API)")
                        self.selected_tunnels.remove(tunnel_info)

                        # 删除隧道的本地备注
                        self.delete_tunnel_comment(tunnel_id)
                    else:
                        self.logger.error(f"v2 API 删除隧道失败")
                        raise Exception(f"v2 API 删除失败")

                except Exception:
                    self.logger.error(f"v2 API 删除失败，尝试 v1 API...")
                    try:
                        # 保存隧道ID用于稍后删除本地备注
                        tunnel_id = tunnel_info["id"]

                        url_v1 = f"http://cf-v1.uapis.cn/api/deletetl.php"
                        params = {
                            "token": user_token,
                            "userid": user_id,
                            "nodeid": tunnel_id,
                        }
                        headers = get_headers()
                        response_v1 = requests.get(url_v1, params=params, headers=headers)
                        if response_v1.status_code == 200:
                            self.logger.info(f"隧道 '{tunnel_info['name']}' 删除成功 (v1 API)")
                            self.selected_tunnels.remove(tunnel_info)  # 从选中列表中移除

                            # 删除隧道的本地备注
                            self.delete_tunnel_comment(tunnel_id)
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
            # 更新节点并检查变化
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
        # 保存当前选中节点的信息
        selected_node_name = None
        if hasattr(self, 'selected_node') and self.selected_node:
            selected_node_name = self.selected_node.get('node_name')

        # 刷新节点列表
        self.load_nodes()

        # 如果之前有选中的节点，尝试重新选中它
        if selected_node_name:
            layout = self.node_container.layout()
            for i in range(layout.count()):
                widget = layout.itemAt(i).widget()

                # 对于API节点的特殊处理
                if selected_node_name == 'API服务器' and isinstance(widget, ApiStatusCard):
                    widget.setSelected(True)
                    continue

                # 对于普通节点
                if hasattr(widget, 'node_info') and widget.node_info.get('node_name') == selected_node_name:
                    widget.setSelected(True)

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

class MessageDialog(QDialog):
    """消息对话框，用于显示服务器消息"""
    def __init__(self, token=None, parent=None):
        super().__init__(parent)
        self.message_detail = None
        self.token = token
        self.parent = parent
        self.setWindowTitle("系统消息")
        self.setMinimumWidth(500)
        self.setMinimumHeight(400)
        self.init_ui()
        self.load_messages()

    def init_ui(self):
        layout = QVBoxLayout(self)
        # 消息列表
        self.message_list = QListWidget()
        self.message_list.setAlternatingRowColors(True)
        self.message_list.itemClicked.connect(self.show_message_detail)
        layout.addWidget(self.message_list)
        # 消息详情
        self.message_detail = QTextEdit()
        self.message_detail.setReadOnly(True)
        layout.addWidget(self.message_detail)
        # 刷新按钮
        refresh_button = QPushButton("刷新消息")
        refresh_button.clicked.connect(self.load_messages)
        # 关闭按钮
        close_button = QPushButton("关闭")
        close_button.clicked.connect(self.accept)

        button_layout = QHBoxLayout()
        button_layout.addWidget(refresh_button)
        button_layout.addStretch()
        button_layout.addWidget(close_button)
        layout.addLayout(button_layout)

    def load_messages(self):
        """从API加载消息"""
        self.message_list.clear()
        self.message_detail.clear()
        if not self.token:
            self.message_list.addItem("请先登录后查看消息")
            return
        try:
            url = "http://cf-v2.uapis.cn/messages"
            params = {"token": self.token}
            headers = get_headers()
            response = requests.get(url, headers=headers, params=params)
            if response.status_code == 200:
                data = response.json()
                if data['code'] == 200:
                    messages = data.get('data', [])

                    if not messages:
                        self.message_list.addItem("暂无消息")
                        return

                    for message in messages:
                        item = QListWidgetItem()
                        # 判断是否为全局消息或个人消息
                        is_global = message.get('quanti') == 'yes'
                        # 设置消息图标
                        if is_global:
                            item.setIcon(QIcon.fromTheme("dialog-information"))
                        else:
                            item.setIcon(QIcon.fromTheme("dialog-warning"))
                        # 设置消息标题
                        time_str = message.get('time', '').split('T')[0]  # 简化时间格式
                        title = f"[{time_str}] {'系统公告' if is_global else '个人通知'}"
                        item.setText(title)
                        # 存储消息内容
                        item.setData(Qt.ItemDataRole.UserRole, message)
                        # 设置文字颜色
                        if not is_global:
                            item.setForeground(Qt.GlobalColor.red)
                        self.message_list.addItem(item)
                else:
                    self.message_list.addItem(f"获取消息失败: {data.get('msg', '未知错误')}")
            else:
                self.message_list.addItem(f"网络错误: {response.status_code}")
        except Exception as e:
            if self.parent:
                self.parent.logger.error(f"加载消息时发生错误: {str(e)}")
            self.message_list.addItem(f"加载消息失败: {str(e)}")

    def show_message_detail(self, item):
        """显示消息详情"""
        message = item.data(Qt.ItemDataRole.UserRole)
        if not message:
            return

        content = message.get('content', '')
        time_str = message.get('time', '').replace('T', ' ').split('.')[0]
        is_global = message.get('quanti') == 'yes'

        detail_html = f"""
        <h3>{'系统公告' if is_global else '个人通知'}</h3>
        <p><b>时间:</b> {time_str}</p>
        <p><b>内容:</b></p>
        <div style="background-color: {'#f0f0f0' if is_global else '#fff0f0'}; padding: 10px; border-radius: 5px;">
            {content}
        </div>
        """

        self.message_detail.setHtml(detail_html)

    def apply_theme(self, is_dark):
        """应用主题"""
        if is_dark:
            self.setStyleSheet("""
                QDialog { background-color: #2D2D2D; color: #FFFFFF; }
                QListWidget { background-color: #3D3D3D; color: #FFFFFF; border: 1px solid #555555; }
                QListWidget::item:alternate { background-color: #353535; }
                QTextEdit { background-color: #3D3D3D; color: #FFFFFF; border: 1px solid #555555; }
                QPushButton { background-color: #0D6EFD; color: white; border-radius: 4px; padding: 6px 12px; }
                QPushButton:hover { background-color: #0B5ED7; }
            """)
        else:
            self.setStyleSheet("""
                QDialog { background-color: #FFFFFF; color: #212529; }
                QListWidget { background-color: #FFFFFF; color: #212529; border: 1px solid #CED4DA; }
                QListWidget::item:alternate { background-color: #F8F9FA; }
                QTextEdit { background-color: #FFFFFF; color: #212529; border: 1px solid #CED4DA; }
                QPushButton { background-color: #0D6EFD; color: white; border-radius: 4px; padding: 6px 12px; }
                QPushButton:hover { background-color: #0B5ED7; }
            """)

class BlacklistManager:
    """管理黑名单数据的类"""
    def __init__(self, logger=None):
        self.blacklist = []
        self.blacklist_loaded = False
        self.logger = logger

    def load_blacklist(self):
        """加载黑名单数据"""
        try:
            # 使用内网穿透.中国 的黑名单API
            url = "https://xn--6orp08a.xn--v6qw21h0gd43u.xn--fiqs8s/v1/blacklist/list/all"
            response = requests.get(url, timeout=10)

            # 检查请求是否成功
            if response.status_code == 200:
                data = response.json()
                # 检查API返回结构
                if 'data' in data and 'list' in data['data']:
                    self.blacklist = data['data']['list']
                    self.blacklist_loaded = True
                    return True
                else:
                    if self.logger:
                        self.logger.error("黑名单API返回格式不正确")
            else:
                if self.logger:
                    self.logger.error(f"黑名单API请求失败，状态码: {response.status_code}")

        except Exception as e:
            if self.logger:
                self.logger.error(f"加载黑名单时发生错误: {str(e)}")
        return False

    def get_blacklist_data(self):
        """获取原始黑名单数据"""
        if not self.blacklist_loaded:
            self.load_blacklist()
        return self.blacklist

class BlacklistDialog(QDialog):
    """黑名单信息对话框"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.blacklist_manager = BlacklistManager(logger=parent.logger if parent else None)

        self.setWindowTitle("黑名单列表")
        self.setMinimumWidth(650)
        self.setMinimumHeight(500)
        self.init_ui()
        self.load_blacklist()

    def init_ui(self):
        layout = QVBoxLayout(self)
        # 搜索区域
        search_layout = QHBoxLayout()
        search_label = QLabel("搜索:")
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("输入邮箱或原因关键词")
        self.search_input.textChanged.connect(self.filter_blacklist)
        search_layout.addWidget(search_label)
        search_layout.addWidget(self.search_input)
        layout.addLayout(search_layout)
        # 黑名单表格
        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["邮箱", "原因", "创建日期", "更新日期"])
        # 设置表格列宽
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)  # 邮箱列自适应
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)  # 原因列自适应
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)  # 创建日期列自适应内容
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)  # 更新日期列自适应内容

        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setAlternatingRowColors(True)
        layout.addWidget(self.table)
        # 统计信息
        self.stats_label = QLabel("加载中...")
        layout.addWidget(self.stats_label)
        # 按钮区域
        button_layout = QHBoxLayout()
        refresh_button = QPushButton("刷新")
        refresh_button.clicked.connect(self.load_blacklist)
        close_button = QPushButton("关闭")
        close_button.clicked.connect(self.accept)
        button_layout.addWidget(refresh_button)
        button_layout.addStretch()
        button_layout.addWidget(close_button)
        layout.addLayout(button_layout)

    def load_blacklist(self):
        """加载黑名单数据到表格"""
        # 显示加载状态
        self.table.setRowCount(0)
        self.stats_label.setText("正在加载黑名单数据...")
        QApplication.processEvents()
        # 加载数据
        success = self.blacklist_manager.load_blacklist()
        if not success:
            self.stats_label.setText("无法加载黑名单数据，请检查网络连接")
            return
        # 显示数据
        self.populate_table()

    @staticmethod
    def format_datetime(datetime_str):
        """格式化日期时间显示"""
        if not datetime_str:
            return "未知时间"
        try:
            # 将ISO格式的时间转换
            # 输入格式: 2024-07-22T18:51:38.000+00:00
            # 输出格式: 2024-07-22 18:51:38
            date_time_parts = datetime_str.split('T')
            date = date_time_parts[0]
            time = date_time_parts[1].split('.')[0]
            return f"{date} {time}"
        except:
            return datetime_str

    def populate_table(self, filter_text=None):
        """将数据填充到表格，可选过滤条件"""
        self.table.setRowCount(0)
        blacklist = self.blacklist_manager.get_blacklist_data()
        if not blacklist:
            self.stats_label.setText("黑名单为空")
            return
        # 过滤数据
        if filter_text:
            filter_text = filter_text.lower()
            filtered_list = [
                item for item in blacklist
                if filter_text in item.get('email', '').lower() or
                   filter_text in item.get('reason', '').lower()
            ]
        else:
            filtered_list = blacklist

        # 填充表格
        for row, item in enumerate(filtered_list):
            self.table.insertRow(row)
            # 处理可能包含多个邮箱的情况
            email = item.get('email', 'N/A')
            if ';' in email:
                email = email.replace(';', '\n')

            reason = item.get('reason', '未指定原因')
            created_at = self.format_datetime(item.get('createdAt', ''))
            updated_at = self.format_datetime(item.get('updatedAt', ''))

            email_item = QTableWidgetItem(email)
            email_item.setToolTip(email)  # 设置工具提示

            reason_item = QTableWidgetItem(reason)
            reason_item.setToolTip(reason)  # 设置工具提示

            self.table.setItem(row, 0, email_item)
            self.table.setItem(row, 1, reason_item)
            self.table.setItem(row, 2, QTableWidgetItem(created_at))
            self.table.setItem(row, 3, QTableWidgetItem(updated_at))

        # 表格行高自适应内容
        for row in range(self.table.rowCount()):
            self.table.resizeRowToContents(row)

        # 更新统计信息
        if filter_text:
            self.stats_label.setText(f"显示 {len(filtered_list)}/{len(blacklist)} 条记录 (已过滤)")
        else:
            self.stats_label.setText(f"共 {len(blacklist)} 条记录")

    def filter_blacklist(self):
        """根据搜索框内容过滤黑名单列表"""
        filter_text = self.search_input.text().strip()
        self.populate_table(filter_text)

    def apply_theme(self, is_dark):
        """应用主题"""
        if is_dark:
            self.setStyleSheet("""
                QDialog { background-color: #2D2D2D; color: #FFFFFF; }
                QTableWidget { background-color: #3D3D3D; color: #FFFFFF; border: 1px solid #555555; }
                QTableWidget::item:alternate { background-color: #353535; }
                QHeaderView::section { background-color: #2A2A2A; color: #FFFFFF; padding: 5px; border: 1px solid #555555; }
                QLineEdit { background-color: #3D3D3D; color: #FFFFFF; border: 1px solid #555555; padding: 5px; }
                QPushButton { background-color: #0D6EFD; color: white; border-radius: 4px; padding: 6px 12px; }
                QPushButton:hover { background-color: #0B5ED7; }
                QLabel { color: #FFFFFF; }
            """)
        else:
            self.setStyleSheet("""
                QDialog { background-color: #FFFFFF; color: #212529; }
                QTableWidget { background-color: #FFFFFF; color: #212529; border: 1px solid #DEE2E6; }
                QTableWidget::item:alternate { background-color: #F8F9FA; }
                QHeaderView::section { background-color: #E9ECEF; color: #212529; padding: 5px; border: 1px solid #DEE2E6; }
                QLineEdit { background-color: #FFFFFF; color: #212529; border: 1px solid #CED4DA; padding: 5px; }
                QPushButton { background-color: #0D6EFD; color: white; border-radius: 4px; padding: 6px 12px; }
                QPushButton:hover { background-color: #0B5ED7; }
                QLabel { color: #212529; }
            """)

if __name__ == '__main__':
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
    # 设置全局日志
    try:
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
    except Exception as e:
        print(f"设置全局日志失败: {str(e)}")
    # 窗口启动和文件检查
    try:
        sys.excepthook = exception_hook
        # 获取镜像地址
        MIRROR_PREFIXES = get_mirrors()
        Pre_run_operations.document_checking()  # 配置文件检查
        app = QApplication(sys.argv)
        main_window = MainWindow()
        main_window.show()
        sys.exit(app.exec())
    except Exception as e:
        print(f"发生意外错误: {e}")
        traceback.print_exc()
