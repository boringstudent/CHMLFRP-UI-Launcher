import smtplib
import socket
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import Tuple
import html

def get_computer_name() -> str:
    return socket.gethostname()

def get_current_time(format_str: str = "%Y-%m-%d %H:%M:%S") -> str:
    return datetime.now().strftime(format_str)

def auto_detect_config(email: str) -> Tuple[str, int]:
    domain = email.split('@')[-1].lower()
    
    # 扩展支持的邮箱配置
    config_map = {
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
    
    for key, value in config_map.items():
        if domain.endswith(key):  # 支持子域名（如 exmail.qq.com 的子域名）
            return value
    
    if domain.endswith('.com') and 'exmail' in domain:
        return ('smtp.exmail.qq.com', 465)
    
    raise ValueError(f"不支持的邮箱服务商: {domain}，请手动配置SMTP信息")

def send_email(smtp_server: str, port: int, sender_email: str, 
              password: str, receiver_email: str, subject: str, body: str) -> Tuple[bool, str]:

    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = receiver_email
    message["Subject"] = subject
    
    # 使用 html.unescape 替换 HTML 实体
    clean_body = html.unescape(body)
    message.attach(MIMEText(clean_body, "plain", "utf-8"))

    try:
        # 根据端口号选择加密方式
        server = None
        if port == 465:
            server = smtplib.SMTP_SSL(smtp_server, port, timeout=15)
        else:
            server = smtplib.SMTP(smtp_server, port, timeout=15)
            server.starttls()
        
        server.login(sender_email, password)
        server.sendmail(sender_email, receiver_email, message.as_string())
        server.quit()
        return True, "邮件发送成功"
    
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

# 配置参数（建议使用环境变量存储敏感信息）
config = {
    "sender_email": "1972403603@qq.com",
    "receiver_email": "1972403603@qq.com",
    "subject": "隧道alist离线",
    "body": f"来自&ldquo;{get_computer_name()}&rdquo;的CUL在 {get_current_time()} 发出的警告"
}

password = "********"

config["password"] = password

# 自动识别配置
try:
    smtp_server, port = auto_detect_config(config["sender_email"])
    config.update({
        "smtp_server": smtp_server,
        "port": port
    })
except ValueError as e:
    print(f"配置错误: {str(e)}")
    exit(1)

# 发送邮件
success, message = send_email(**config)
print(f"发送结果: {success}, 信息: {message}")
