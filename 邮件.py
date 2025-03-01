import smtplib
import socket
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import Tuple

def get_computer_name() -> str:
    """获取计算机名称"""
    return socket.gethostname()

def get_current_time() -> str:
    """获取当前格式化时间"""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def auto_detect_config(email: str) -> Tuple[str, int]:
    """
    自动识别邮箱配置
    返回 (smtp_server, port)
    """
    domain = email.split('@')[-1].lower()
    
    config_map = {
    'qq.com': ('smtp.qq.com', 465),
    '163.com': ('smtp.163.com', 465),
    'gmail.com': ('smtp.gmail.com', 465),
    'outlook.com': ('smtp.office365.com', 587),
    'hotmail.com': ('smtp.office365.com', 587),
    'yahoo.com': ('smtp.mail.yahoo.com', 465),
    'aliyun.com': ('smtp.aliyun.com', 465),
    '126.com': ('smtp.126.com', 465),
    'foxmail.com': ('smtp.exmail.qq.com', 465),
    'protonmail.com': ('smtp.protonmail.com', 465),
    'icloud.com': ('smtp.mail.me.com', 587),
    'zoho.com': ('smtp.zoho.com', 465),
    'aol.com': ('smtp.aol.com', 465),
    'mail.com': ('smtp.mail.com', 465),
    'tutanota.com': ('smtp.tutanota.com', 465),
    'sina.com': ('smtp.sina.com', 465),
    'sohu.com': ('smtp.sohu.com', 465),
    'yeah.net': ('smtp.yeah.net', 465),
    '21cn.com': ('smtp.21cn.com', 465),
    'tom.com': ('smtp.tom.com', 465),
    'vip.qq.com': ('smtp.vip.qq.com', 465),
    '263.net': ('smtp.263.net', 465),
}
    
    for key, value in config_map.items():
        if domain == key:
            return value
    
    if domain.endswith('.com') and 'exmail' in domain:
        return ('smtp.exmail.qq.com', 465)
    
    raise ValueError(f"不支持的邮箱服务商: {domain}，请手动配置SMTP信息")

def send_email(smtp_server: str, port: int, sender_email: str, 
              password: str, receiver_email: str, subject: str, body: str) -> Tuple[bool, str]:
    """
    发送邮件核心函数
    返回 (是否成功, 描述信息)
    """
    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = receiver_email
    message["Subject"] = subject
    
    # 修复HTML实体问题
    clean_body = body.replace("&ldquo;", "&ldquo;").replace("&rdquo;", "&rdquo;")
    message.attach(MIMEText(clean_body, "plain", "utf-8"))

    try:
        # 自动选择加密方式
        if port == 465:
            with smtplib.SMTP_SSL(smtp_server, port, timeout=15) as server:
                server.login(sender_email, password)
                server.sendmail(sender_email, receiver_email, message.as_string())
        else:
            with smtplib.SMTP(smtp_server, port, timeout=15) as server:
                server.starttls()
                server.login(sender_email, password)
                server.sendmail(sender_email, receiver_email, message.as_string())
        return True, "邮件发送成功"
    
    except smtplib.SMTPAuthenticationError as e:
        return False, f"认证失败：{str(e)}"
    except smtplib.SMTPConnectError as e:
        return False, f"连接服务器失败：{str(e)}"
    except smtplib.SMTPException as e:
        return False, f"SMTP协议错误：{str(e)}"
    except socket.timeout:
        return False, "连接超时，请检查网络设置"
    except Exception as e:
        return False, f"未知错误：{str(e)}"

# 配置参数（只需维护发件人信息）
config = {
    "sender_email": "1972403603@qq.com",
    "password": "*********",  # 授权码/密码
    "receiver_email": "boring_student@qq.com",
    "subject": "隧道alist离线",
    "body": f"来自&ldquo;{get_computer_name()}&rdquo;的CUL在 {get_current_time()} 发出的警告"
}

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
