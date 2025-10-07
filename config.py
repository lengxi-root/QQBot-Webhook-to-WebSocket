# -*- coding: utf-8 -*-

CONFIG_FILE = "config.py"

# 访问令牌 - 用于访问登录页面和管理面板
access_token = "admin123"

# 管理员配置
admin = {
    "password": "admin123",              # 管理员登录密码
    "enabled": True,                     # 是否启用管理员功能
}

# 消息缓存配置
cache = {
    "default_max_messages": 1000,  # 默认最大缓存消息数
    "max_public_messages": 1000,   # 公共消息最大缓存数
    "max_token_messages": 500,     # 带token消息最大缓存数
    "message_ttl": 300,            # 消息缓存时间（秒）
    "clean_interval": 120,         # 缓存清理间隔（秒）
}

# 消息去重TTL（秒）
deduplication_ttl = 20

# 日志级别 - DEBUG, INFO, WARNING, ERROR, CRITICAL
log_level = "INFO"

# 日志最大长度
log_maxlen = 2000

# 不缓存的密钥列表
no_cache_secrets = [
    # "example_secret_key",
]

# 服务监听端口
port = 8000

# 原始消息记录配置
raw_content = {
    "enabled": False,  # 是否启用原始消息记录
    "path": "logs",    # 原始消息日志保存路径
}

# SSL配置
ssl = {
    "ssl_keyfile": "",   # SSL私钥文件路径（留空则不启用SSL）
    "ssl_certfile": "",  # SSL证书文件路径（留空则不启用SSL）
}

# 统计信息配置
stats = {
    "write_interval": 5,              # 统计信息写入间隔（秒）
    "stats_file": "data/stats.json",  # 统计信息文件路径
}

# Webhook转发配置
webhook_forward = {
    "enabled": True,   # 是否启用Webhook转发
    "timeout": 5,      # 转发超时时间（秒）
    "targets": [       # 转发目标列表
        # {
        #     "url": "http://example.com/webhook?secret=your_secret",
        #     "secret": "your_secret_key",  # 匹配此密钥的消息将转发到此URL
        # },
    ],
}


def update_settings(settings_dict):
    """运行时更新配置"""
    try:
        globals().update(settings_dict)
        return True
    except Exception as e:
        import logging
        logging.error(f"更新配置失败: {str(e)}")
        return False
