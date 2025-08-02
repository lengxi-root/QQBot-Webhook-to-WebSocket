import json
import logging
import os
from pathlib import Path
import time
from concurrent.futures import ThreadPoolExecutor
from modules.privacy import PrivacyUtils
from modules.config import config
import uuid
import secrets
import hashlib
import functools
from typing import Dict, Any, Optional, Callable
from cryptography.hazmat.primitives.asymmetric import ed25519

# 线程池用于IO密集型任务
thread_pool = ThreadPoolExecutor(max_workers=4)

def setup_logger():
    """设置日志记录器"""
    log_level = getattr(logging, config.log_level, logging.INFO)
    
    # 自定义日志格式，不显示root前缀
    class NoRootFilter(logging.Filter):
        def filter(self, record):
            # 去掉root:前缀
            if record.name == 'root':
                record.name = ''
            return True
    
    # 消息过滤器
    class MessageFilter(logging.Filter):
        def filter(self, record):
            # 过滤掉心跳消息的日志
            message = record.getMessage()
            # 过滤心跳消息
            if '{"op":1,"d":1}' in message or "{'op': 1, 'd': 1}" in message:
                return False
            # 过滤原始消息日志
            if message.startswith("收到原始消息:") or "b'{" in message:
                return False
            # 过滤消息ID缓存日志
            if message.startswith("添加消息ID到缓存"):
                return False
            # 过滤统计信息写入日志
            if message.startswith("统计信息已写入文件:"):
                return False
            # 过滤密钥不匹配的Webhook转发跳过日志
            if "Webhook转发跳过" in message and "原因: 密钥不匹配" in message:
                return False
            # 过滤失败数为0的Webhook转发失败日志
            if "Webhook转发全部失败" in message and "失败数：0/0" in message:
                return False
            # 过滤转发消息内容日志
            if message.startswith("转发消息内容:") or (message.startswith("INFO::转发消息内容:") and "{" in message):
                return False
            # 过滤收到WS消息和解析WS消息日志
            if message.startswith("收到WS消息:") or message.startswith("INFO::收到WS消息:"):
                return False
            if message.startswith("解析WS消息:") or message.startswith("INFO::解析WS消息:"):
                return False
            # 过滤403错误日志
            if "connection rejected (403 Forbidden)" in message:
                return False
            if "connection closed" in message and record.levelname == "INFO":
                return False
            if "WebSocket" in message and "403" in message:
                return False
            # 保留WS连接成功日志
            return True
    
    # 配置根日志记录器
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        handlers=[
            logging.StreamHandler(),  # 仅输出到控制台
        ]
    )
    
    # 设置urllib3的日志级别为WARNING，减少不必要的日志
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    
    # 设置uvicorn.error日志级别为INFO，允许显示WebSocket连接信息
    logging.getLogger('uvicorn.error').setLevel(logging.INFO)
    
    # 确保根日志记录器级别设置正确
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    
    # 添加过滤器
    for handler in root_logger.handlers:
        handler.addFilter(NoRootFilter())
        handler.addFilter(MessageFilter())
    
    return root_logger

def generate_signature(bot_secret, event_ts, plain_token):
    """生成签名
    
    Args:
        bot_secret: 机器人密钥
        event_ts: 事件时间戳
        plain_token: 明文令牌
        
    Returns:
        dict: 包含签名和明文令牌的字典
    """
    while len(bot_secret) < 32:
        bot_secret = (bot_secret + bot_secret)[:32]

    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(bot_secret.encode())
    message = f"{event_ts}{plain_token}".encode()
    signature = private_key.sign(message).hex()

    return {
        "plain_token": plain_token,
        "signature": signature
    } 