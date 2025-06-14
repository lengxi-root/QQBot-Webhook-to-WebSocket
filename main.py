from fastapi import FastAPI, Request, Header, WebSocket, WebSocketDisconnect
from fastapi.responses import *
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from cryptography.hazmat.primitives.asymmetric import ed25519
from datetime import datetime, timedelta
import logging
import uvicorn
import asyncio
from collections import deque, defaultdict
import configparser
import os
from pathlib import Path
import re
from urllib.parse import urlparse
import psutil
import platform
import aiohttp
from typing import List
from models import get_session, WebhookStats, ConnectionStats, ensure_tables
from sqlalchemy import update, func, text
from contextlib import asynccontextmanager
import time
from concurrent.futures import ThreadPoolExecutor
import threading
from functools import partial

try:
    import orjson

    json_module = orjson
    JSONDecodeError = orjson.JSONDecodeError
except ImportError:
    import json

    json_module = json
    JSONDecodeError = json.JSONDecodeError

# 线程池用于IO密集型任务
thread_pool = ThreadPoolExecutor(max_workers=4)

# 缓存大小配置
CACHE_CONFIG = {
    "default_max_messages": 1000,  # 默认每个密钥最大缓存消息数
    "max_public_messages": 1000,  # 公共队列最大消息数
    "max_token_messages": 500,  # 每个token队列最大消息数
    "message_ttl": 300,  # 消息有效期(秒)，5分钟
    "clean_interval": 120,  # 清理间隔(秒)
}


# 消息缓存管理器
class MessageCacheManager:
    def __init__(self):
        self.message_cache = {}  # {secret: {"public": deque(), "tokens": {token: deque()}}}
        self.cache_locks = {}  # {secret: asyncio.Lock()}
        self.message_id_cache = {}  # {message_id: expiry_timestamp}
        self.clean_thread = None
        self.stop_flag = threading.Event()

    async def get_lock_for_secret(self, secret):
        """获取特定密钥的锁"""
        if secret not in self.cache_locks:
            self.cache_locks[secret] = asyncio.Lock()
        return self.cache_locks[secret]

    def start_cleaning_thread(self):
        """启动清理线程"""
        if self.clean_thread is None or not self.clean_thread.is_alive():
            self.stop_flag.clear()
            self.clean_thread = threading.Thread(target=self._clean_expired_messages)
            self.clean_thread.daemon = True
            self.clean_thread.start()
            logging.info("缓存清理线程已启动")

    def stop_cleaning_thread(self):
        """停止清理线程"""
        if self.clean_thread and self.clean_thread.is_alive():
            self.stop_flag.set()
            self.clean_thread.join(timeout=2)
            logging.info("缓存清理线程已停止")

    def _clean_expired_messages(self):
        """清理过期消息线程"""
        while not self.stop_flag.is_set():
            try:
                # 清理message_id缓存
                now = datetime.now()
                expired_ids = [msg_id for msg_id, expiry in self.message_id_cache.items() if expiry < now]
                for msg_id in expired_ids:
                    self.message_id_cache.pop(msg_id, None)

                if expired_ids:
                    logging.debug(f"清理过期消息ID: {len(expired_ids)}个")

                # 清理消息缓存
                for secret in list(self.message_cache.keys()):
                    try:
                        cache = self.message_cache[secret]

                        # 清理公共缓存
                        if "public" in cache:
                            before_count = len(cache["public"])
                            cache["public"] = deque(
                                [(exp, data) for exp, data in cache["public"] if exp > now],
                                maxlen=cache["public"].maxlen
                            )
                            after_count = len(cache["public"])
                            if before_count > after_count:
                                logging.debug(
                                    f"清理公共缓存 | 密钥：{PrivacyUtils.sanitize_secret(secret)} | 清理:{before_count - after_count}个")

                        # 清理token缓存
                        empty_tokens = []
                        for token, queue in cache.get("tokens", {}).items():
                            before_count = len(queue)
                            cache["tokens"][token] = deque(
                                [(exp, data) for exp, data in queue if exp > now],
                                maxlen=queue.maxlen
                            )
                            after_count = len(cache["tokens"][token])

                            # 如果队列为空，标记为删除
                            if after_count == 0:
                                empty_tokens.append(token)
                            elif before_count > after_count:
                                logging.debug(
                                    f"清理Token缓存 | 密钥：{PrivacyUtils.sanitize_secret(secret)} | Token：{PrivacyUtils.sanitize_secret(token)} | 清理:{before_count - after_count}个")

                        # 删除空队列
                        for token in empty_tokens:
                            del cache["tokens"][token]

                        # 如果密钥下没有任何缓存，删除该密钥
                        if (not cache.get("public") or len(cache["public"]) == 0) and len(cache.get("tokens", {})) == 0:
                            del self.message_cache[secret]
                            if secret in self.cache_locks:
                                del self.cache_locks[secret]
                            logging.debug(f"删除空缓存 | 密钥：{PrivacyUtils.sanitize_secret(secret)}")

                    except Exception as e:
                        logging.error(f"清理密钥{PrivacyUtils.sanitize_secret(secret)}缓存异常: {e}")

                # 等待下一次清理
                for _ in range(int(CACHE_CONFIG["clean_interval"] / 0.5)):
                    if self.stop_flag.is_set():
                        break
                    time.sleep(0.5)

            except Exception as e:
                logging.error(f"缓存清理线程异常: {e}")
                time.sleep(30)  # 出错后延长等待时间

    async def add_message(self, secret, message_bytes, token=None):
        """添加消息到缓存"""
        lock = await self.get_lock_for_secret(secret)
        async with lock:
            now = datetime.now()
            expiry = now + timedelta(seconds=CACHE_CONFIG["message_ttl"])

            # 初始化缓存结构
            if secret not in self.message_cache:
                self.message_cache[secret] = {
                    "public": deque(maxlen=CACHE_CONFIG["max_public_messages"]),
                    "tokens": {}
                }

            # 添加到公共缓存
            if token is None:
                self.message_cache[secret]["public"].append((expiry, message_bytes))
                return True

            # 添加到Token缓存
            if token not in self.message_cache[secret]["tokens"]:
                self.message_cache[secret]["tokens"][token] = deque(maxlen=CACHE_CONFIG["max_token_messages"])

            self.message_cache[secret]["tokens"][token].append((expiry, message_bytes))
            return True

    async def get_messages_for_token(self, secret, token):
        """获取指定token的消息，并清空缓存"""
        lock = await self.get_lock_for_secret(secret)
        async with lock:
            if secret not in self.message_cache or token not in self.message_cache[secret]["tokens"]:
                return []

            messages = list(self.message_cache[secret]["tokens"][token])
            self.message_cache[secret]["tokens"][token].clear()
            return messages

    async def get_public_messages(self, secret):
        """获取公共消息，并清空缓存"""
        lock = await self.get_lock_for_secret(secret)
        async with lock:
            if secret not in self.message_cache or "public" not in self.message_cache[secret]:
                return []

            messages = list(self.message_cache[secret]["public"])
            self.message_cache[secret]["public"].clear()
            return messages

    def add_message_id(self, message_id, ttl=None):
        """添加消息ID到去重缓存"""
        if not ttl:
            ttl = CACHE_CONFIG["message_ttl"]
        self.message_id_cache[message_id] = datetime.now() + timedelta(seconds=ttl)

    def has_message_id(self, message_id):
        """检查消息ID是否存在"""
        return message_id in self.message_id_cache


# 创建缓存管理器
cache_manager = MessageCacheManager()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # 启动配置监控任务
    config_task = asyncio.create_task(watch_config())
    # 启动健康监控任务
    health_task = asyncio.create_task(monitor_service_health())
    # 确保数据库表已创建
    await ensure_tables()
    # 启动缓存清理线程
    cache_manager.start_cleaning_thread()

    logging.info(f"服务已启动")

    yield

    # 清理资源
    config_task.cancel()
    health_task.cancel()
    # 停止缓存清理线程
    cache_manager.stop_cleaning_thread()

    try:
        await config_task
        await health_task
    except asyncio.CancelledError:
        pass
    logging.info(f"服务已停止")


app = FastAPI(lifespan=lifespan)

# 跨域配置
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class PrivacyUtils:
    @staticmethod
    def sanitize_ip(ip: str) -> str:
        """IP地址脱敏处理"""
        if not ip or ip == "unknown":
            return "unknown"
        ip_parts = ip.split('.')
        if len(ip_parts) == 4:  # IPv4地址处理
            return f"{ip_parts[0]}.***.***.{ip_parts[3]}"
        return ip

    @staticmethod
    def sanitize_secret(secret: str) -> str:
        """密钥脱敏处理"""
        if not secret:
            return "****"
        if len(secret) <= 6:
            return "****"
        return f"{secret[:3]}****{secret[-3:]}"

    @staticmethod
    def sanitize_url(url: str) -> str:
        """URL脱敏处理"""
        try:
            parsed = urlparse(url)
            # 处理域名部分
            netloc = parsed.netloc
            if ':' in netloc:
                host, port = netloc.split(':')
                host = PrivacyUtils.sanitize_ip(host)
                netloc = f"{host}:{port}"
            else:
                netloc = PrivacyUtils.sanitize_ip(netloc)

            # 处理查询参数中的密钥
            query = parsed.query
            if query:
                query_params = dict(param.split('=') for param in query.split('&') if '=' in param)
                if 'secret' in query_params:
                    query_params['secret'] = PrivacyUtils.sanitize_secret(query_params['secret'])
                query = '&'.join(f"{k}={v}" for k, v in query_params.items())

            # 重建URL
            sanitized = parsed._replace(netloc=netloc, query=query)
            return sanitized.geturl()
        except Exception as e:
            logging.error(f"URL脱敏处理失败: {str(e)}")
            return "***"

    @staticmethod
    def sanitize_path(path: str) -> str:
        """URL路径脱敏处理"""
        return re.sub(
            r"(secret=)(\w{3})\w+",
            r"\1\2****",
            path,
            flags=re.IGNORECASE
        )


# 隐私保护中间件
@app.middleware("http")
async def privacy_middleware(request: Request, call_next):
    response = await call_next(request)

    # IP地址脱敏处理
    client_host = request.client.host if request.client else "unknown"
    sanitized_ip = PrivacyUtils.sanitize_ip(client_host)

    # URL路径处理
    full_url = str(request.url)
    parsed_url = urlparse(full_url)
    sanitized_path = parsed_url.path
    if parsed_url.query:
        sanitized_path += "?" + parsed_url.query

    # 敏感参数过滤
    sanitized_path = PrivacyUtils.sanitize_path(sanitized_path)

    # 构建安全日志
    log_message = (
        f'{sanitized_ip}:{request.client.port if request.client else 0} - '
        f'"{request.method} {sanitized_path} HTTP/{request.scope["http_version"]}" '
        f'{response.status_code}'
    )

    logger.info(log_message)

    return response


# 存储结构
active_connections = {}  # {secret: {websocket: {"token": str, ...}}}
message_cache = {}  # {secret: {"public": deque(), "tokens": {token: deque()}}}
cache_locks = {}  # {secret: asyncio.Lock()} - 细化锁粒度，每个密钥一个锁
message_id_cache = {}  # {message_id: expiry_timestamp}


# 日志配置
def load_log_config():
    config = configparser.ConfigParser()
    config.read('config.ini', encoding='UTF-8')
    log_level = config.get('DEFAULT', 'log', fallback='INFO').upper()
    if log_level == "TESTING":
        log_level = "DEBUG"
    return log_level


# 加载消息去重配置
def load_deduplication_config():
    config = configparser.ConfigParser()
    config.read('config.ini', encoding='UTF-8')
    return config.getint('DEFAULT', 'deduplication_ttl', fallback=20)


# 加载原始内容记录配置
def load_raw_content_config():
    config = configparser.ConfigParser()
    config.read('config.ini', encoding='UTF-8')
    return {
        'enabled': config.getboolean('DEFAULT', 'save_raw_content', fallback=False),
        'path': config.get('DEFAULT', 'raw_content_path', fallback='logs')
    }


# 加载不缓存的密钥列表
def load_no_cache_secrets():
    config = configparser.ConfigParser()
    config.read('config.ini', encoding='UTF-8')
    no_cache_secrets = config.get('DEFAULT', 'no_cache_secrets', fallback='').strip()
    if not no_cache_secrets:
        return []
    return [secret.strip() for secret in no_cache_secrets.split(',')]


# 初始化日志
log_level = load_log_config()
logging.basicConfig(
    level=log_level,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger()


# 签名生成函数
def generate_signature(bot_secret, event_ts, plain_token):
    while len(bot_secret) < 32:
        bot_secret = (bot_secret + bot_secret)[:32]

    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(bot_secret.encode())
    message = f"{event_ts}{plain_token}".encode()
    signature = private_key.sign(message).hex()

    return {
        "plain_token": plain_token,
        "signature": signature
    }


class Payload(BaseModel):
    d: dict


# 统计数据结构
connection_stats = {
    "history_connections": defaultdict(int),  # 历史连接数
    "webhook_forwards": defaultdict(lambda: {"count": 0, "urls": set(), "total_bytes": 0}),  # webhook转发统计
    "active_keys": set(),  # 活跃密钥
}


def get_system_stats():
    """获取系统资源使用情况"""
    process = psutil.Process(os.getpid())

    # CPU使用率
    cpu_percent = process.cpu_percent(interval=0.1)

    # 内存使用
    memory_info = process.memory_info()
    memory_percent = process.memory_percent()

    # 系统信息
    system_info = {
        "platform": platform.system(),
        "platform_version": platform.version(),
        "python_version": platform.python_version(),
        "cpu_count": psutil.cpu_count(),
        "total_memory": psutil.virtual_memory().total,
    }

    return {
        "cpu_percent": round(cpu_percent, 1),
        "memory_used": memory_info.rss,  # 实际使用的物理内存
        "memory_percent": round(memory_percent, 1),
        "system_info": system_info
    }


async def update_webhook_stats(secret: str, url: str, bytes_count: int):
    """更新webhook统计数据"""
    try:
        async with await get_session() as session:
            async with session.begin():
                stats = (await session.execute(
                    text("SELECT * FROM webhook_stats WHERE secret = :secret AND url = :url"),
                    {"secret": secret, "url": url}
                )).first()

                if stats:
                    await session.execute(
                        text(
                            "UPDATE webhook_stats SET count = count + 1, total_bytes = total_bytes + :bytes, last_updated = :now WHERE secret = :secret AND url = :url"),
                        {"bytes": bytes_count, "now": datetime.now(), "secret": secret, "url": url}
                    )
                else:
                    await session.execute(
                        text(
                            "INSERT INTO webhook_stats (secret, url, count, total_bytes, last_updated) VALUES (:secret, :url, 1, :bytes, :now)"),
                        {"secret": secret, "url": url, "bytes": bytes_count, "now": datetime.now()}
                    )
    except Exception as e:
        logging.error(f"更新webhook统计失败: {e}")


async def update_connection_stats(secret: str, is_active: bool = True):
    """更新连接统计数据"""
    try:
        async with await get_session() as session:
            async with session.begin():
                stats = (await session.execute(
                    text("SELECT * FROM connection_stats WHERE secret = :secret"),
                    {"secret": secret}
                )).first()

                if stats:
                    if is_active:
                        await session.execute(
                            text(
                                "UPDATE connection_stats SET history_connections = history_connections + 1, is_active = 1, last_updated = :now WHERE secret = :secret"),
                            {"now": datetime.now(), "secret": secret}
                        )
                    else:
                        await session.execute(
                            text(
                                "UPDATE connection_stats SET is_active = 0, last_updated = :now WHERE secret = :secret"),
                            {"now": datetime.now(), "secret": secret}
                        )
                else:
                    await session.execute(
                        text(
                            "INSERT INTO connection_stats (secret, history_connections, is_active, last_updated) VALUES (:secret, :history, :active, :now)"),
                        {"secret": secret, "history": 1 if is_active else 0, "active": 1 if is_active else 0,
                         "now": datetime.now()}
                    )
    except Exception as e:
        logging.error(f"更新连接统计失败: {e}")


@app.get("/logs")
async def logs_page():
    return FileResponse("logs.html")


# 获取特定密钥的锁
async def get_lock_for_secret(secret):
    return await cache_manager.get_lock_for_secret(secret)


@app.get("/api/stats")
async def get_stats():
    try:
        async with await get_session() as session:
            # 获取在线连接信息
            online_connections = []
            total_online = 0

            for secret, connections in active_connections.items():
                for ws, info in connections.items():
                    total_online += 1
                    online_connections.append({
                        "secret": f"{secret[:3]}****",
                        "token": f"{info['token'][:3]}****" if info.get('token') else None,
                        "environment": "沙盒环境" if info.get('is_sandbox') else "正式环境",
                        "type": "常驻连接" if info.get('token') else "临时连接"
                    })

            # 获取webhook转发信息
            webhook_stats_result = await session.execute(text("SELECT * FROM webhook_stats"))
            webhook_stats = webhook_stats_result.fetchall()
            webhook_forwards = []
            total_webhooks = 0
            total_bytes = 0

            for stats in webhook_stats:
                total_webhooks += stats.count
                total_bytes += stats.total_bytes

                parsed_url = urlparse(stats.url)
                domain = parsed_url.netloc.split('.')
                if len(domain) >= 2:
                    domain = f"{domain[0]}.{domain[1]}"
                else:
                    domain = parsed_url.netloc

                webhook_forwards.append({
                    "secret": f"{stats.secret[:3]}****",
                    "url": f"{domain}...",
                    "count": stats.count,
                    "total_bytes": stats.total_bytes
                })

            # 获取历史连接总数
            history_count_result = await session.execute(text("SELECT SUM(history_connections) FROM connection_stats"))
            history_count = history_count_result.scalar() or 0

            # 获取活跃密钥数
            active_keys_result = await session.execute(
                text("SELECT COUNT(*) FROM connection_stats WHERE is_active = 1"))
            active_keys = active_keys_result.scalar()

            # 获取系统资源使用情况
            system_stats = get_system_stats()

            return {
                "online_count": total_online,
                "history_count": history_count,
                "webhook_count": total_webhooks,
                "webhook_total_bytes": total_bytes,
                "active_keys": active_keys,
                "online_connections": online_connections,
                "webhook_forwards": webhook_forwards,
                "system_stats": system_stats
            }
    except Exception as e:
        logging.error(f"获取统计数据失败: {e}")
        return {"error": "获取统计数据失败"}


def load_webhook_config() -> dict:
    config = configparser.ConfigParser()
    config.read('config.ini', encoding='UTF-8')

    # 解析目标URL和对应的密钥
    targets_config = config.get('WEBHOOK_FORWARD', 'targets', fallback='')
    targets = []
    for url in targets_config.split(','):
        url = url.strip()
        if not url:
            continue

        # 解析URL中的secret参数
        parsed_url = urlparse(url)
        query_params = dict(param.split('=') for param in parsed_url.query.split('&') if '=' in param)
        target_secret = query_params.get('secret')

        if target_secret:
            targets.append({
                'url': url,
                'secret': target_secret
            })

    return {
        'enabled': config.getboolean('WEBHOOK_FORWARD', 'enabled', fallback=False),
        'targets': targets,
        'timeout': config.getint('WEBHOOK_FORWARD', 'timeout', fallback=5)
    }


async def forward_webhook(
        targets: List[dict],
        body: bytes,
        headers: dict,
        timeout: int,
        current_secret: str
) -> list:
    async def send_to_target(session: aiohttp.ClientSession, target: dict) -> dict:
        # 只转发给匹配密钥的目标
        if target['secret'] != current_secret:
            return {
                'url': target['url'],
                'status': None,
                'success': True,
                'skipped': True,
                'reason': '密钥不匹配'
            }

        try:
            async with session.post(
                    target['url'],
                    data=body,
                    headers=headers,
                    timeout=timeout
            ) as response:
                success = 200 <= response.status < 300
                result = {
                    'url': target['url'],
                    'status': response.status,
                    'success': success,
                    'skipped': False
                }
                return result
        except Exception as e:
            return {
                'url': target['url'],
                'status': None,
                'success': False,
                'skipped': False,
                'error': str(e)
            }

    async with aiohttp.ClientSession() as session:
        tasks = [
            send_to_target(session, target)
            for target in targets
        ]
        results = await asyncio.gather(*tasks)
        return results


# 添加服务健康状态监控
service_health = {
    "last_successful_webhook": 0,
    "last_successful_ws_message": 0,
    "restart_count": 0,
    "error_count": 0,
    "high_load_detected": False
}


# 监控和自动修复
async def monitor_service_health():
    """监控服务健康状态并尝试自动修复"""
    while True:
        try:
            now = time.time()
            # 检查webhook处理
            if service_health["last_successful_webhook"] > 0:
                webhook_idle_time = now - service_health["last_successful_webhook"]
                if webhook_idle_time > 300:  # 5分钟没有成功处理webhook
                    logging.warning(f"检测到webhook处理异常，{webhook_idle_time:.1f}秒未成功处理")

                    # 检查连接数量
                    total_connections = sum(len(conns) for conns in active_connections.values())
                    if total_connections == 0 and service_health["error_count"] > 10:
                        # 清理资源并重置状态
                        logging.warning("执行自动恢复: 清理缓存和锁")
                        cache_locks.clear()
                        message_cache.clear()
                        message_id_cache.clear()
                        service_health["restart_count"] += 1
                        service_health["error_count"] = 0

            # 检查系统负载
            cpu_percent = psutil.cpu_percent(interval=0.5)
            if cpu_percent > 90:  # CPU使用率超过90%
                if not service_health["high_load_detected"]:
                    logging.warning(f"检测到高CPU负载: {cpu_percent}%，尝试释放资源")
                    service_health["high_load_detected"] = True

                # 清理过期消息缓存
                for secret in list(message_cache.keys()):
                    try:
                        lock = await get_lock_for_secret(secret)
                        if lock.locked():
                            continue  # 跳过正在使用的缓存

                        async with lock:
                            # 清理公共缓存
                            now_dt = datetime.now()
                            if "public" in message_cache[secret]:
                                message_cache[secret]["public"] = deque(
                                    [(exp, data) for exp, data in message_cache[secret]["public"] if exp > now_dt],
                                    maxlen=message_cache[secret]["public"].maxlen
                                )

                            # 清理token缓存
                            for token in list(message_cache[secret].get("tokens", {}).keys()):
                                token_queue = message_cache[secret]["tokens"][token]
                                message_cache[secret]["tokens"][token] = deque(
                                    [(exp, data) for exp, data in token_queue if exp > now_dt],
                                    maxlen=token_queue.maxlen
                                )
                    except Exception as e:
                        logging.error(f"清理缓存异常: {e}")
            else:
                service_health["high_load_detected"] = False

            # 监控内存使用
            memory_percent = psutil.Process().memory_percent()
            if memory_percent > 85:  # 内存使用超过85%
                logging.warning(f"检测到高内存使用: {memory_percent:.1f}%，执行垃圾回收")
                import gc
                gc.collect()

            await asyncio.sleep(30)  # 每30秒检查一次
        except Exception as e:
            logging.error(f"健康监控异常: {e}")
            await asyncio.sleep(60)  # 出错后等待时间延长


@app.post("/webhook")
async def handle_webhook(
        request: Request,
        payload: Payload,
        user_agent: str = Header(None),
        x_bot_appid: str = Header(None)
):
    start_time = time.time()
    secret = request.query_params.get('secret')
    body_bytes = await request.body()
    logging.debug(f"收到原始消息: {body_bytes}")

    # 获取客户端IP地址
    client_host = request.client.host if request.client else "unknown"
    client_port = request.client.port if request.client else 0
    client_ip = f"{client_host}:{client_port}"

    message_id = None
    # 消息ID检查和去重处理
    try:
        message_data = json_module.loads(body_bytes)
        message_id = message_data.get('id')

        # 保存原始内容（初始状态）
        save_raw_content(body_bytes, secret, message_id, "接收", client_ip)

        # 如果存在消息ID，检查是否已经处理过
        if message_id:
            # 获取去重有效期配置
            deduplication_ttl = load_deduplication_config()

            # 检查当前消息是否已存在于缓存中
            if cache_manager.has_message_id(message_id):
                logging.info(f"检测到重复消息ID，跳过所有处理和转发: {message_id} | IP: {client_ip}")
                # 更新消息状态
                save_raw_content(body_bytes, secret, message_id, "重复消息-不转发", client_ip)
                return {"status": "success"}  # 直接返回，不进行后续任何处理

            # 将当前消息ID添加到缓存中，有效期从配置中读取
            cache_manager.add_message_id(message_id, deduplication_ttl)
            logging.debug(f"添加消息ID到缓存，有效期{deduplication_ttl}秒: {message_id}")
    except Exception as e:
        logging.error(f"消息去重处理异常: {str(e)}")
        service_health["error_count"] += 1
        # 更新消息状态
        save_raw_content(body_bytes, secret, message_id, "解析异常", client_ip)

    # 处理回调验证
    if "event_ts" in payload.d and "plain_token" in payload.d:
        try:
            event_ts = payload.d["event_ts"]
            plain_token = payload.d["plain_token"]
            # 更新消息状态
            save_raw_content(body_bytes, secret, message_id, "回调验证", client_ip)
            result = generate_signature(secret, event_ts, plain_token)
            service_health["last_successful_webhook"] = time.time()
            return result
        except Exception as e:
            logging.error(f"签名错误: {e}")
            service_health["error_count"] += 1
            # 更新消息状态
            save_raw_content(body_bytes, secret, message_id, "签名错误", client_ip)
            return {"status": "error"}

    # 转发状态
    forward_status = "转发状态：未知"

    # 处理webhook转发
    webhook_config = load_webhook_config()
    if webhook_config['enabled'] and webhook_config['targets']:
        # 获取原始请求头
        forward_headers = {
            k: v for k, v in request.headers.items()
            if k.lower() not in ['host', 'content-length']
        }

        try:
            # 异步转发
            forward_results = await forward_webhook(
                webhook_config['targets'],
                body_bytes,
                forward_headers,
                webhook_config['timeout'],
                secret
            )

            # 记录转发结果
            success_count = 0
            fail_count = 0

            for result in forward_results:
                sanitized_url = PrivacyUtils.sanitize_url(result['url'])
                if result.get('skipped', False):
                    logging.debug(f"Webhook转发跳过 | URL: {sanitized_url} | 原因: {result.get('reason', '未知')}")
                elif result['success']:
                    success_count += 1
                    logging.info(f"Webhook转发成功 | URL: {sanitized_url} | 状态码: {result['status']}")
                else:
                    fail_count += 1
                    logging.error(f"Webhook转发失败 | URL: {sanitized_url} | 错误: {result.get('error', '未知错误')}")

            forward_status = f"Webhook转发：成功{success_count}，失败{fail_count}"
        except Exception as e:
            logging.error(f"Webhook转发处理异常: {e}")
            service_health["error_count"] += 1
            forward_status = f"Webhook转发异常: {str(e)}"

    # 更新webhook统计
    if secret:
        await update_webhook_stats(secret, str(request.url), len(body_bytes))

    # 获取不缓存的密钥列表
    no_cache_secrets = load_no_cache_secrets()

    # 检查当前密钥是否在不缓存列表中
    skip_cache = secret in no_cache_secrets
    if skip_cache:
        forward_status += " | 不缓存密钥"

    # 检查是否有在线连接
    has_online = secret in active_connections and len(active_connections[secret]) > 0

    # 消息处理逻辑
    try:
        # 没有在线连接且不跳过缓存时，添加到缓存
        if not has_online and not skip_cache:
            await cache_manager.add_message(secret, body_bytes)
            forward_status += " | WS：无在线连接-已缓存"
        elif not has_online:
            forward_status += " | WS：无在线连接-不缓存"
        else:
            forward_status += " | WS：有在线连接"
    except Exception as e:
        logging.error(f"消息缓存处理异常: {e}")
        service_health["error_count"] += 1
        forward_status += f" | 缓存异常: {str(e)}"

    # 实时转发
    if has_online:
        try:
            await send_to_all(secret, body_bytes)
        except Exception as e:
            logging.error(f"实时转发异常: {e}")
            service_health["error_count"] += 1
            forward_status += f" | 转发异常: {str(e)}"

    # 最终更新消息状态
    save_raw_content(body_bytes, secret, message_id, forward_status, client_ip)

    # 更新健康状态
    process_time = time.time() - start_time
    if process_time > 2:
        logging.warning(f"Webhook处理耗时较长: {process_time:.2f}秒 | 密钥: {PrivacyUtils.sanitize_secret(secret)}")

    service_health["last_successful_webhook"] = time.time()

    return {"status": "success"}


@app.websocket("/ws/{secret}")
async def websocket_endpoint(
        websocket: WebSocket,
        secret: str,
        token: str = None,
        group: str = None,
        member: str = None,
        content: str = None
):
    try:
        await websocket.accept()

        # 更新连接统计
        await update_connection_stats(secret, True)

        # 发送初始心跳
        await websocket.send_bytes(json_module.dumps({
            "op": 10,
            "d": {"heartbeat_interval": 30000}
        }))

        is_sandbox = any([group, member, content])
        environment = "沙盒环境" if is_sandbox else "正式环境"

        lock = await get_lock_for_secret(secret)
        async with lock:
            if secret not in active_connections:
                active_connections[secret] = {}

            active_connections[secret][websocket] = {
                "token": token,
                "failure_count": 0,
                "group": group,
                "member": member,
                "content": content,
                "is_sandbox": is_sandbox,
                "last_activity": time.time()
            }

            current_count = len(active_connections[secret])

            # 确保token缓存队列存在
            if token:
                message_cache.setdefault(secret, {"public": deque(maxlen=1000), "tokens": {}})
                message_cache[secret]["tokens"].setdefault(token, deque(maxlen=1000))
                logging.debug(
                    f"初始化Token队列 | 密钥：{PrivacyUtils.sanitize_secret(secret)} | Token：{PrivacyUtils.sanitize_secret(token)}")

        logging.info(
            f"WS连接成功 | 密钥：{PrivacyUtils.sanitize_secret(secret)} | Token：{PrivacyUtils.sanitize_secret(token) if token else '无'} | "
            f"环境：{environment} | 连接数：{current_count}"
        )

        # 触发补发任务
        if token:
            asyncio.create_task(resend_token_cache(secret, token, websocket))
        asyncio.create_task(resend_public_cache(secret, websocket))

        # 心跳任务
        heartbeat_task = asyncio.create_task(send_heartbeat(websocket, secret))

        try:
            while True:
                try:
                    # 设置超时接收，避免永久阻塞
                    data = await asyncio.wait_for(websocket.receive_text(), timeout=60)

                    # 更新活动时间
                    async with lock:
                        if secret in active_connections and websocket in active_connections[secret]:
                            active_connections[secret][websocket]["last_activity"] = time.time()

                    logging.debug(f"收到WS消息: {data}")
                    await handle_ws_message(data, websocket)
                    service_health["last_successful_ws_message"] = time.time()
                except asyncio.TimeoutError:
                    # 检查连接是否活跃
                    async with lock:
                        if secret in active_connections and websocket in active_connections[secret]:
                            last_activity = active_connections[secret][websocket]["last_activity"]
                            if time.time() - last_activity > 120:  # 2分钟无活动
                                logging.warning(f"WS连接超时无活动 | 密钥：{PrivacyUtils.sanitize_secret(secret)}")
                                break
                        else:
                            break
                    continue  # 继续等待消息
        except WebSocketDisconnect:
            logging.info(f"WS正常断开连接 | 密钥：{PrivacyUtils.sanitize_secret(secret)}")
        except Exception as e:
            logging.error(f"WS消息接收异常: {str(e)}")
            service_health["error_count"] += 1
        finally:
            # 取消心跳任务
            heartbeat_task.cancel()

            # 清理连接
            async with lock:
                if secret in active_connections and websocket in active_connections[secret]:
                    conn_info = active_connections[secret][websocket]
                    token = conn_info["token"]
                    del active_connections[secret][websocket]
                    remaining = len(active_connections[secret])

                    # 更新连接统计
                    await update_connection_stats(secret, False)

                    # 确保离线token的缓存队列存在
                    if token:
                        message_cache.setdefault(secret, {"public": deque(maxlen=1000), "tokens": {}})
                        message_cache[secret]["tokens"].setdefault(token, deque(maxlen=1000))
                        logging.debug(
                            f"准备离线缓存 | 密钥：{PrivacyUtils.sanitize_secret(secret)} | Token：{PrivacyUtils.sanitize_secret(token)}")

                    logging.info(
                        f"WS断开连接处理完成 | 密钥：{PrivacyUtils.sanitize_secret(secret)} | Token：{PrivacyUtils.sanitize_secret(token) if token else '无'} | "
                        f"剩余连接：{remaining}"
                    )

                    if not active_connections[secret]:
                        del active_connections[secret]
                        connection_stats["active_keys"].discard(secret)
    except Exception as e:
        logging.error(f"WS连接全局异常: {str(e)}")
        service_health["error_count"] += 1
        try:
            await websocket.close()
        except:
            pass


async def send_heartbeat(websocket: WebSocket, secret: str):
    """定期发送心跳包保持连接"""
    try:
        while True:
            try:
                await asyncio.sleep(25)  # 每25秒发送一次心跳
                await websocket.send_bytes(json_module.dumps({"op": 11}))
                logging.debug(f"发送心跳包 | 密钥：{PrivacyUtils.sanitize_secret(secret)}")
            except Exception as e:
                logging.error(f"心跳发送失败: {e}")
                # 如果连续3次心跳失败，退出心跳任务
                break
    except asyncio.CancelledError:
        # 任务被取消，正常退出
        pass
    except Exception as e:
        logging.error(f"心跳任务异常: {e}")


async def handle_ws_message(message: str, websocket: WebSocket):
    try:
        data = json_module.loads(message)
        logging.debug(f"解析WS消息: {data}")
        if data["op"] == 2:  # 鉴权
            await websocket.send_bytes(json_module.dumps({
                "op": 0,
                "s": 1,
                "t": "READY",
                "d": {
                    "version": 1,
                    "session_id": "open-connection",
                    "user": {"bot": True},
                    "shard": [0, 0]
                }
            }))
        elif data["op"] == 1:  # 心跳
            await websocket.send_bytes(json_module.dumps({"op": 11}))
    except Exception as e:
        logging.error(f"WS消息处理错误: {e}")
        service_health["error_count"] += 1


async def send_to_all(secret: str, data: bytes):
    """向所有相关WebSocket连接发送消息"""
    try:
        lock = await get_lock_for_secret(secret)
        async with lock:
            connections = active_connections.get(secret, {})
            websockets = list(connections.keys())

        success_count = 0
        sandbox_success = 0
        formal_success = 0
        fail_count = 0

        # 并发发送，提高效率
        tasks = []
        for ws in websockets:
            task = asyncio.create_task(send_to_one(ws, data, connections[ws], secret))
            tasks.append(task)

        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if isinstance(result, Exception):
                    fail_count += 1
                    logging.error(f"消息发送任务异常: {result}")
                    continue

                if result:
                    success_type, is_sandbox = result
                    if success_type:
                        success_count += 1
                        if is_sandbox:
                            sandbox_success += 1
                        else:
                            formal_success += 1
                else:
                    fail_count += 1

        # 记录转发结果
        if success_count > 0:
            log_parts = [
                f"消息转发成功 | 密钥：{PrivacyUtils.sanitize_secret(secret)}",
                f"总数：{success_count}/{len(websockets)}",
                f"沙盒：{sandbox_success}" if sandbox_success > 0 else "",
                f"正式：{formal_success}" if formal_success > 0 else ""
            ]
            logging.info(" | ".join([p for p in log_parts if p]))

        if fail_count > 0:
            logging.warning(
                f"消息转发失败 | 密钥：{PrivacyUtils.sanitize_secret(secret)} | "
                f"失败数：{fail_count}/{len(websockets)}"
            )

        return success_count > 0
    except Exception as e:
        logging.error(f"发送消息全局异常: {e}")
        service_health["error_count"] += 1
        return False


async def send_to_one(ws: WebSocket, data: bytes, conn_info: dict, secret: str):
    """向单个WebSocket连接发送消息"""
    try:
        is_sandbox = conn_info["is_sandbox"]
        group = conn_info["group"]
        member = conn_info["member"]
        content_filter = conn_info["content"]

        should_send = True
        if is_sandbox:
            try:
                msg_json = json_module.loads(data)
                d = msg_json.get("d", {})
                if group and d.get("group_openid") != group:
                    should_send = False
                if should_send and member and d.get("author", {}).get("member_openid") != member:
                    should_send = False
                if should_send and content_filter and content_filter not in d.get("content", ""):
                    should_send = False
            except JSONDecodeError:
                logging.error(f"消息解析失败: {data}")

        if should_send:
            try:
                await ws.send_bytes(data)
                logging.debug(f"转发消息内容: {data.decode()}")

                # 更新成功状态
                lock = await get_lock_for_secret(secret)
                async with lock:
                    if secret in active_connections and ws in active_connections[secret]:
                        active_connections[secret][ws]["failure_count"] = 0
                        active_connections[secret][ws]["last_activity"] = time.time()

                return (True, is_sandbox)
            except Exception as e:
                lock = await get_lock_for_secret(secret)
                async with lock:
                    if secret in active_connections and ws in active_connections[secret]:
                        active_connections[secret][ws]["failure_count"] += 1
                        if active_connections[secret][ws]["failure_count"] >= 5:
                            try:
                                await ws.close()
                            except:
                                pass

                            # 从连接列表中移除
                            if secret in active_connections and ws in active_connections[secret]:
                                del active_connections[secret][ws]
                                if not active_connections[secret]:
                                    del active_connections[secret]
                                logging.warning(f"连接重试过多关闭 | 密钥：{PrivacyUtils.sanitize_secret(secret)}")
                return False
        return None  # 不需要发送
    except Exception as e:
        logging.error(f"单个消息发送异常: {e}")
        return False


async def resend_cache(secret: str, websocket: WebSocket, cache_queue: list, cache_type: str, token: str = None):
    try:
        success = 0
        fail = 0
        valid_count = 0
        now = datetime.now()
        total = len(cache_queue)

        # 生成日志描述
        if cache_type == 'token':
            cache_desc = f"Token：{token[:3]}****{token[-3:] if token and len(token) > 6 else ''}" if token else "Token：未知"
            log_prefix = "Token补发"
        else:
            cache_desc = "公共缓存"
            log_prefix = "公共补发"

        logging.info(
            f"开始补发{cache_desc} | 密钥：{secret[:3]}****{secret[-3:] if secret and len(secret) > 6 else ''} | 总量：{total}")

        # 分批次发送（每秒10条）
        batch_size = 10
        for i in range(0, len(cache_queue), batch_size):
            batch = cache_queue[i:i + batch_size]
            batch_success = 0
            batch_fail = 0

            for expiry, msg in batch:
                if expiry < now:
                    continue
                valid_count += 1
                try:
                    await websocket.send_bytes(msg)
                    batch_success += 1
                    logging.debug(f"补发{cache_desc}消息: {msg.decode()}")
                except Exception as e:
                    batch_fail += 1

            success += batch_success
            fail += batch_fail

            # 记录批次日志
            logging.info(
                f"{log_prefix}进度 | 密钥：{secret[:3]}****{secret[-3:] if secret and len(secret) > 6 else ''} | "
                f"批次：{i // batch_size + 1} | 本批：{batch_success}成功/{batch_fail}失败"
            )

            # 严格1秒间隔
            if i + batch_size < len(cache_queue):
                await asyncio.sleep(1)

        logging.info(
            f"{cache_desc}补发完成 | 密钥：{secret[:3]}****{secret[-3:] if secret and len(secret) > 6 else ''} | "
            f"总消息：{total} | 有效消息：{valid_count} | "
            f"成功：{success} | 失败：{fail}"
        )
    except WebSocketDisconnect:
        logging.warning(
            f"补发中断：WebSocket连接已关闭 | 密钥：{secret[:3]}****{secret[-3:] if secret and len(secret) > 6 else ''} | {cache_desc}")
    except Exception as e:
        logging.error(f"{cache_desc}补发异常: {str(e)}")


async def resend_token_cache(secret: str, token: str, websocket: WebSocket):
    """补发token缓存消息"""
    try:
        await asyncio.sleep(3)
        messages = await cache_manager.get_messages_for_token(secret, token)
        await resend_cache(
            secret=secret,
            websocket=websocket,
            cache_queue=messages,
            cache_type='token',
            token=token
        )
    except Exception as e:
        logging.error(f"Token缓存补发异常: {str(e)}")


async def resend_public_cache(secret: str, websocket: WebSocket):
    """补发公共缓存消息"""
    try:
        await asyncio.sleep(3)
        messages = await cache_manager.get_public_messages(secret)
        await resend_cache(
            secret=secret,
            websocket=websocket,
            cache_queue=messages,
            cache_type='public'
        )
    except Exception as e:
        logging.error(f"公共缓存补发异常: {str(e)}")


async def watch_config():
    """配置文件监视任务"""
    last_mtime = 0
    last_valid_level = logger.level
    while True:
        try:
            current_mtime = os.path.getmtime("config.ini")
            if current_mtime != last_mtime:
                last_mtime = current_mtime
                config = configparser.ConfigParser()
                config.read('config.ini', encoding='UTF-8')
                new_level = config.get('DEFAULT', 'log', fallback='INFO').upper()
                if new_level == "TESTING":
                    new_level = "DEBUG"

                # 验证日志级别有效性
                temp_logger = logging.getLogger('temp_validation')
                try:
                    temp_logger.setLevel(new_level)
                    valid = True
                except ValueError:
                    valid = False

                if valid:
                    logger.setLevel(new_level)
                    for handler in logger.handlers:
                        handler.setLevel(new_level)
                    last_valid_level = new_level
                    logging.info(f"检测到配置文件更新，日志级别已更改为：{new_level}")

                    # 输出去重配置更新日志
                    deduplication_ttl = config.getint('DEFAULT', 'deduplication_ttl', fallback=20)
                    logging.info(f"消息去重有效期配置为：{deduplication_ttl}秒")

                    # 输出原始内容记录配置更新日志
                    raw_content_enabled = config.getboolean('DEFAULT', 'save_raw_content', fallback=False)
                    raw_content_path = config.get('DEFAULT', 'raw_content_path', fallback='logs')
                    logging.info(f"原始内容记录：{'启用' if raw_content_enabled else '禁用'}, 路径: {raw_content_path}")

                    # 输出不缓存密钥配置更新日志
                    no_cache_secrets = load_no_cache_secrets()
                    if no_cache_secrets:
                        sanitized_secrets = [PrivacyUtils.sanitize_secret(s) for s in no_cache_secrets]
                        logging.info(f"不缓存密钥列表：{', '.join(sanitized_secrets)}")
                    else:
                        logging.info("不缓存密钥列表：无")
                else:
                    logger.setLevel(last_valid_level)
                    for handler in logger.handlers:
                        handler.setLevel(last_valid_level)
                    logging.error(
                        f"配置的日志级别无效: {new_level}，已恢复为之前的级别: {logging.getLevelName(last_valid_level)}")

        except FileNotFoundError:
            pass
        except Exception as e:
            logging.error(f"配置文件监视错误: {str(e)}")
        await asyncio.sleep(20)


# 保存原始内容到日志文件
def save_raw_content(content_bytes, secret, message_id=None, status=None, client_ip=None):
    # 将保存操作提交到线程池
    thread_pool.submit(_save_raw_content_thread, content_bytes, secret, message_id, status, client_ip)
    return True


# 线程中执行的保存函数
def _save_raw_content_thread(content_bytes, secret, message_id=None, status=None, client_ip=None):
    try:
        config = load_raw_content_config()
        if not config['enabled']:
            return False

        # 创建日志文件夹
        log_dir = Path(config['path'])
        log_dir.mkdir(exist_ok=True, parents=True)

        # 生成当前日期的文件名
        current_date = datetime.now().strftime('%Y%m%d')
        filename = f"webhook_raw_{current_date}.log"
        file_path = log_dir / filename

        # 获取当前时间戳
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # 添加消息分隔符和元信息
        secret_prefix = PrivacyUtils.sanitize_secret(secret) if secret else "unknown"
        message_info = f"[{timestamp}] Secret: {secret_prefix}"

        # 添加IP地址信息
        if client_ip:
            message_info += f" | IP: {client_ip}"

        # 添加消息ID信息
        if message_id:
            message_info += f" | Message ID: {message_id}"

        # 添加消息状态信息
        if status:
            message_info += f" | Status: {status}"

        separator = f"\n\n---------\n{message_info}\n"

        # 以追加模式打开文件并写入内容
        try:
            content_str = content_bytes.decode('utf-8')
        except UnicodeDecodeError:
            content_str = f"[Binary content, length: {len(content_bytes)} bytes]"

        with open(file_path, 'a', encoding='utf-8') as f:
            f.write(separator)
            f.write(content_str)

        logging.info(f"原始内容已追加到文件: {filename}")
        return True
    except Exception as e:
        logging.error(f"保存原始内容失败: {str(e)}")
        return False


if __name__ == "__main__":
    import asyncio
    from models import ensure_tables

    # 确保数据库表已创建
    asyncio.run(ensure_tables())

    # 读取SSL配置
    def load_ssl_config():
        config = configparser.ConfigParser()
        config.read('config.ini', encoding='UTF-8')
        
        # 尝试从配置读取
        if 'SSL' in config:
            return {
                "ssl_keyfile": config.get('SSL', 'ssl_keyfile', fallback=""),
                "ssl_certfile": config.get('SSL', 'ssl_certfile', fallback=""),
            }
        return {
            "ssl_keyfile": "",
            "ssl_certfile": ""
        }

    # 加载SSL配置
    ssl_kwargs = load_ssl_config()

    # 设置端口
    port = 8443 if ssl_kwargs["ssl_keyfile"] and ssl_kwargs["ssl_certfile"] else 8000

    # 创建UVICORN配置
    config = uvicorn.Config(
        app,
        host="0.0.0.0",
        port=port,
        log_config=None,
        access_log=False
    )

    # 只有当证书都不为空时才添加SSL配置
    if ssl_kwargs["ssl_keyfile"] and ssl_kwargs["ssl_certfile"]:
        config.ssl_keyfile = ssl_kwargs["ssl_keyfile"]
        config.ssl_certfile = ssl_kwargs["ssl_certfile"]
        logging.info(f"启用SSL，监听端口: {port}")
    else:
        logging.info(f"未启用SSL，监听端口: {port}")

    # 启动服务
    server = uvicorn.Server(config)
    asyncio.run(server.serve())
