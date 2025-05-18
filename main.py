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
from models import get_session, WebhookStats, ConnectionStats
from sqlalchemy import update, func

try:
    import orjson
    json_module = orjson
    JSONDecodeError = orjson.JSONDecodeError
except ImportError:
    import json
    json_module = json
    JSONDecodeError = json.JSONDecodeError

app = FastAPI()

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
message_cache = {}       # {secret: {"public": deque(), "tokens": {token: deque()}}}
cache_lock = asyncio.Lock()
webhook_retry_cache = {}  # {url: {"body": bytes, "headers": dict, "secret": str, "retry_time": datetime}}
message_id_cache = {}     # {message_id: expiry_timestamp}

# 日志配置
def load_log_config():
    config = configparser.ConfigParser()
    config.read('config.ini')
    log_level = config.get('DEFAULT', 'log', fallback='INFO').upper()
    if log_level == "TESTING":
        log_level = "DEBUG"
    return log_level

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

def update_webhook_stats(secret: str, url: str, bytes_count: int):
    """更新webhook统计数据"""
    session = get_session()
    try:
        stats = session.query(WebhookStats).filter_by(secret=secret, url=url).first()
        if stats:
            stats.count += 1
            stats.total_bytes += bytes_count
            stats.last_updated = datetime.now()
        else:
            stats = WebhookStats(
                secret=secret,
                url=url,
                count=1,
                total_bytes=bytes_count
            )
            session.add(stats)
        session.commit()
    except Exception as e:
        logging.error(f"更新webhook统计失败: {e}")
        session.rollback()
    finally:
        session.close()

def update_connection_stats(secret: str, is_active: bool = True):
    """更新连接统计数据"""
    session = get_session()
    try:
        stats = session.query(ConnectionStats).filter_by(secret=secret).first()
        if stats:
            if is_active:
                stats.history_connections += 1
            stats.is_active = 1 if is_active else 0
            stats.last_updated = datetime.now()
        else:
            stats = ConnectionStats(
                secret=secret,
                history_connections=1 if is_active else 0,
                is_active=1 if is_active else 0
            )
            session.add(stats)
        session.commit()
    except Exception as e:
        logging.error(f"更新连接统计失败: {e}")
        session.rollback()
    finally:
        session.close()

@app.get("/logs")
async def logs_page():
    return FileResponse("logs.html")

@app.get("/api/stats")
async def get_stats():
    session = get_session()
    try:
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
        webhook_stats = session.query(WebhookStats).all()
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
        history_count = session.query(func.sum(ConnectionStats.history_connections)).scalar() or 0
        
        # 获取活跃密钥数
        active_keys = session.query(ConnectionStats).filter_by(is_active=1).count()
        
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
    finally:
        session.close()

def load_webhook_config() -> dict:
    config = configparser.ConfigParser()
    config.read('config.ini')
    
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
                
                # 如果请求失败（非2xx状态码），将请求缓存起来等待重试
                if not success:
                    retry_time = datetime.now() + timedelta(seconds=10)
                    webhook_retry_cache[target['url']] = {
                        'body': body,
                        'headers': headers,
                        'secret': current_secret,
                        'retry_time': retry_time,
                        'retried': False  # 标记为未重试
                    }
                    logging.info(f"Webhook请求失败（状态码: {response.status}），已加入重试队列：{PrivacyUtils.sanitize_url(target['url'])}")
                
                return result
        except Exception as e:
            # 发生异常时也将请求加入重试队列
            retry_time = datetime.now() + timedelta(seconds=10)
            webhook_retry_cache[target['url']] = {
                'body': body,
                'headers': headers, 
                'secret': current_secret,
                'retry_time': retry_time,
                'retried': False  # 标记为未重试
            }
            logging.error(f"Webhook请求异常，已加入重试队列：{PrivacyUtils.sanitize_url(target['url'])} | 错误: {str(e)}")
            
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

@app.post("/webhook")
async def handle_webhook(
        request: Request,
        payload: Payload,
        user_agent: str = Header(None),
        x_bot_appid: str = Header(None)
):
    secret = request.query_params.get('secret')
    body_bytes = await request.body()
    logging.debug(f"收到原始消息: {body_bytes}")

    # 消息ID检查和去重处理
    try:
        message_data = json_module.loads(body_bytes)
        message_id = message_data.get('id')
        
        # 如果存在消息ID，检查是否已经处理过
        if message_id:
            now = datetime.now()
            
            # 清理过期的消息ID缓存
            expired_ids = [id for id, expiry in message_id_cache.items() if expiry < now]
            for id in expired_ids:
                message_id_cache.pop(id, None)
            
            # 检查当前消息是否已存在于缓存中
            if message_id in message_id_cache:
                logging.info(f"检测到重复消息ID，忽略处理: {message_id}")
                return {"status": "ignored", "reason": "duplicate message"}
            
            # 将当前消息ID添加到缓存中，有效期20秒
            message_id_cache[message_id] = now + timedelta(seconds=20)
    except Exception as e:
        logging.error(f"消息去重处理异常: {str(e)}")

    # 处理webhook转发
    webhook_config = load_webhook_config()
    if webhook_config['enabled'] and webhook_config['targets']:
        # 获取原始请求头
        forward_headers = {
            k: v for k, v in request.headers.items()
            if k.lower() not in ['host', 'content-length']
        }
        
        # 异步转发
        forward_results = await forward_webhook(
            webhook_config['targets'],
            body_bytes,
            forward_headers,
            webhook_config['timeout'],
            secret
        )
        
        # 记录转发结果
        for result in forward_results:
            sanitized_url = PrivacyUtils.sanitize_url(result['url'])
            if result.get('skipped', False):
                logging.debug(f"Webhook转发跳过 | URL: {sanitized_url} | 原因: {result.get('reason', '未知')}")
            elif result['success']:
                logging.info(f"Webhook转发成功 | URL: {sanitized_url} | 状态码: {result['status']}")
            else:
                logging.error(f"Webhook转发失败 | URL: {sanitized_url} | 错误: {result.get('error', '未知错误')}")

    # 更新webhook统计
    if secret:
        update_webhook_stats(secret, str(request.url), len(body_bytes))

    # 处理回调验证
    if "event_ts" in payload.d and "plain_token" in payload.d:
        try:
            event_ts = payload.d["event_ts"]
            plain_token = payload.d["plain_token"]
            result = generate_signature(secret, event_ts, plain_token)
            return result
        except Exception as e:
            logging.error(f"签名错误: {e}")
            return {"status": "error"}

    # 消息处理逻辑
    async with cache_lock:
        now = datetime.now()
        expiry = now + timedelta(minutes=5)
        has_online = secret in active_connections and len(active_connections[secret]) > 0

        # 初始化缓存结构
        if secret not in message_cache:
            message_cache[secret] = {"public": deque(maxlen=1000), "tokens": {}}
        cache = message_cache[secret]

        # 清理公共缓存
        expired_public = 0
        while cache["public"] and cache["public"][0][0] < now:
            cache["public"].popleft()
            expired_public += 1
        if expired_public > 0:
            logging.debug(f"清理公共缓存 | 密钥：{PrivacyUtils.sanitize_secret(secret)} | 数量：{expired_public}")

        # 没有在线连接时缓存到公共
        if not has_online:
            cache["public"].append((expiry, body_bytes))
            logging.info(f"消息存入公共缓存 | 密钥：{PrivacyUtils.sanitize_secret(secret)} | 数量：{len(cache['public'])}")

        # 处理token缓存
        offline_tokens = []
        for token in cache["tokens"].keys():
            token_has_online = any(
                conn.get("token") == token 
                for conn in active_connections.get(secret, {}).values()
            )
            if not token_has_online:
                offline_tokens.append(token)

        for token in offline_tokens:
            deque_token = cache["tokens"][token]
            
            # 清理过期
            expired = 0
            while deque_token and deque_token[0][0] < now:
                deque_token.popleft()
                expired += 1
            if expired > 0:
                logging.debug(f"清理Token缓存 | 密钥：{PrivacyUtils.sanitize_secret(secret)} | Token：{PrivacyUtils.sanitize_secret(token)} | 数量：{expired}")
            
            deque_token.append((expiry, body_bytes))
            logging.info(f"消息存入Token缓存 | 密钥：{PrivacyUtils.sanitize_secret(secret)} | Token：{PrivacyUtils.sanitize_secret(token)} | 数量：{len(deque_token)}")

    # 实时转发
    await send_to_all(secret, body_bytes)
    return {"status": "delivered" if has_online else "cached"}

@app.websocket("/ws/{secret}")
async def websocket_endpoint(
    websocket: WebSocket,
    secret: str,
    token: str = None,
    group: str = None,
    member: str = None,
    content: str = None
):
    await websocket.accept()
    
    # 更新连接统计
    update_connection_stats(secret, True)

    # 发送初始心跳
    await websocket.send_bytes(json_module.dumps({
        "op": 10,
        "d": {"heartbeat_interval": 30000}
    }))

    is_sandbox = any([group, member, content])
    environment = "沙盒环境" if is_sandbox else "正式环境"

    async with cache_lock:
        if secret not in active_connections:
            active_connections[secret] = {}

        active_connections[secret][websocket] = {
            "token": token,
            "failure_count": 0,
            "group": group,
            "member": member,
            "content": content,
            "is_sandbox": is_sandbox
        }

        current_count = len(active_connections[secret])
        
        # 确保token缓存队列存在
        if token:
            message_cache.setdefault(secret, {"public": deque(maxlen=1000), "tokens": {}})
            message_cache[secret]["tokens"].setdefault(token, deque(maxlen=1000))
            logging.debug(f"初始化Token队列 | 密钥：{PrivacyUtils.sanitize_secret(secret)} | Token：{PrivacyUtils.sanitize_secret(token)}")

    logging.info(
        f"WS连接成功 | 密钥：{PrivacyUtils.sanitize_secret(secret)} | Token：{PrivacyUtils.sanitize_secret(token) if token else '无'} | "
        f"环境：{environment} | 连接数：{current_count}"
    )

    # 触发补发任务
    if token:
        asyncio.create_task(resend_token_cache(secret, token, websocket))
    asyncio.create_task(resend_public_cache(secret, websocket))

    try:
        while True:
            data = await websocket.receive_text()
            logging.debug(f"收到WS消息: {data}")
            await handle_ws_message(data, websocket)
    except WebSocketDisconnect:
        async with cache_lock:
            if secret in active_connections and websocket in active_connections[secret]:
                conn_info = active_connections[secret][websocket]
                token = conn_info["token"]
                del active_connections[secret][websocket]
                remaining = len(active_connections[secret])

                # 更新连接统计
                update_connection_stats(secret, False)

                # 确保离线token的缓存队列存在
                if token:
                    message_cache.setdefault(secret, {"public": deque(maxlen=1000), "tokens": {}})
                    message_cache[secret]["tokens"].setdefault(token, deque(maxlen=1000))
                    logging.debug(f"准备离线缓存 | 密钥：{PrivacyUtils.sanitize_secret(secret[:3])} | Token：{PrivacyUtils.sanitize_secret(token[:3])}")

                logging.info(
                    f"WS断开连接 | 密钥：{PrivacyUtils.sanitize_secret(secret[:3])} | Token：{PrivacyUtils.sanitize_secret(token) if token else '无'} | "
                    f"剩余连接：{remaining}"
                )

                if not active_connections[secret]:
                    del active_connections[secret]
                    connection_stats["active_keys"].discard(secret)
    except Exception as e:
        logging.error(f"WS连接异常: {str(e)}")
        async with cache_lock:
            if secret in active_connections and websocket in active_connections[secret]:
                del active_connections[secret][websocket]
                if not active_connections[secret]:
                    del active_connections[secret]
                    connection_stats["active_keys"].discard(secret)

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

async def send_to_all(secret: str, data: bytes):
    async with cache_lock:
        connections = active_connections.get(secret, {})
        websockets = list(connections.keys())
    
    success_count = 0
    sandbox_success = 0
    formal_success = 0
    fail_count = 0
    
    for ws in websockets:
        conn_info = connections[ws]
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
                success_count += 1
                if is_sandbox:
                    sandbox_success += 1
                else:
                    formal_success += 1
                logging.debug(f"转发消息内容: {data.decode()}")
                async with cache_lock:
                    connections[ws]["failure_count"] = 0
            except Exception as e:
                fail_count += 1
                async with cache_lock:
                    connections[ws]["failure_count"] += 1
                    if connections[ws]["failure_count"] >= 5:
                        try:
                            await ws.close()
                        except:
                            pass
                        del connections[ws]
                        logging.warning(f"连接重试过多关闭 | 密钥：{PrivacyUtils.sanitize_secret(secret)}")

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

        logging.info(f"开始补发{cache_desc} | 密钥：{secret[:3]}****{secret[-3:] if secret and len(secret) > 6 else ''} | 总量：{total}")

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
                f"批次：{i//batch_size + 1} | 本批：{batch_success}成功/{batch_fail}失败"
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
        logging.warning(f"补发中断：WebSocket连接已关闭 | 密钥：{secret[:3]}****{secret[-3:] if secret and len(secret) > 6 else ''} | {cache_desc}")
    except Exception as e:
        logging.error(f"{cache_desc}补发异常: {str(e)}")

async def resend_token_cache(secret: str, token: str, websocket: WebSocket):
    try:
        await asyncio.sleep(3)
        async with cache_lock:
            if secret not in message_cache or token not in message_cache[secret]["tokens"]:
                return
            deque_cache = message_cache[secret]["tokens"][token]
            messages = list(deque_cache)
            deque_cache.clear()
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
    try:
        await asyncio.sleep(3)
        async with cache_lock:
            if secret not in message_cache:
                return
            public_deque = message_cache[secret]["public"]
            messages = list(public_deque)
            public_deque.clear()
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
                config.read('config.ini')
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
                else:
                    logger.setLevel(last_valid_level)
                    for handler in logger.handlers:
                        handler.setLevel(last_valid_level)
                    logging.error(f"配置的日志级别无效: {new_level}，已恢复为之前的级别: {logging.getLevelName(last_valid_level)}")

        except FileNotFoundError:
            pass
        except Exception as e:
            logging.error(f"配置文件监视错误: {str(e)}")
        await asyncio.sleep(20)

async def process_webhook_retry_queue():
    """处理webhook重试队列的后台任务"""
    while True:
        try:
            now = datetime.now()
            urls_to_retry = []
            
            # 找出需要重试的URL
            for url, data in webhook_retry_cache.items():
                if now >= data['retry_time'] and not data['retried']:
                    urls_to_retry.append(url)
            
            # 重试发送请求
            if urls_to_retry:
                logging.info(f"开始处理webhook重试队列，共{len(urls_to_retry)}个请求")
                
                async with aiohttp.ClientSession() as session:
                    for url in urls_to_retry:
                        data = webhook_retry_cache[url]
                        try:
                            async with session.post(
                                url,
                                data=data['body'],
                                headers=data['headers'],
                                timeout=10  # 重试请求的超时设置为10秒
                            ) as response:
                                success = 200 <= response.status < 300
                                if success:
                                    logging.info(f"Webhook重试成功: {PrivacyUtils.sanitize_url(url)} | 状态码: {response.status}")
                                    # 成功后从缓存中删除
                                    webhook_retry_cache.pop(url, None)
                                else:
                                    logging.warn(f"Webhook重试仍然失败: {PrivacyUtils.sanitize_url(url)} | 状态码: {response.status}")
                                    # 标记为已重试，不再进行后续重试
                                    data['retried'] = True
                        except Exception as e:
                            logging.error(f"Webhook重试异常: {PrivacyUtils.sanitize_url(url)} | 错误: {str(e)}")
                            # 标记为已重试，不再进行后续重试
                            data['retried'] = True
                            
                # 清理已经重试过的记录
                urls_to_remove = [url for url, data in webhook_retry_cache.items() if data['retried']]
                for url in urls_to_remove:
                    webhook_retry_cache.pop(url, None)
                
                if urls_to_remove:
                    logging.info(f"清理已重试的webhook请求，共{len(urls_to_remove)}个")
            
            # 等待1秒再检查
            await asyncio.sleep(1)
            
        except Exception as e:
            logging.error(f"处理webhook重试队列异常: {str(e)}")
            await asyncio.sleep(5)  # 发生异常时等待长一点再重试

@app.on_event("startup")
async def startup_event():
    # 启动配置监控任务
    asyncio.create_task(watch_config())
    
    # 启动webhook重试队列处理任务
    asyncio.create_task(process_webhook_retry_queue())
    
    logging.info(f"服务已启动")

if __name__ == "__main__":
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        loop="uvloop",
        http="httptools",
        log_config=None,
        access_log=False
    )