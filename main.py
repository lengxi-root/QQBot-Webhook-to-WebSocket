from fastapi import FastAPI, Request, Header, WebSocket, WebSocketDisconnect
from fastapi.responses import *
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from cryptography.hazmat.primitives.asymmetric import ed25519
from datetime import datetime, timedelta
import logging
import uvicorn
import asyncio
from collections import deque
import configparser
import os
from pathlib import Path
import re
from urllib.parse import urlparse

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

# 隐私保护中间件
@app.middleware("http")
async def privacy_middleware(request: Request, call_next):
    response = await call_next(request)
    
    # IP地址脱敏处理
    client_host = request.client.host if request.client else "unknown"
    if client_host != "unknown":
        ip_parts = client_host.split('.')
        if len(ip_parts) == 4:  # IPv4地址处理
            sanitized_ip = f"{ip_parts[0]}.***.***.{ip_parts[3]}"
        else:  # 其他格式保持原样
            sanitized_ip = client_host
    else:
        sanitized_ip = "unknown"

    # URL路径处理
    full_url = str(request.url)
    parsed_url = urlparse(full_url)
    sanitized_path = parsed_url.path
    if parsed_url.query:
        sanitized_path += "?" + parsed_url.query
    
    # 敏感参数过滤
    sanitized_path = re.sub(
        r"(secret=)(\w{3})\w+",
        r"\1\2****",
        sanitized_path,
        flags=re.IGNORECASE
    )

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
            logging.debug(f"清理公共缓存 | 密钥：{secret[:3]}**** | 数量：{expired_public}")

        # 没有在线连接时缓存到公共
        if not has_online:
            cache["public"].append((expiry, body_bytes))
            logging.info(f"消息存入公共缓存 | 密钥：{secret[:3]}**** | 数量：{len(cache['public'])}")

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
                logging.debug(f"清理Token缓存 | 密钥：{secret[:3]}**** | Token：{token[:3]}**** | 数量：{expired}")
            
            deque_token.append((expiry, body_bytes))
            logging.info(f"消息存入Token缓存 | 密钥：{secret[:3]}**** | Token：{token[:3]}**** | 数量：{len(deque_token)}")

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
            logging.debug(f"初始化Token队列 | 密钥：{secret[:3]}**** | Token：{token[:3]}****")

    logging.info(
        f"WS连接成功 | 密钥：{secret[:3]}**** | Token：{token[:8]+'****' if token else '无'} | "
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

                # 确保离线token的缓存队列存在
                if token:
                    message_cache.setdefault(secret, {"public": deque(maxlen=1000), "tokens": {}})
                    message_cache[secret]["tokens"].setdefault(token, deque(maxlen=1000))
                    logging.debug(f"准备离线缓存 | 密钥：{secret[:3]}**** | Token：{token[:3]}****")

                logging.info(
                    f"WS断开连接 | 密钥：{secret[:3]}**** | Token：{token[:8]+'****' if token else '无'} | "
                    f"剩余连接：{remaining}"
                )
    finally:
        async with cache_lock:
            if secret in active_connections and websocket in active_connections[secret]:
                del active_connections[secret][websocket]

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
        elif data["op"] == 1:  # 心跳响应
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
                        logging.warning(f"连接重试过多关闭 | 密钥：{secret[:3]}****")

    # 记录转发结果
    if success_count > 0:
        log_parts = [
            f"消息转发成功 | 密钥：{secret[:3]}****",
            f"总数：{success_count}/{len(websockets)}",
            f"沙盒：{sandbox_success}" if sandbox_success > 0 else "",
            f"正式：{formal_success}" if formal_success > 0 else ""
        ]
        logging.info(" | ".join([p for p in log_parts if p]))
    
    if fail_count > 0:
        logging.warning(
            f"消息转发失败 | 密钥：{secret[:3]}**** | "
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
            cache_desc = f"Token：{token[:3]}****" if token else "Token：未知"
            log_prefix = "Token补发"
        else:
            cache_desc = "公共缓存"
            log_prefix = "公共补发"

        logging.info(f"开始补发{cache_desc} | 密钥：{secret[:3]}**** | 总量：{total}")

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
                f"{log_prefix}进度 | 密钥：{secret[:3]}**** | "
                f"批次：{i//batch_size + 1} | 本批：{batch_success}成功/{batch_fail}失败"
            )
            
            # 严格1秒间隔
            if i + batch_size < len(cache_queue):
                await asyncio.sleep(1)

        logging.info(
            f"{cache_desc}补发完成 | 密钥：{secret[:3]}**** | "
            f"总消息：{total} | 有效消息：{valid_count} | "
            f"成功：{success} | 失败：{fail}"
        )
    except WebSocketDisconnect:
        logging.warning(f"补发中断：WebSocket连接已关闭 | 密钥：{secret[:3]}**** | {cache_desc}")
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

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(watch_config())

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