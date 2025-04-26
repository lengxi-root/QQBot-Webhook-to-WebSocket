# -*- coding: utf-8 -*-
from fastapi import FastAPI, Request, Header, WebSocket, WebSocketDisconnect
from fastapi.responses import *
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from cryptography.hazmat.primitives.asymmetric import ed25519
from datetime import datetime, timedelta
import logging
import uvicorn
import json
import asyncio
from collections import deque

app = FastAPI()

# 跨域配置
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 存储结构
active_connections = {}  # {secret: {websocket: failure_count}}
message_cache = {}       # {secret: deque((timestamp, message))}
cache_lock = asyncio.Lock()
sender_tasks = {}        # {secret: task}

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

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

@app.post("/webhook")
async def handle_webhook(
        request: Request,
        payload: Payload,
        user_agent: str = Header(None),
        x_bot_appid: str = Header(None)
):
    secret = request.query_params.get('secret')
    body_bytes = await request.body()
    logging.debug(f"收到消息: {body_bytes}")

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
        has_connection = secret in active_connections and len(active_connections[secret]) > 0
        
        if not has_connection:
            # 缓存消息（保留5分钟）
            now = datetime.now()
            expiry = now + timedelta(minutes=5)
            
            if secret not in message_cache:
                message_cache[secret] = deque(maxlen=1000)  # 限制最大缓存量
            
            message_cache[secret].append((expiry, body_bytes))
            logging.info(f"消息已缓存 | 密钥：{secret} | 缓存数：{len(message_cache[secret])}")
            
            # 清理过期消息
            while message_cache[secret] and message_cache[secret][0][0] < now:
                message_cache[secret].popleft()
            
            return {"status": "cached"}
        
    # 实时转发
    await send_to_all(secret, body_bytes)
    return {"status": "delivered"}

@app.websocket("/ws/{secret}")
async def websocket_endpoint(websocket: WebSocket, secret: str, group: str = None, member: str = None, content: str = None):
    await websocket.accept()
    
    # 发送初始心跳
    await websocket.send_bytes(json.dumps({
        "op": 10,
        "d": {"heartbeat_interval": 30000}
    }))
    
    # 判断环境
    is_sandbox = any([group, member, content])
    environment = "沙盒环境" if is_sandbox else "正式环境"

    # 注册连接
    async with cache_lock:
        if secret not in active_connections:
            active_connections[secret] = {}
        
        active_connections[secret][websocket] = {
            "failure_count": 0,
            "group": group,
            "member": member,
            "content": content,
            "is_sandbox": is_sandbox
        }

        current_count = len(active_connections[secret])
        
        logging.info(f"WS连接成功 | 密钥：{secret} | 连接数：{current_count} | 当前环境：{environment}")
        # 延迟启动缓存重发
        if secret in message_cache and len(message_cache[secret]) > 0:
            if secret in sender_tasks:
                sender_tasks[secret].cancel()
                logging.info(f"取消现有重发任务 | 密钥：{secret}")
            
            async def delayed_resend():
                try:
                    logging.info(f"等待3秒开始重发 | 密钥：{secret}")
                    await asyncio.sleep(3)
                    await resend_cached_messages(secret)
                except asyncio.CancelledError:
                    logging.info(f"延迟任务被取消 | 密钥：{secret}")
            
            sender_tasks[secret] = asyncio.create_task(delayed_resend())
            logging.info(f"已创建延迟重发任务 | 密钥：{secret}")

    try:
        while True:
            data = await websocket.receive_text()
            await handle_ws_message(data, websocket)
    except WebSocketDisconnect:
        async with cache_lock:
            if secret in active_connections and websocket in active_connections[secret]:
                del active_connections[secret][websocket]
                remaining = len(active_connections[secret])
                
                if remaining == 0:
                    del active_connections[secret]
                    if secret in sender_tasks:
                        sender_tasks[secret].cancel()
                        del sender_tasks[secret]
                
                logging.info(f"WS连接断开 | 密钥：{secret} | 剩余连接：{remaining}")
    finally:
        async with cache_lock:
            if secret in active_connections and websocket in active_connections[secret]:
                del active_connections[secret][websocket]

async def handle_ws_message(message: str, websocket: WebSocket):
    try:
        data = json.loads(message)
        if data["op"] == 2:  # 处理鉴权
            await websocket.send_bytes(json.dumps({
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
            await websocket.send_bytes(json.dumps({"op": 11}))
    except Exception as e:
        logging.error(f"WS消息处理错误: {e}")

async def send_to_all(secret: str, data: bytes):
    try:
        message_json = json.loads(data.decode('utf-8'))
    except json.JSONDecodeError:
        logging.error(f"消息解析错误: {data}")
        return
    async with cache_lock:
        connections = active_connections.get(secret, {})
        websockets = list(connections.keys())
    
    success_count = 0
    sandbox_success = 0
    formal_success = 0
    for ws in websockets:
        filters = connections[ws]
        group = filters.get("group")
        member = filters.get("member")
        content_filter = filters.get("content")
        is_sandbox = filters.get("is_sandbox")

        should_send = True
        if is_sandbox:
            if group:
                should_send = message_json.get("d", {}).get("group_openid") == group
            if should_send and member:
                should_send = should_send and message_json.get("d", {}).get("author", {}).get("member_openid") == member
            if should_send and content_filter:
                content = message_json.get("d", {}).get("content")
                should_send = should_send and (content_filter in content if content else False)

        if should_send:
            try:
                await ws.send_bytes(data)
                success_count += 1
                if is_sandbox:
                    sandbox_success += 1
                else:
                    formal_success += 1
                async with cache_lock:
                    connections[ws]["failure_count"] = 0  # 重置失败计数
            except Exception as e:
                logging.error(f"消息转发失败 | 密钥：{secret} | 错误：{e}")
                async with cache_lock:
                    connections[ws]["failure_count"] += 1

                    if connections[ws]["failure_count"] >= 5:
                        try:
                            await ws.close()
                        except:
                            pass
                        del connections[ws]
                        logging.info(f"连续5次失败关闭连接 | 密钥：{secret}")

    env_str = []
    if sandbox_success > 0:
        env_str.append("沙盒环境")
    if formal_success > 0:
        env_str.append("正式环境")
    env_str = " | ".join(env_str)

    if success_count > 0:
        logging.info(f"消息转发成功 | 密钥：{secret} | 成功数：{success_count}/{len(websockets)} | {env_str}")


async def resend_cached_messages(secret: str):
    try:
        logging.info(f"开始处理缓存消息 | 密钥：{secret}")
        while True:
            # 检查连接状态
            async with cache_lock:
                if secret not in active_connections or len(active_connections[secret]) == 0:
                    logging.warning(f"中止重发：无有效连接 | 密钥：{secret}")
                    break
                
                if secret not in message_cache or len(message_cache[secret]) == 0:
                    logging.info(f"缓存已清空 | 密钥：{secret}")
                    break
                
                # 获取一批消息（最多10条）
                batch = []
                for _ in range(10):
                    if not message_cache[secret]:
                        break
                    batch.append(message_cache[secret].popleft()[1])
            
            # 发送批次
            for msg in batch:
                await send_to_all(secret, msg)
                await asyncio.sleep(0.1)  # 控制发送速度
            
            # 检查剩余消息
            async with cache_lock:
                if not message_cache.get(secret):
                    break
            
            await asyncio.sleep(1)
    except asyncio.CancelledError:
        logging.info(f"重发任务被取消 | 密钥：{secret}")
    finally:
        async with cache_lock:
            if secret in sender_tasks:
                del sender_tasks[secret]

if __name__ == "__main__":
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        loop="uvloop",
        http="httptools",
        timeout_keep_alive=30
    )