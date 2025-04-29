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

# 存储结构
active_connections = {}  # {secret: {websocket: {"token": str, ...}}}
message_cache = {}       # {secret: {"public": deque(), "tokens": {token: deque()}}}
cache_lock = asyncio.Lock()

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
            logging.debug(f"清理公共缓存 | 密钥：{secret[:8]}**** | 数量：{expired_public}")

        # 没有在线连接时缓存到公共
        if not has_online:
            cache["public"].append((expiry, body_bytes))
            logging.info(f"消息存入公共缓存 | 密钥：{secret[:8]}**** | 数量：{len(cache['public'])}")

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
                logging.debug(f"清理Token缓存 | 密钥：{secret[:8]}**** | Token：{token[:8]}**** | 数量：{expired}")
            
            deque_token.append((expiry, body_bytes))
            logging.info(f"消息存入Token缓存 | 密钥：{secret[:8]}**** | Token：{token[:8]}**** | 数量：{len(deque_token)}")

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
            logging.debug(f"初始化Token队列 | 密钥：{secret[:8]}**** | Token：{token[:8]}****")

    logging.info(
        f"WS连接成功 | 密钥：{secret[:8]}**** | Token：{token[:8]+'****' if token else '无'} | "
        f"环境：{environment} | 连接数：{current_count}"
    )

    # 触发补发任务
    if token:
        asyncio.create_task(resend_token_cache(secret, token, websocket))
    asyncio.create_task(resend_public_cache(secret, websocket))

    try:
        while True:
            data = await websocket.receive_text()
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
                    logging.debug(f"准备离线缓存 | 密钥：{secret[:8]}**** | Token：{token[:8]}****")

                logging.info(
                    f"WS断开连接 | 密钥：{secret[:8]}**** | Token：{token[:8]+'****' if token else '无'} | "
                    f"剩余连接：{remaining}"
                )
    finally:
        async with cache_lock:
            if secret in active_connections and websocket in active_connections[secret]:
                del active_connections[secret][websocket]

async def handle_ws_message(message: str, websocket: WebSocket):
    try:
        data = json_module.loads(message)
        if data["op"] == 2:  # 处理鉴权
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
                        logging.warning(f"连接重试过多关闭 | 密钥：{secret[:8]}****")

    # 记录转发结果
    if success_count > 0:
        log_parts = [
            f"消息转发成功 | 密钥：{secret[:8]}****",
            f"总数：{success_count}/{len(websockets)}",
            f"沙盒：{sandbox_success}" if sandbox_success > 0 else "",
            f"正式：{formal_success}" if formal_success > 0 else ""
        ]
        logging.info(" | ".join([p for p in log_parts if p]))
    
    if fail_count > 0:
        logging.warning(
            f"消息转发失败 | 密钥：{secret[:8]}**** | "
            f"失败数：{fail_count}/{len(websockets)}"
        )

async def resend_token_cache(secret: str, token: str, websocket: WebSocket):
    try:
        await asyncio.sleep(3)  # 固定延迟3秒
        
        async with cache_lock:
            if secret not in message_cache or token not in message_cache[secret]["tokens"]:
                return
            deque_cache = message_cache[secret]["tokens"][token]
            messages = list(deque_cache)
            deque_cache.clear()

        success = 0
        fail = 0
        valid_count = 0
        now = datetime.now()
        total = len(messages)
        
        logging.info(f"开始补发Token缓存 | 密钥：{secret[:8]}**** | Token：{token[:8]}**** | 总量：{total}")
        
        # 分批次发送（每秒10条）
        batch_size = 10
        for i in range(0, len(messages), batch_size):
            batch = messages[i:i+batch_size]
            batch_success = 0
            batch_fail = 0
            
            for expiry, msg in batch:
                if expiry < now:
                    continue
                valid_count += 1
                try:
                    await websocket.send_bytes(msg)
                    batch_success += 1
                except Exception as e:
                    batch_fail += 1
            
            success += batch_success
            fail += batch_fail
            
            # 记录批次日志
            logging.info(
                f"Token补发进度 | 密钥：{secret[:8]}**** | Token：{token[:8]}**** | "
                f"批次：{i//batch_size+1} | 本批：{batch_success}成功/{batch_fail}失败"
            )
            
            # 严格1秒间隔
            if i + batch_size < len(messages):
                await asyncio.sleep(1)

        logging.info(
            f"Token缓存补发完成 | 密钥：{secret[:8]}**** | Token：{token[:8]}**** | "
            f"总消息：{total} | 有效消息：{valid_count} | "
            f"成功：{success} | 失败：{fail}"
        )
    except WebSocketDisconnect:
        logging.warning(f"补发中断：WebSocket连接已关闭 | 密钥：{secret[:8]}**** | Token：{token[:8]}****")
    except Exception as e:
        logging.error(f"Token缓存补发异常: {str(e)}")

async def resend_public_cache(secret: str, websocket: WebSocket):
    try:
        await asyncio.sleep(3)  # 固定延迟3秒
        
        async with cache_lock:
            if secret not in message_cache:
                return
            public_deque = message_cache[secret]["public"]
            messages = list(public_deque)
            public_deque.clear()

        success = 0
        fail = 0
        valid_count = 0
        now = datetime.now()
        total = len(messages)
        
        logging.info(f"开始补发公共缓存 | 密钥：{secret[:8]}**** | 总量：{total}")
        
        # 分批次发送（每秒10条）
        batch_size = 10
        for i in range(0, len(messages), batch_size):
            batch = messages[i:i+batch_size]
            batch_success = 0
            batch_fail = 0
            
            for expiry, msg in batch:
                if expiry < now:
                    continue
                valid_count += 1
                try:
                    await websocket.send_bytes(msg)
                    batch_success += 1
                except Exception as e:
                    batch_fail += 1
            
            success += batch_success
            fail += batch_fail
            
            # 记录批次日志
            logging.info(
                f"公共补发进度 | 密钥：{secret[:8]}**** | "
                f"批次：{i//batch_size+1} | 本批：{batch_success}成功/{batch_fail}失败"
            )
            
            # 严格1秒间隔
            if i + batch_size < len(messages):
                await asyncio.sleep(1)

        logging.info(
            f"公共缓存补发完成 | 密钥：{secret[:8]}**** | "
            f"总消息：{total} | 有效消息：{valid_count} | "
            f"成功：{success} | 失败：{fail}"
        )
    except WebSocketDisconnect:
        logging.warning(f"补发中断：WebSocket连接已关闭 | 密钥：{secret[:8]}****")
    except Exception as e:
        logging.error(f"公共缓存补发异常: {str(e)}")

if __name__ == "__main__":
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        loop="uvloop",
        http="httptools",
        timeout_keep_alive=30
    )