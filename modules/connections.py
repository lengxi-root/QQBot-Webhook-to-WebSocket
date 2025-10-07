import asyncio
import hashlib
import json
import logging
import os
import threading
import time
from collections import deque
from datetime import datetime
from typing import List, Dict, Any, Optional

import aiohttp
from fastapi import WebSocket, WebSocketDisconnect

from modules.privacy import PrivacyUtils
from modules.cache import cache_manager
from modules.stats import stats_manager

active_connections = {}

service_health = {
    "last_successful_webhook": 0,
    "last_successful_ws_message": 0,
    "error_count": 0,
    "high_load_detected": False
}

PUSH_TIMEOUT = 10
RETRY_INTERVAL = 1
MAX_RETRY_TIME = 180
SLOW_THRESHOLD = 3

push_records: Dict[str, Dict] = {}

json_module = json
JSONDecodeError = json.JSONDecodeError


class MessagePushRecord:
    
    def __init__(self, message_id: str, secret: str, data: bytes, target_count: int):
        self.message_id = message_id
        self.secret = secret
        self.data = data
        self.target_count = target_count
        self.start_time = time.time()
        self.end_time: Optional[float] = None
        self.retry_count = 0
        self.success_count = 0
        self.status = "pending"
        
    def to_dict(self) -> Dict[str, Any]:
        duration = (self.end_time or time.time()) - self.start_time
        return {
            "message_id": self.message_id,
            "secret": self.secret[:8] + "***",
            "message_preview": self.data[:100].decode('utf-8', errors='ignore'),
            "target_count": self.target_count,
            "start_time": datetime.fromtimestamp(self.start_time).isoformat(),
            "end_time": datetime.fromtimestamp(self.end_time).isoformat() if self.end_time else None,
            "duration": round(duration, 2),
            "retry_count": self.retry_count,
            "success_count": self.success_count,
            "status": self.status
        }


def generate_message_id() -> str:
    return hashlib.md5(str(time.time()).encode()).hexdigest()[:16]


async def send_to_all(secret: str, data: bytes):
    try:
        lock = await cache_manager.get_lock_for_secret(secret)
        async with lock:
            connections = active_connections.get(secret, {})
            websockets = list(connections.keys())
            
        if len(websockets) == 0:
            return False

        success_count = 0
        sandbox_success = 0
        formal_success = 0
        fail_count = 0

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

        for _ in range(success_count):
            stats_manager.increment_ws_stats(secret, success=True)
        for _ in range(fail_count):
            stats_manager.increment_ws_stats(secret, success=False)

        if success_count > 0:
            log_parts = [
                f"{time.strftime('%m-%d %H:%M:%S')} - WebSocket转发成功 | 密钥：{PrivacyUtils.sanitize_secret(secret)}",
                f"总数：{success_count}/{len(websockets)}",
                f"沙盒：{sandbox_success}" if sandbox_success > 0 else "",
                f"正式：{formal_success}" if formal_success > 0 else ""
            ]
            root_logger = logging.getLogger()
            root_logger.info(" | ".join([p for p in log_parts if p]))

            if fail_count > 0:
                root_logger.info(
                    f"{time.strftime('%m-%d %H:%M:%S')} - 部分消息转发失败 | 密钥：{PrivacyUtils.sanitize_secret(secret)} | "
                    f"失败数：{fail_count}/{len(websockets)}"
                )
        elif fail_count > 0:
            root_logger = logging.getLogger()
            root_logger.warning(
                f"{time.strftime('%m-%d %H:%M:%S')} - WebSocket消息转发全部失败 | 密钥：{PrivacyUtils.sanitize_secret(secret)} | "
                f"失败数：{fail_count}/{len(websockets)}"
            )

        return success_count > 0
    except Exception as e:
        logging.error(f"发送消息全局异常: {e}")
        service_health["error_count"] += 1
        return False


async def send_to_one(ws: WebSocket, data: bytes, conn_info: dict, secret: str):
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
                root_logger = logging.getLogger()
                root_logger.debug(f"转发消息内容: {data.decode()}")

                lock = await cache_manager.get_lock_for_secret(secret)
                async with lock:
                    if secret in active_connections and ws in active_connections[secret]:
                        active_connections[secret][ws]["failure_count"] = 0
                        active_connections[secret][ws]["last_activity"] = time.time()
                
                stats_manager.increment_ws_stats(secret, success=True)

                return (True, is_sandbox)
            except Exception as e:
                lock = await cache_manager.get_lock_for_secret(secret)
                async with lock:
                    if secret in active_connections and ws in active_connections[secret]:
                        active_connections[secret][ws]["failure_count"] += 1
                        if active_connections[secret][ws]["failure_count"] >= 5:
                            try:
                                await ws.close()
                            except:
                                pass

                            if secret in active_connections and ws in active_connections[secret]:
                                del active_connections[secret][ws]
                                if not active_connections[secret]:
                                    del active_connections[secret]
                                logging.warning(f"连接重试过多关闭 | 密钥：{PrivacyUtils.sanitize_secret(secret)}")
                
                stats_manager.increment_ws_stats(secret, success=False)
                
                return False
        return None
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

        if cache_type == 'token':
            cache_desc = f"Token：{PrivacyUtils.sanitize_secret(token)}" if token else "Token：未知"
            log_prefix = "Token补发"
        else:
            cache_desc = "公共缓存"
            log_prefix = "公共补发"

        logging.info(
            f"开始补发{cache_desc} | 密钥：{PrivacyUtils.sanitize_secret(secret)} | 总量：{total}")

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
                    logging.info(f"补发{cache_desc}消息: {msg.decode()}")
                except Exception as e:
                    batch_fail += 1

            success += batch_success
            fail += batch_fail

            logging.info(
                f"{log_prefix}进度 | 密钥：{PrivacyUtils.sanitize_secret(secret)} | "
                f"批次：{i // batch_size + 1} | 本批：{batch_success}成功/{batch_fail}失败"
            )

            if i + batch_size < len(cache_queue):
                await asyncio.sleep(1)

        logging.info(
            f"{cache_desc}补发完成 | 密钥：{PrivacyUtils.sanitize_secret(secret)} | "
            f"总消息：{total} | 有效消息：{valid_count} | "
            f"成功：{success} | 失败：{fail}"
        )
    except WebSocketDisconnect:
        logging.warning(
            f"补发中断：WebSocket连接已关闭 | 密钥：{PrivacyUtils.sanitize_secret(secret)} | {cache_desc}")
    except Exception as e:
        logging.error(f"{cache_desc}补发异常: {str(e)}")


async def resend_token_cache(secret: str, token: str, websocket: WebSocket):
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


async def send_heartbeat(websocket: WebSocket, secret: str):
    try:
        while True:
            try:
                await asyncio.sleep(25)
                await websocket.send_bytes(json_module.dumps({"op": 11}))
                logging.debug(f"发送心跳包 | 密钥：{PrivacyUtils.sanitize_secret(secret)}")
            except Exception as e:
                logging.error(f"心跳发送失败: {e}")
                break
    except asyncio.CancelledError:
        pass
    except Exception as e:
        logging.error(f"心跳任务异常: {e}")


async def handle_ws_message(message: str, websocket: WebSocket):
    try:
        data = json_module.loads(message)
        
        if data.get("op") == 1 and data.get("d") == 1:
            logging.debug(f"解析WS心跳: {data}")
        else:
            logging.debug(f"解析WS消息: {data}")
        
        if data["op"] == 2:
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
        elif data["op"] == 1:
            await websocket.send_bytes(json_module.dumps({"op": 11}))
    except Exception as e:
        logging.error(f"WS消息处理错误: {e}")
        service_health["error_count"] += 1


async def forward_webhook(targets: List[dict], body: bytes, headers: dict, timeout: int, current_secret: str) -> list:
    
    message_id = generate_message_id()
    webhook_targets = [t for t in targets if t['secret'] == current_secret]
    
    record = MessagePushRecord(
        message_id=message_id,
        secret=current_secret,
        data=body,
        target_count=len(webhook_targets)
    )
    record.status = "sending"
    push_records[message_id] = record
    
    async def send_to_target_with_retry(session: aiohttp.ClientSession, target: dict) -> dict:
        if target['secret'] != current_secret:
            return {
                'url': target['url'],
                'status': None,
                'success': True,
                'skipped': True,
                'reason': '密钥不匹配'
            }

        start_time = time.time()
        retry_count = 0
        last_error = None
        
        while True:
            elapsed = time.time() - start_time
            
            if elapsed > MAX_RETRY_TIME:
                logging.warning(f"Webhook转发超时（{MAX_RETRY_TIME}秒），取消重试 | 密钥: {PrivacyUtils.sanitize_secret(current_secret)}")
                return {
                    'url': target['url'],
                    'status': None,
                    'success': False,
                    'skipped': False,
                    'timeout': True,
                    'retry_count': retry_count,
                    'error': last_error or '超过最大重试时间'
                }
            
            try:
                async with asyncio.timeout(PUSH_TIMEOUT):
                    async with session.post(
                            target['url'],
                            data=body,
                            headers=headers,
                            timeout=aiohttp.ClientTimeout(total=PUSH_TIMEOUT)
                    ) as response:
                        success = 200 <= response.status < 300
                        
                        if success:
                            record.success_count += 1
                            duration = time.time() - start_time
                            return {
                                'url': target['url'],
                                'status': response.status,
                                'success': True,
                                'skipped': False,
                                'retry_count': retry_count,
                                'duration': round(duration, 2)
                            }
                        else:
                            last_error = f"HTTP {response.status}"
                            
            except asyncio.TimeoutError:
                last_error = "请求超时（10秒）"
            except Exception as e:
                last_error = str(e)
            
            retry_count += 1
            record.retry_count = retry_count
            await asyncio.sleep(RETRY_INTERVAL)

    async with aiohttp.ClientSession() as session:
        tasks = [
            send_to_target_with_retry(session, target)
            for target in targets
        ]
        results = await asyncio.gather(*tasks)
        
        record.end_time = time.time()
        success_count = sum(1 for r in results if r.get('success') and not r.get('skipped'))
        record.status = "success" if success_count > 0 else "failed"
        
        return results
