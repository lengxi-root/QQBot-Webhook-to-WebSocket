import asyncio
import aiohttp
import logging
import time
from typing import List, Dict, Any
from fastapi import WebSocket, WebSocketDisconnect
from datetime import datetime
from collections import deque
from modules.privacy import PrivacyUtils
from modules.cache import cache_manager
from modules.stats import stats_manager

# 存储结构
active_connections = {}  # {secret: {websocket: {"token": str, ...}}}

# 服务健康状态监控
service_health = {
    "last_successful_webhook": 0,
    "last_successful_ws_message": 0,
    "error_count": 0,
    "high_load_detected": False
}

# 导入JSON库
try:
    import orjson
    json_module = orjson
    JSONDecodeError = orjson.JSONDecodeError
except ImportError:
    import json
    json_module = json
    JSONDecodeError = json.JSONDecodeError

async def send_to_all(secret: str, data: bytes):
    """向所有相关WebSocket连接发送消息"""
    try:
        lock = await cache_manager.get_lock_for_secret(secret)
        async with lock:
            connections = active_connections.get(secret, {})
            websockets = list(connections.keys())
            
        # 如果没有WebSocket连接，直接返回，不进行任何操作
        if len(websockets) == 0:
            return False

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

        # 更新WS转发统计
        for _ in range(success_count):
            stats_manager.increment_ws_stats(secret, success=True)
        for _ in range(fail_count):
            stats_manager.increment_ws_stats(secret, success=False)

        # 记录转发结果
        if success_count > 0:
            log_parts = [
                f"{time.strftime('%m-%d %H:%M:%S')} - WebSocket消息转发成功 | 密钥：{PrivacyUtils.sanitize_secret(secret)}",
                f"总数：{success_count}/{len(websockets)}",
                f"沙盒：{sandbox_success}" if sandbox_success > 0 else "",
                f"正式：{formal_success}" if formal_success > 0 else ""
            ]
            # 使用root logger确保消息被处理
            root_logger = logging.getLogger()
            root_logger.info(" | ".join([p for p in log_parts if p]))

            # 只有当有部分失败时才记录部分失败信息，使用info级别而不是warning
            if fail_count > 0:
                root_logger.info(
                    f"{time.strftime('%m-%d %H:%M:%S')} - 部分消息转发失败 | 密钥：{PrivacyUtils.sanitize_secret(secret)} | "
                    f"失败数：{fail_count}/{len(websockets)}"
                )
        elif fail_count > 0:
            # 全部失败时才记录警告日志
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
                # 使用root logger确保消息被处理，但降级为DEBUG级别
                root_logger = logging.getLogger()
                root_logger.debug(f"转发消息内容: {data.decode()}")

                # 更新成功状态
                lock = await cache_manager.get_lock_for_secret(secret)
                async with lock:
                    if secret in active_connections and ws in active_connections[secret]:
                        active_connections[secret][ws]["failure_count"] = 0
                        active_connections[secret][ws]["last_activity"] = time.time()
                
                # 更新统计
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

                            # 从连接列表中移除
                            if secret in active_connections and ws in active_connections[secret]:
                                del active_connections[secret][ws]
                                if not active_connections[secret]:
                                    del active_connections[secret]
                                logging.warning(f"连接重试过多关闭 | 密钥：{PrivacyUtils.sanitize_secret(secret)}")
                
                # 更新统计
                stats_manager.increment_ws_stats(secret, success=False)
                
                return False
        return None  # 不需要发送
    except Exception as e:
        logging.error(f"单个消息发送异常: {e}")
        return False


async def resend_cache(secret: str, websocket: WebSocket, cache_queue: list, cache_type: str, token: str = None):
    """重发缓存消息"""
    try:
        success = 0
        fail = 0
        valid_count = 0
        now = datetime.now()
        total = len(cache_queue)

        # 生成日志描述
        if cache_type == 'token':
            cache_desc = f"Token：{PrivacyUtils.sanitize_secret(token)}" if token else "Token：未知"
            log_prefix = "Token补发"
        else:
            cache_desc = "公共缓存"
            log_prefix = "公共补发"

        logging.info(
            f"开始补发{cache_desc} | 密钥：{PrivacyUtils.sanitize_secret(secret)} | 总量：{total}")

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
                    logging.info(f"补发{cache_desc}消息: {msg.decode()}")
                except Exception as e:
                    batch_fail += 1

            success += batch_success
            fail += batch_fail

            # 记录批次日志
            logging.info(
                f"{log_prefix}进度 | 密钥：{PrivacyUtils.sanitize_secret(secret)} | "
                f"批次：{i // batch_size + 1} | 本批：{batch_success}成功/{batch_fail}失败"
            )

            # 严格1秒间隔
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


async def send_heartbeat(websocket: WebSocket, secret: str):
    """定期发送心跳包保持连接"""
    try:
        while True:
            try:
                await asyncio.sleep(25)  # 每25秒发送一次心跳
                await websocket.send_bytes(json_module.dumps({"op": 11}))
                # 心跳包日志降级为DEBUG级别，不在前台显示
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
    """处理WebSocket消息"""
    try:
        data = json_module.loads(message)
        
        # 所有WS消息解析降级为DEBUG级别，不在前台显示
        if data.get("op") == 1 and data.get("d") == 1:
            logging.debug(f"解析WS心跳: {data}")
        else:
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


async def forward_webhook(targets: List[dict], body: bytes, headers: dict, timeout: int, current_secret: str) -> list:
    """转发Webhook消息到目标URL列表"""
    
    async def send_to_target(session: aiohttp.ClientSession, target: dict) -> dict:
        """向单个目标发送消息"""
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
                    'skipped': False,
                    'retry': False
                }
                
                # 如果请求失败，进行一次重试
                if not success:
                    logging.warning(f"Webhook转发失败，3秒后重试: {PrivacyUtils.sanitize_url(target['url'])}")
                    await asyncio.sleep(3)  # 等待3秒后重试
                    try:
                        async with session.post(
                                target['url'],
                                data=body,
                                headers=headers,
                                timeout=timeout
                        ) as retry_response:
                            retry_success = 200 <= retry_response.status < 300
                            if retry_success:
                                result = {
                                    'url': target['url'],
                                    'status': retry_response.status,
                                    'success': True,
                                    'skipped': False,
                                    'retry': True
                                }
                                logging.info(f"Webhook重试转发成功: {PrivacyUtils.sanitize_url(target['url'])}")
                            else:
                                result['retry'] = True
                    except Exception as retry_e:
                        logging.error(f"Webhook重试转发异常: {str(retry_e)}")
                        result['retry'] = True
                        result['retry_error'] = str(retry_e)
                
                return result
        except Exception as e:
            logging.error(f"Webhook首次转发异常: {str(e)}")
            # 发生异常，进行重试
            await asyncio.sleep(3)  # 等待3秒后重试
            try:
                async with session.post(
                        target['url'],
                        data=body,
                        headers=headers,
                        timeout=timeout
                ) as retry_response:
                    retry_success = 200 <= retry_response.status < 300
                    return {
                        'url': target['url'],
                        'status': retry_response.status,
                        'success': retry_success,
                        'skipped': False,
                        'error': str(e),
                        'retry': True
                    }
            except Exception as retry_e:
                return {
                    'url': target['url'],
                    'status': None,
                    'success': False,
                    'skipped': False,
                    'error': str(e),
                    'retry': True,
                    'retry_error': str(retry_e)
                }

    async with aiohttp.ClientSession() as session:
        tasks = [
            send_to_target(session, target)
            for target in targets
        ]
        results = await asyncio.gather(*tasks)
        return results 