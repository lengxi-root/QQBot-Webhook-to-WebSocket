import asyncio
from collections import deque
from datetime import datetime, timedelta
import logging
import threading
import time
from modules.privacy import PrivacyUtils
from modules.config import config

class MessageCacheManager:
    """消息缓存管理类"""
    
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
        clean_interval = config.cache["clean_interval"]  # 从配置获取清理间隔
        
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
                for _ in range(int(clean_interval / 0.5)):
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
            message_ttl = config.cache["message_ttl"]  # 从配置获取消息TTL
            expiry = now + timedelta(seconds=message_ttl)

            # 初始化缓存结构
            if secret not in self.message_cache:
                self.message_cache[secret] = {
                    "public": deque(maxlen=config.cache["max_public_messages"]),
                    "tokens": {}
                }

            # 添加到公共缓存
            if token is None:
                self.message_cache[secret]["public"].append((expiry, message_bytes))
                return True

            # 添加到Token缓存
            if token not in self.message_cache[secret]["tokens"]:
                self.message_cache[secret]["tokens"][token] = deque(maxlen=config.cache["max_token_messages"])

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
            ttl = config.cache["message_ttl"]  # 从配置获取消息TTL
        self.message_id_cache[message_id] = datetime.now() + timedelta(seconds=ttl)

    def has_message_id(self, message_id):
        """检查消息ID是否存在"""
        return message_id in self.message_id_cache

# 创建缓存管理器单例实例
cache_manager = MessageCacheManager() 