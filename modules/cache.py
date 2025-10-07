import asyncio
import logging
import threading
import time
from collections import deque
from datetime import datetime, timedelta

import config
from modules.privacy import PrivacyUtils

class MessageCacheManager:
    
    def __init__(self):
        self.message_cache = {}
        self.cache_locks = {}
        self.message_id_cache = {}
        self.clean_thread = None
        self.stop_flag = threading.Event()

    async def get_lock_for_secret(self, secret):
        if secret not in self.cache_locks:
            self.cache_locks[secret] = asyncio.Lock()
        return self.cache_locks[secret]

    def start_cleaning_thread(self):
        if self.clean_thread is None or not self.clean_thread.is_alive():
            self.stop_flag.clear()
            self.clean_thread = threading.Thread(target=self._clean_expired_messages)
            self.clean_thread.daemon = True
            self.clean_thread.start()
            logging.info("缓存清理线程已启动")

    def stop_cleaning_thread(self):
        if self.clean_thread and self.clean_thread.is_alive():
            self.stop_flag.set()
            self.clean_thread.join(timeout=2)
            logging.info("缓存清理线程已停止")

    def _clean_expired_messages(self):
        clean_interval = config.cache["clean_interval"]
        
        while not self.stop_flag.is_set():
            try:
                now = datetime.now()
                expired_ids = [msg_id for msg_id, expiry in self.message_id_cache.items() if expiry < now]
                for msg_id in expired_ids:
                    self.message_id_cache.pop(msg_id, None)

                if expired_ids:
                    logging.debug(f"清理过期消息ID: {len(expired_ids)}个")
                
                # 防止message_id_cache无限增长：如果超过10000条，强制清理最旧的
                if len(self.message_id_cache) > 10000:
                    sorted_ids = sorted(self.message_id_cache.items(), key=lambda x: x[1])
                    for msg_id, _ in sorted_ids[:len(self.message_id_cache) - 5000]:
                        self.message_id_cache.pop(msg_id, None)
                    logging.warning(f"消息ID缓存超限，强制清理至5000条")

                for secret in list(self.message_cache.keys()):
                    try:
                        cache = self.message_cache[secret]

                        if "public" in cache:
                            before = len(cache["public"])
                            cache["public"] = deque(
                                [(exp, data) for exp, data in cache["public"] if exp > now],
                                maxlen=cache["public"].maxlen
                            )
                            after = len(cache["public"])
                            if before > after:
                                logging.debug(
                                    f"清理公共缓存 | 密钥：{PrivacyUtils.sanitize_secret(secret)} | 清理:{before - after}个")

                        empty_tokens = []
                        for token, queue in cache.get("tokens", {}).items():
                            before = len(queue)
                            cache["tokens"][token] = deque(
                                [(exp, data) for exp, data in queue if exp > now],
                                maxlen=queue.maxlen
                            )
                            after = len(cache["tokens"][token])

                            if after == 0:
                                empty_tokens.append(token)
                            elif before > after:
                                logging.debug(
                                    f"清理Token缓存 | 密钥：{PrivacyUtils.sanitize_secret(secret)} | Token：{PrivacyUtils.sanitize_secret(token)} | 清理:{before - after}个")

                        for token in empty_tokens:
                            del cache["tokens"][token]

                        if (not cache.get("public") or len(cache["public"]) == 0) and len(cache.get("tokens", {})) == 0:
                            del self.message_cache[secret]
                            if secret in self.cache_locks:
                                del self.cache_locks[secret]
                            logging.debug(f"删除空缓存 | 密钥：{PrivacyUtils.sanitize_secret(secret)}")

                    except Exception as e:
                        logging.error(f"清理密钥{PrivacyUtils.sanitize_secret(secret)}缓存异常: {e}")

                for _ in range(int(clean_interval / 0.5)):
                    if self.stop_flag.is_set():
                        break
                    time.sleep(0.5)

            except Exception as e:
                logging.error(f"缓存清理线程异常: {e}")
                time.sleep(30)

    async def add_message(self, secret, message_bytes, token=None):
        lock = await self.get_lock_for_secret(secret)
        async with lock:
            now = datetime.now()
            message_ttl = config.cache["message_ttl"]
            expiry = now + timedelta(seconds=message_ttl)

            if secret not in self.message_cache:
                self.message_cache[secret] = {
                    "public": deque(maxlen=config.cache["max_public_messages"]),
                    "tokens": {}
                }

            if token is None:
                self.message_cache[secret]["public"].append((expiry, message_bytes))
                return True

            if token not in self.message_cache[secret]["tokens"]:
                self.message_cache[secret]["tokens"][token] = deque(maxlen=config.cache["max_token_messages"])

            self.message_cache[secret]["tokens"][token].append((expiry, message_bytes))
            return True

    async def get_messages_for_token(self, secret, token):
        lock = await self.get_lock_for_secret(secret)
        async with lock:
            if secret not in self.message_cache or token not in self.message_cache[secret]["tokens"]:
                return []

            messages = list(self.message_cache[secret]["tokens"][token])
            self.message_cache[secret]["tokens"][token].clear()
            return messages

    async def get_public_messages(self, secret):
        lock = await self.get_lock_for_secret(secret)
        async with lock:
            if secret not in self.message_cache or "public" not in self.message_cache[secret]:
                return []

            messages = list(self.message_cache[secret]["public"])
            self.message_cache[secret]["public"].clear()
            return messages

    def add_message_id(self, message_id, ttl=None):
        if not ttl:
            ttl = config.cache["message_ttl"]
        self.message_id_cache[message_id] = datetime.now() + timedelta(seconds=ttl)

    def has_message_id(self, message_id):
        return message_id in self.message_id_cache

cache_manager = MessageCacheManager()
