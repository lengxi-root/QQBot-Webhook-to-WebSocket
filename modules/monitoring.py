import asyncio
import logging
import time
import psutil
import config
from modules.connections import service_health
from modules.cache import cache_manager
from modules.privacy import PrivacyUtils

async def watch_config():
    while True:
        await asyncio.sleep(3600)

def log_config_changes():
    logging.info(f"缓存配置: 默认={config.cache['default_max_messages']}, "
               f"公共={config.cache['max_public_messages']}, "
               f"Token={config.cache['max_token_messages']}, "
               f"TTL={config.cache['message_ttl']}秒, "
               f"清理间隔={config.cache['clean_interval']}秒")
    
    logging.info(f"统计配置: 间隔={config.stats['write_interval']}秒, "
               f"文件={config.stats['stats_file']}")
    
    logging.info(f"去重有效期: {config.deduplication_ttl}秒")
    
    if config.no_cache_secrets:
        sanitized = [PrivacyUtils.sanitize_secret(s) for s in config.no_cache_secrets]
        logging.info(f"不缓存密钥: {', '.join(sanitized)}")
    else:
        logging.info("不缓存密钥: 无")

async def monitor_service_health():
    while True:
        try:
            now = time.time()
            
            if service_health["last_successful_webhook"] > 0:
                idle = now - service_health["last_successful_webhook"]
                if idle > 300:
                    logging.warning(f"Webhook处理异常，{idle:.1f}秒未成功处理")

                    from modules.connections import active_connections
                    total = sum(len(conns) for conns in active_connections.values())
                    if total == 0 and service_health["error_count"] > 10:
                        logging.warning("执行自动恢复: 清理缓存和锁")
                        cache_manager.cache_locks.clear()
                        cache_manager.message_cache.clear()
                        cache_manager.message_id_cache.clear()
                        service_health["error_count"] = 0

            cpu = psutil.cpu_percent(interval=0.5)
            if cpu > 90:
                logging.warning(f"高CPU负载: {cpu}%")
                service_health["high_load_detected"] = True
            else:
                service_health["high_load_detected"] = False

            mem = psutil.Process().memory_percent()
            if mem > 85:
                logging.warning(f"高内存使用: {mem:.1f}%，执行垃圾回收")
                import gc
                gc.collect()

            await asyncio.sleep(30)
        except Exception as e:
            logging.error(f"健康监控异常: {e}")
            await asyncio.sleep(60)
