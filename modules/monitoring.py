import asyncio
import logging
import os
import psutil
import time
from collections import deque
from modules.connections import service_health
from modules.config import config
from modules.cache import cache_manager

async def watch_config():
    """配置更新逻辑"""
    # 配置直接在代码中定义，不再需要监视文件变更
    # 但保留函数以供未来扩展
    while True:
        await asyncio.sleep(3600)  # 睡眠以保持任务运行，但不执行任何操作

def log_config_changes():
    """记录配置变更的日志"""
    # 缓存配置
    logging.info(f"缓存配置已更新: 最大缓存消息数={config.cache['default_max_messages']}, "
               f"公共队列最大={config.cache['max_public_messages']}, "
               f"Token队列最大={config.cache['max_token_messages']}, "
               f"TTL={config.cache['message_ttl']}秒, "
               f"清理间隔={config.cache['clean_interval']}秒")
    
    # 统计配置
    logging.info(f"统计配置已更新: 间隔={config.stats['write_interval']}秒, "
               f"文件={config.stats['stats_file']}")
    
    # 去重配置
    logging.info(f"消息去重有效期配置为：{config.deduplication_ttl}秒")
    
    # 不缓存密钥列表
    from modules.privacy import PrivacyUtils
    if config.no_cache_secrets:
        sanitized_secrets = [PrivacyUtils.sanitize_secret(s) for s in config.no_cache_secrets]
        logging.info(f"不缓存密钥列表：{', '.join(sanitized_secrets)}")
    else:
        logging.info("不缓存密钥列表：无")

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
                    from modules.connections import active_connections
                    total_connections = sum(len(conns) for conns in active_connections.values())
                    if total_connections == 0 and service_health["error_count"] > 10:
                        # 清理资源并重置状态
                        logging.warning("执行自动恢复: 清理缓存和锁")
                        cache_manager.cache_locks.clear()
                        cache_manager.message_cache.clear()
                        cache_manager.message_id_cache.clear()
                        service_health["error_count"] = 0

            # 检查系统负载
            cpu_percent = psutil.cpu_percent(interval=0.5)
            if cpu_percent > 90:  # CPU使用率超过90%
                logging.warning(f"检测到高CPU负载: {cpu_percent}%")
                service_health["high_load_detected"] = True
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