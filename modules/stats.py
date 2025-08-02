import threading
import logging
import time
import json
import os
from collections import defaultdict
from modules.config import config

class StatsManager:
    """统计信息管理类"""
    
    def __init__(self):
        # 初始化空统计数据结构
        self.stats = {
            "total_messages": 0,
            "ws": {
                "total_success": 0,
                "total_failure": 0,
            },
            "wh": {
                "total_success": 0,
                "total_failure": 0,
            },
            "per_secret": defaultdict(lambda: {
                "ws": {"success": 0, "failure": 0},
                "wh": {"success": 0, "failure": 0}
            })
        }
        self.stats_lock = threading.Lock()
        self.write_thread = None
        self.stop_flag = threading.Event()
        
        # 尝试从文件中加载已有的统计数据
        try:
            self.load_stats_from_file()
        except Exception as e:
            logging.warning(f"加载统计数据文件失败，将使用初始空统计: {e}")
    
    def load_stats_from_file(self):
        """从JSON文件加载统计数据"""
        stats_file = config.stats["stats_file"]
        try:
            if os.path.exists(stats_file):
                with open(stats_file, 'r', encoding='utf-8') as f:
                    saved_stats = json.load(f)
                
                # 更新总消息数
                self.stats["total_messages"] = saved_stats.get("total_messages", 0)
                
                # 更新WS统计
                if "ws" in saved_stats:
                    self.stats["ws"]["total_success"] = saved_stats["ws"].get("total_success", 0)
                    self.stats["ws"]["total_failure"] = saved_stats["ws"].get("total_failure", 0)
                
                # 更新WH统计
                if "wh" in saved_stats:
                    self.stats["wh"]["total_success"] = saved_stats["wh"].get("total_success", 0)
                    self.stats["wh"]["total_failure"] = saved_stats["wh"].get("total_failure", 0)
                
                # 更新每个密钥的统计
                if "per_secret" in saved_stats:
                    for secret, data in saved_stats["per_secret"].items():
                        # 确保字典结构正确
                        if not isinstance(data, dict):
                            continue
                        
                        # 初始化这个密钥的统计数据
                        if secret not in self.stats["per_secret"]:
                            self.stats["per_secret"][secret] = {
                                "ws": {"success": 0, "failure": 0},
                                "wh": {"success": 0, "failure": 0}
                            }
                        
                        # 复制WS统计
                        if "ws" in data and isinstance(data["ws"], dict):
                            self.stats["per_secret"][secret]["ws"]["success"] = data["ws"].get("success", 0)
                            self.stats["per_secret"][secret]["ws"]["failure"] = data["ws"].get("failure", 0)
                        
                        # 复制WH统计
                        if "wh" in data and isinstance(data["wh"], dict):
                            self.stats["per_secret"][secret]["wh"]["success"] = data["wh"].get("success", 0)
                            self.stats["per_secret"][secret]["wh"]["failure"] = data["wh"].get("failure", 0)
                
                logging.info(f"成功从文件加载统计数据: {stats_file}")
                logging.info(f"已加载消息总数: {self.stats['total_messages']}, "
                           f"WS成功: {self.stats['ws']['total_success']}, "
                           f"WS失败: {self.stats['ws']['total_failure']}, "
                           f"WH成功: {self.stats['wh']['total_success']}, "
                           f"WH失败: {self.stats['wh']['total_failure']}")
        except Exception as e:
            logging.error(f"加载统计数据异常: {e}")
            raise
    
    def start_write_thread(self):
        """启动统计写入线程"""
        if self.write_thread is None or not self.write_thread.is_alive():
            self.stop_flag.clear()
            self.write_thread = threading.Thread(target=self._write_stats_to_file)
            self.write_thread.daemon = True
            self.write_thread.start()
            logging.info("统计信息写入线程已启动")
    
    def stop_write_thread(self):
        """停止统计写入线程"""
        if self.write_thread and self.write_thread.is_alive():
            self.stop_flag.set()
            self.write_thread.join(timeout=2)
            logging.info("统计信息写入线程已停止")
    
    def _write_stats_to_file(self):
        """写入统计信息到文件线程"""
        write_interval = config.stats["write_interval"]  # 从配置获取写入间隔
        stats_file = config.stats["stats_file"]  # 从配置获取统计文件路径
        
        while not self.stop_flag.is_set():
            try:
                # 尝试先读取现有文件数据
                existing_stats = {}
                if os.path.exists(stats_file):
                    try:
                        with open(stats_file, 'r', encoding='utf-8') as f:
                            existing_stats = json.load(f)
                    except Exception as e:
                        logging.error(f"读取现有统计文件异常: {e}")
                
                # 复制当前统计数据以避免锁争用
                with self.stats_lock:
                    # 转换defaultdict为普通dict以便JSON序列化
                    stats_copy = {
                        "total_messages": self.stats["total_messages"],
                        "ws": dict(self.stats["ws"]),
                        "wh": dict(self.stats["wh"]),
                        "per_secret": {
                            k: {
                                "ws": dict(v["ws"]),
                                "wh": dict(v["wh"])
                            } for k, v in self.stats["per_secret"].items()
                        }
                    }
                
                # 确保数据不会减少
                updated_stats = self._merge_stats(existing_stats, stats_copy)
                
                # 写入JSON文件
                with open(stats_file, 'w', encoding='utf-8') as f:
                    json.dump(updated_stats, f, indent=2, ensure_ascii=False)
                
                logging.debug(f"统计信息已写入文件: {stats_file}")
                
                # 等待下一次写入
                for _ in range(int(write_interval / 0.5)):
                    if self.stop_flag.is_set():
                        break
                    time.sleep(0.5)
                    
            except Exception as e:
                logging.error(f"统计信息写入异常: {e}")
                time.sleep(30)  # 异常后延长等待时间
    
    def _merge_stats(self, old_stats, new_stats):
        """合并统计数据，确保数值只增不减"""
        if not old_stats:
            return new_stats
        
        result = {
            "total_messages": max(old_stats.get("total_messages", 0), new_stats["total_messages"]),
            "ws": {
                "total_success": max(old_stats.get("ws", {}).get("total_success", 0), new_stats["ws"]["total_success"]),
                "total_failure": max(old_stats.get("ws", {}).get("total_failure", 0), new_stats["ws"]["total_failure"])
            },
            "wh": {
                "total_success": max(old_stats.get("wh", {}).get("total_success", 0), new_stats["wh"]["total_success"]),
                "total_failure": max(old_stats.get("wh", {}).get("total_failure", 0), new_stats["wh"]["total_failure"])
            },
            "per_secret": {}
        }
        
        # 合并所有密钥的统计
        all_secrets = set(list(old_stats.get("per_secret", {}).keys()) + list(new_stats.get("per_secret", {}).keys()))
        
        for secret in all_secrets:
            old_secret_stats = old_stats.get("per_secret", {}).get(secret, {})
            new_secret_stats = new_stats.get("per_secret", {}).get(secret, {})
            
            result["per_secret"][secret] = {
                "ws": {
                    "success": max(old_secret_stats.get("ws", {}).get("success", 0), 
                                  new_secret_stats.get("ws", {}).get("success", 0)),
                    "failure": max(old_secret_stats.get("ws", {}).get("failure", 0), 
                                  new_secret_stats.get("ws", {}).get("failure", 0))
                },
                "wh": {
                    "success": max(old_secret_stats.get("wh", {}).get("success", 0), 
                                  new_secret_stats.get("wh", {}).get("success", 0)),
                    "failure": max(old_secret_stats.get("wh", {}).get("failure", 0), 
                                  new_secret_stats.get("wh", {}).get("failure", 0))
                }
            }
        
        return result
    
    def increment_message_count(self):
        """增加消息总数"""
        with self.stats_lock:
            self.stats["total_messages"] += 1
    
    def increment_ws_stats(self, secret, success=True):
        """增加WS转发统计"""
        with self.stats_lock:
            if success:
                self.stats["ws"]["total_success"] += 1
                self.stats["per_secret"][secret]["ws"]["success"] += 1
            else:
                self.stats["ws"]["total_failure"] += 1
                self.stats["per_secret"][secret]["ws"]["failure"] += 1
    
    def increment_wh_stats(self, secret, success=True):
        """增加WH转发统计"""
        with self.stats_lock:
            if success:
                self.stats["wh"]["total_success"] += 1
                self.stats["per_secret"][secret]["wh"]["success"] += 1
            else:
                self.stats["wh"]["total_failure"] += 1
                self.stats["per_secret"][secret]["wh"]["failure"] += 1
    
    def batch_update_wh_stats(self, secret, success_count, failure_count):
        """批量更新WH转发统计"""
        with self.stats_lock:
            self.stats["wh"]["total_success"] += success_count
            self.stats["wh"]["total_failure"] += failure_count
            self.stats["per_secret"][secret]["wh"]["success"] += success_count
            self.stats["per_secret"][secret]["wh"]["failure"] += failure_count

# 创建统计管理器单例实例
stats_manager = StatsManager() 