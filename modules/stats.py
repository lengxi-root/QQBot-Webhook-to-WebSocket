import json
import logging
import os
import threading
import time
from collections import defaultdict

import config

class StatsManager:
    
    def __init__(self):
        self.stats = {
            "total_messages": 0,
            "ws": {"total_success": 0, "total_failure": 0},
            "wh": {"total_success": 0, "total_failure": 0},
            "per_secret": defaultdict(lambda: {
                "ws": {"success": 0, "failure": 0},
                "wh": {"success": 0, "failure": 0}
            })
        }
        self.stats_lock = threading.Lock()
        self.write_thread = None
        self.stop_flag = threading.Event()
        
        try:
            self.load_stats_from_file()
        except Exception as e:
            logging.warning(f"加载统计数据失败: {e}")
    
    def load_stats_from_file(self):
        stats_file = config.stats["stats_file"]
        if not os.path.exists(stats_file):
            return
            
        try:
            with open(stats_file, 'r', encoding='utf-8') as f:
                saved = json.load(f)
            
            self.stats["total_messages"] = saved.get("total_messages", 0)
            
            if "ws" in saved:
                self.stats["ws"].update(saved["ws"])
            if "wh" in saved:
                self.stats["wh"].update(saved["wh"])
            
            if "per_secret" in saved:
                for secret, data in saved["per_secret"].items():
                    if isinstance(data, dict):
                        if secret not in self.stats["per_secret"]:
                            self.stats["per_secret"][secret] = {
                                "ws": {"success": 0, "failure": 0},
                                "wh": {"success": 0, "failure": 0}
                            }
                        if "ws" in data:
                            self.stats["per_secret"][secret]["ws"].update(data["ws"])
                        if "wh" in data:
                            self.stats["per_secret"][secret]["wh"].update(data["wh"])
            
            logging.info(f"已加载统计: 总消息{self.stats['total_messages']}, "
                       f"WS {self.stats['ws']['total_success']}/{self.stats['ws']['total_failure']}, "
                       f"WH {self.stats['wh']['total_success']}/{self.stats['wh']['total_failure']}")
        except Exception as e:
            logging.error(f"加载统计数据异常: {e}")
            raise
    
    def start_write_thread(self):
        if self.write_thread is None or not self.write_thread.is_alive():
            self.stop_flag.clear()
            self.write_thread = threading.Thread(target=self._write_stats_to_file)
            self.write_thread.daemon = True
            self.write_thread.start()
            logging.info("统计写入线程已启动")
    
    def stop_write_thread(self):
        if self.write_thread and self.write_thread.is_alive():
            self.stop_flag.set()
            self.write_thread.join(timeout=2)
            logging.info("统计写入线程已停止")
    
    def _write_stats_to_file(self):
        write_interval = config.stats["write_interval"]
        stats_file = config.stats["stats_file"]
        
        while not self.stop_flag.is_set():
            try:
                existing = {}
                if os.path.exists(stats_file):
                    try:
                        with open(stats_file, 'r', encoding='utf-8') as f:
                            existing = json.load(f)
                    except:
                        pass
                
                with self.stats_lock:
                    # 清理无活动的secret统计（超过1000个时，只保留最近活跃的500个）
                    if len(self.stats["per_secret"]) > 1000:
                        # 计算每个secret的总活动数
                        secret_activity = {}
                        for secret, data in self.stats["per_secret"].items():
                            total = (data["ws"]["success"] + data["ws"]["failure"] + 
                                   data["wh"]["success"] + data["wh"]["failure"])
                            secret_activity[secret] = total
                        
                        # 按活跃度排序，只保留前500个
                        sorted_secrets = sorted(secret_activity.items(), key=lambda x: x[1], reverse=True)
                        secrets_to_keep = set(s for s, _ in sorted_secrets[:500])
                        
                        # 删除不活跃的secret
                        secrets_to_remove = [s for s in self.stats["per_secret"].keys() if s not in secrets_to_keep]
                        for secret in secrets_to_remove:
                            del self.stats["per_secret"][secret]
                        
                        logging.warning(f"清理统计数据：删除{len(secrets_to_remove)}个不活跃的secret统计")
                    
                    current = {
                        "total_messages": self.stats["total_messages"],
                        "ws": dict(self.stats["ws"]),
                        "wh": dict(self.stats["wh"]),
                        "per_secret": {
                            k: {"ws": dict(v["ws"]), "wh": dict(v["wh"])}
                            for k, v in self.stats["per_secret"].items()
                        }
                    }
                
                merged = self._merge_stats(existing, current)
                
                with open(stats_file, 'w', encoding='utf-8') as f:
                    json.dump(merged, f, indent=2, ensure_ascii=False)
                
                for _ in range(int(write_interval / 0.5)):
                    if self.stop_flag.is_set():
                        break
                    time.sleep(0.5)
                    
            except Exception as e:
                logging.error(f"写入统计异常: {e}")
                time.sleep(30)
    
    def _merge_stats(self, old, new):
        if not old:
            return new
        
        result = {
            "total_messages": max(old.get("total_messages", 0), new["total_messages"]),
            "ws": {
                "total_success": max(old.get("ws", {}).get("total_success", 0), new["ws"]["total_success"]),
                "total_failure": max(old.get("ws", {}).get("total_failure", 0), new["ws"]["total_failure"])
            },
            "wh": {
                "total_success": max(old.get("wh", {}).get("total_success", 0), new["wh"]["total_success"]),
                "total_failure": max(old.get("wh", {}).get("total_failure", 0), new["wh"]["total_failure"])
            },
            "per_secret": {}
        }
        
        all_secrets = set(list(old.get("per_secret", {}).keys()) + list(new.get("per_secret", {}).keys()))
        
        for secret in all_secrets:
            old_data = old.get("per_secret", {}).get(secret, {})
            new_data = new.get("per_secret", {}).get(secret, {})
            
            result["per_secret"][secret] = {
                "ws": {
                    "success": max(old_data.get("ws", {}).get("success", 0), 
                                  new_data.get("ws", {}).get("success", 0)),
                    "failure": max(old_data.get("ws", {}).get("failure", 0), 
                                  new_data.get("ws", {}).get("failure", 0))
                },
                "wh": {
                    "success": max(old_data.get("wh", {}).get("success", 0), 
                                  new_data.get("wh", {}).get("success", 0)),
                    "failure": max(old_data.get("wh", {}).get("failure", 0), 
                                  new_data.get("wh", {}).get("failure", 0))
                }
            }
        
        return result
    
    def increment_message_count(self):
        with self.stats_lock:
            self.stats["total_messages"] += 1
    
    def increment_ws_stats(self, secret, success=True):
        with self.stats_lock:
            if success:
                self.stats["ws"]["total_success"] += 1
                self.stats["per_secret"][secret]["ws"]["success"] += 1
            else:
                self.stats["ws"]["total_failure"] += 1
                self.stats["per_secret"][secret]["ws"]["failure"] += 1
    
    def increment_wh_stats(self, secret, success=True):
        with self.stats_lock:
            if success:
                self.stats["wh"]["total_success"] += 1
                self.stats["per_secret"][secret]["wh"]["success"] += 1
            else:
                self.stats["wh"]["total_failure"] += 1
                self.stats["per_secret"][secret]["wh"]["failure"] += 1
    
    def batch_update_wh_stats(self, secret, success_count, failure_count):
        with self.stats_lock:
            self.stats["wh"]["total_success"] += success_count
            self.stats["wh"]["total_failure"] += failure_count
            self.stats["per_secret"][secret]["wh"]["success"] += success_count
            self.stats["per_secret"][secret]["wh"]["failure"] += failure_count

stats_manager = StatsManager()
