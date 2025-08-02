"""
AppID管理模块
处理AppID和密钥映射功能
"""

import json
import os
import time
import random
import string
import hashlib
import logging
from typing import Dict, List, Optional, Tuple
import threading

class AppIdManager:
    """AppID管理类"""
    
    def __init__(self):
        self.appids_file = "data/appids.json"
        self.appids = {}  # AppID映射: {appid: {secret, create_time, description}}
        self.lock = threading.RLock()
        
        # 确保数据目录存在
        os.makedirs("data", exist_ok=True)
        
        # 加载数据
        self._load_data()
    
    def _load_data(self):
        """加载AppID数据"""
        with self.lock:
            try:
                # 确保数据目录存在
                os.makedirs("data", exist_ok=True)
                
                # 加载AppID数据
                if os.path.exists(self.appids_file):
                    with open(self.appids_file, 'r', encoding='utf-8') as f:
                        self.appids = json.load(f)
                    
                    logging.info(f"已加载 {len(self.appids)} 个AppID映射")
                else:
                    logging.warning(f"AppID数据文件不存在: {self.appids_file}")
                    self.appids = {}
                
                return True
            except json.JSONDecodeError as e:
                logging.error(f"加载AppID数据出错: JSON解析失败 - {str(e)}")
                # 如果数据文件损坏，创建备份并使用空数据
                self._backup_corrupted_files()
                self.appids = {}
                return False
            except PermissionError:
                logging.error("加载AppID数据出错: 权限不足，无法读取文件")
                self.appids = {}
                return False
            except Exception as e:
                logging.error(f"加载AppID数据出错: {str(e)}", exc_info=True)
                self.appids = {}
                return False
    
    def _backup_corrupted_files(self):
        """备份损坏的数据文件"""
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        try:
            # 备份AppID数据文件
            if os.path.exists(self.appids_file):
                backup_file = f"{self.appids_file}.{timestamp}.bak"
                os.rename(self.appids_file, backup_file)
                logging.warning(f"已备份损坏的AppID数据文件: {backup_file}")
        except Exception as e:
            logging.error(f"备份损坏的数据文件失败: {str(e)}")
    
    def _save_data(self):
        """保存AppID数据"""
        with self.lock:
            try:
                # 确保数据目录存在
                os.makedirs("data", exist_ok=True)
                
                # 保存AppID数据
                with open(self.appids_file, 'w', encoding='utf-8') as f:
                    json.dump(self.appids, f, ensure_ascii=False, indent=2)
                
                logging.debug("AppID数据保存成功")
                return True
            except PermissionError:
                logging.error("保存AppID数据失败: 权限不足，无法写入文件")
                return False
            except IOError as e:
                logging.error(f"保存AppID数据失败: 文件I/O错误 - {str(e)}")
                return False
            except Exception as e:
                logging.error(f"保存AppID数据失败: {str(e)}", exc_info=True)
                return False
    
    def create_appid(self, appid: str, secret: str, description: str = "") -> Tuple[bool, str]:
        """
        创建或更新AppID映射
        
        返回值: (成功状态, 状态消息)
        状态消息说明:
        - success: 成功创建
        - updated: 更新已存在的AppID
        - invalid: 无效的输入
        - failed: 其他失败情况
        """
        # 输入验证和净化
        appid = appid.strip()
        secret = secret.strip()
        description = description.strip()
        
        if not appid or not secret or len(secret) < 10:
            return False, "invalid"
            
        with self.lock:
            # 检查AppID是否已存在
            if appid in self.appids:
                # 更新现有AppID
                self.appids[appid] = {
                    'secret': secret,
                    'description': description,
                    'create_time': self.appids[appid].get('create_time', time.time())
                }
                
                # 保存数据
                if not self._save_data():
                    return False, "failed"
                
                return True, "updated"
            else:
                # 创建新AppID
                self.appids[appid] = {
                    'secret': secret,
                    'description': description,
                    'create_time': time.time()
                }
                
                # 保存数据
                if not self._save_data():
                    return False, "failed"
                
                return True, "success"
    
    def get_secret_by_appid(self, appid: str) -> Optional[str]:
        """根据AppID获取密钥"""
        with self.lock:
            if appid in self.appids:
                return self.appids[appid].get('secret')
            return None
    
    def get_all_appids(self) -> List[Dict]:
        """获取所有AppID信息"""
        with self.lock:
            result = []
            for appid, data in self.appids.items():
                result.append({
                    'appid': appid,
                    'secret': data.get('secret', ''),
                    'description': data.get('description', ''),
                    'create_time': data.get('create_time', 0)
                })
            return result
    
    def delete_appid(self, appid: str) -> bool:
        """删除AppID"""
        with self.lock:
            if appid not in self.appids:
                return False
            
            # 删除AppID
            del self.appids[appid]
            
            # 保存数据
            self._save_data()
            return True
    
    def verify_signature(self, appid: str, signature: str, timestamp: str, nonce: str) -> bool:
        """验证签名
        
        签名算法: sha1(secret + timestamp + nonce)
        """
        secret = self.get_secret_by_appid(appid)
        if not secret:
            return False
        
        # 计算签名
        raw_str = secret + timestamp + nonce
        expected_signature = hashlib.sha1(raw_str.encode('utf-8')).hexdigest()
        
        return signature == expected_signature

# 创建AppID管理器单例实例
app_id_manager = AppIdManager() 