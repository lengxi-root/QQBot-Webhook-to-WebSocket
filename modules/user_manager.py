import hashlib
import json
import logging
import os
import threading
import time
from typing import Dict, List, Optional, Tuple

class AppIdManager:
    
    def __init__(self):
        self.appids_file = "data/appids.json"
        self.appids = {}
        self.lock = threading.RLock()
        os.makedirs("data", exist_ok=True)
        self._load_data()
    
    def _load_data(self):
        with self.lock:
            try:
                if os.path.exists(self.appids_file):
                    with open(self.appids_file, 'r', encoding='utf-8') as f:
                        self.appids = json.load(f)
                    logging.info(f"已加载 {len(self.appids)} 个AppID映射")
                else:
                    self.appids = {}
                return True
            except Exception as e:
                logging.error(f"加载AppID数据出错: {str(e)}")
                if os.path.exists(self.appids_file):
                    backup_file = f"{self.appids_file}.{time.strftime('%Y%m%d_%H%M%S')}.bak"
                    try:
                        os.rename(self.appids_file, backup_file)
                        logging.warning(f"已备份损坏的文件: {backup_file}")
                    except:
                        pass
                self.appids = {}
                return False
    
    def _save_data(self):
        with self.lock:
            try:
                with open(self.appids_file, 'w', encoding='utf-8') as f:
                    json.dump(self.appids, f, ensure_ascii=False, indent=2)
                return True
            except Exception as e:
                logging.error(f"保存AppID数据失败: {str(e)}")
                return False
    
    def create_appid(self, appid: str, secret: str, description: str = "") -> Tuple[bool, str]:
        appid = appid.strip()
        secret = secret.strip()
        description = description.strip()
        
        if not appid or not secret or len(secret) < 10:
            return False, "invalid"
            
        with self.lock:
            if appid in self.appids:
                self.appids[appid] = {
                    'secret': secret,
                    'description': description,
                    'create_time': self.appids[appid].get('create_time', time.time())
                }
                return (True, "updated") if self._save_data() else (False, "failed")
            else:
                self.appids[appid] = {
                    'secret': secret,
                    'description': description,
                    'create_time': time.time()
                }
                return (True, "success") if self._save_data() else (False, "failed")
    
    def get_secret_by_appid(self, appid: str) -> Optional[str]:
        with self.lock:
            return self.appids.get(appid, {}).get('secret')
    
    def get_all_appids(self) -> List[Dict]:
        with self.lock:
            return [
                {
                    'appid': appid,
                    'secret': data.get('secret', ''),
                    'description': data.get('description', ''),
                    'create_time': data.get('create_time', 0)
                }
                for appid, data in self.appids.items()
            ]
    
    def delete_appid(self, appid: str) -> bool:
        with self.lock:
            if appid not in self.appids:
                return False
            del self.appids[appid]
            self._save_data()
            return True
    
    def verify_signature(self, appid: str, signature: str, timestamp: str, nonce: str) -> bool:
        secret = self.get_secret_by_appid(appid)
        if not secret:
            return False
        raw_str = secret + timestamp + nonce
        expected_signature = hashlib.sha1(raw_str.encode('utf-8')).hexdigest()
        return signature == expected_signature

app_id_manager = AppIdManager()
