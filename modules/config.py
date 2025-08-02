import os
import json
import logging
import sys
from typing import Dict, List, Any

class Config:
    """配置管理类，从JSON文件读取所有配置"""
    
    def __init__(self, config_file=None):
        """
        初始化配置管理器
        
        参数:
            config_file: 可选，配置文件路径，如果不提供则从环境变量或默认路径读取
        """
        # 确定配置文件路径
        self.CONFIG_FILE = config_file or os.environ.get('CONFIG_FILE') or 'config.json'
        
        # 检查配置文件是否存在
        if not os.path.exists(self.CONFIG_FILE):
            logging.error(f"配置文件 {self.CONFIG_FILE} 不存在")
            print(f"错误: 配置文件 {self.CONFIG_FILE} 不存在，请先创建配置文件")
            sys.exit(1)
            
        # 加载配置
        self._load_from_file()
        
        # 初始化黑名单配置，如果不存在
        if not hasattr(self, 'blacklist'):
            self.blacklist = {
                'secrets': [],  # 被拉黑的密钥列表
                'enabled': True  # 是否启用黑名单功能
            }
    
    def _load_from_file(self):
        """从配置文件加载配置"""
        try:
            with open(self.CONFIG_FILE, 'r', encoding='utf-8') as f:
                config_data = json.load(f)
            
            # 更新对象属性
            for key, value in config_data.items():
                setattr(self, key, value)
                
            logging.info(f"从 {self.CONFIG_FILE} 加载配置成功")
        except json.JSONDecodeError:
            logging.error(f"配置文件 {self.CONFIG_FILE} 格式错误，请检查JSON格式")
            print(f"错误: 配置文件 {self.CONFIG_FILE} 格式错误，请检查JSON格式")
            sys.exit(1)
        except Exception as e:
            logging.error(f"加载配置文件失败: {str(e)}")
            print(f"错误: 加载配置文件失败: {str(e)}")
            sys.exit(1)

    def _save_to_file(self):
        """保存配置到文件"""
        try:
            # 将当前配置转换为字典
            config_dict = {}
            for key in dir(self):
                # 跳过内置属性和方法
                if key.startswith('_'):
                    continue
                    
                value = getattr(self, key)
                # 只保存非函数属性
                if not callable(value):
                    config_dict[key] = value
            
            # 写入文件
            with open(self.CONFIG_FILE, 'w', encoding='utf-8') as f:
                json.dump(config_dict, f, ensure_ascii=False, indent=4)
                
            logging.info(f"配置已保存到 {self.CONFIG_FILE}")
            return True
        except Exception as e:
            logging.error(f"保存配置文件失败: {str(e)}")
            return False
    
    def reload(self):
        """重新加载配置"""
        self._load_from_file()
        return True
        
    def update_settings(self, settings: Dict[str, Any]):
        """更新系统设置"""
        for key, value in settings.items():
            if hasattr(self, key):
                setattr(self, key, value)
        
        # 保存到文件
        return self._save_to_file()
    
    def update_blacklist(self, blacklist_data: Dict[str, Any]):
        """更新黑名单设置
        
        Args:
            blacklist_data: 黑名单设置字典
            
        Returns:
            bool: 是否更新成功
        """
        try:
            # 确保blacklist属性存在
            if not hasattr(self, 'blacklist'):
                self.blacklist = {
                    'secrets': [],
                    'enabled': True
                }
                
            # 更新黑名单配置
            if 'secrets' in blacklist_data:
                self.blacklist['secrets'] = blacklist_data['secrets']
            if 'enabled' in blacklist_data:
                self.blacklist['enabled'] = blacklist_data['enabled']
                
            # 保存配置
            self._save_to_file()
            
            logging.info("黑名单配置已更新")
            return True
        except Exception as e:
            logging.error(f"更新黑名单配置失败: {str(e)}")
            return False
    
    def is_secret_blacklisted(self, secret: str) -> bool:
        """检查密钥是否在黑名单中
        
        Args:
            secret: 要检查的密钥
            
        Returns:
            bool: 是否在黑名单中
        """
        if not hasattr(self, 'blacklist') or not self.blacklist.get('enabled', True):
            return False
            
        return secret in self.blacklist.get('secrets', [])

# 单例实例
config = Config() 