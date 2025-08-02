from urllib.parse import urlparse
import re

class PrivacyUtils:
    """隐私保护工具类"""
    
    @staticmethod
    def sanitize_ip(ip_address):
        """对IP地址进行脱敏处理"""
        if not ip_address or ip_address == "unknown":
            return "unknown"
        
        # IPv4 处理
        if '.' in ip_address:
            parts = ip_address.split('.')
            if len(parts) == 4:
                return f"{parts[0]}.{parts[1]}.*.{parts[3]}"
        
        # IPv6 处理
        if ':' in ip_address:
            # 只保留前两段和最后一段
            parts = ip_address.split(':')
            if len(parts) >= 3:
                return f"{parts[0]}:{parts[1]}:..:{parts[-1]}"
        
        return ip_address
    
    @staticmethod
    def sanitize_path(path):
        """对URL路径进行敏感参数过滤"""
        if not path:
            return path
        
        # 处理secret参数，只显示前两位
        path = re.sub(r'(secret=)([^&]{0,2})([^&]*)', lambda m: f"{m.group(1)}{m.group(2)}***", path)
        
        # 过滤其他敏感参数
        path = re.sub(r'(token=)[^&]*', r'\1***', path)
        path = re.sub(r'(key=)[^&]*', r'\1***', path)
        path = re.sub(r'(password=)[^&]*', r'\1***', path)
        
        return path
    
    @staticmethod
    def sanitize_url(url):
        """对完整URL进行脱敏处理"""
        if not url:
            return "unknown"
        
        try:
            parsed = urlparse(url)
            sanitized_path = PrivacyUtils.sanitize_path(parsed.path)
            sanitized_query = PrivacyUtils.sanitize_path(parsed.query) if parsed.query else ""
            
            result = f"{parsed.scheme}://{parsed.netloc}{sanitized_path}"
            if sanitized_query:
                result += f"?{sanitized_query}"
                
            return result
        except:
            return "invalid_url"
    
    @staticmethod
    def sanitize_secret(secret: str) -> str:
        """
        对密钥进行脱敏处理
        
        只显示前2位，其余用***替代
        """
        if not secret:
            return "******"
            
        if len(secret) <= 2:
            return "******"
            
        prefix = secret[:2]
        return f"{prefix}***"

    @staticmethod
    def sanitize_logs(log_message: str) -> str:
        """
        对日志消息中的敏感信息进行脱敏
        
        目前处理：
        - API密钥 (sk-...)
        """
        # 这里可以添加更复杂的正则表达式匹配逻辑
        import re
        
        # 匹配常见API密钥格式并脱敏
        # 例如：sk-1234567890abcdef1234567890abcdef
        patterns = [
            (r'sk-[a-zA-Z0-9]{30,}', 'sk-***********'),
            (r'Bearer\s+[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+', 'Bearer ********') # JWT格式
        ]
        
        result = log_message
        for pattern, replacement in patterns:
            result = re.sub(pattern, replacement, result)
            
        return result 