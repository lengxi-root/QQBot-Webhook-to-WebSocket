import re
from urllib.parse import urlparse

class PrivacyUtils:
    
    @staticmethod
    def sanitize_ip(ip_address):
        if not ip_address or ip_address == "unknown":
            return "unknown"
        
        if '.' in ip_address:
            parts = ip_address.split('.')
            if len(parts) == 4:
                return f"{parts[0]}.{parts[1]}.*.{parts[3]}"
        
        if ':' in ip_address:
            parts = ip_address.split(':')
            if len(parts) >= 3:
                return f"{parts[0]}:{parts[1]}:..:{parts[-1]}"
        
        return ip_address
    
    @staticmethod
    def sanitize_path(path):
        if not path:
            return path
        
        path = re.sub(r'(secret=)([^&]{0,2})([^&]*)', lambda m: f"{m.group(1)}{m.group(2)}***", path)
        path = re.sub(r'(token=)[^&]*', r'\1***', path)
        path = re.sub(r'(key=)[^&]*', r'\1***', path)
        path = re.sub(r'(password=)[^&]*', r'\1***', path)
        
        return path
    
    @staticmethod
    def sanitize_url(url):
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
        if not secret or len(secret) <= 2:
            return "******"
        return f"{secret[:2]}***"

    @staticmethod
    def sanitize_logs(log_message: str) -> str:
        patterns = [
            (r'sk-[a-zA-Z0-9]{30,}', 'sk-***********'),
            (r'Bearer\s+[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+', 'Bearer ********')
        ]
        
        result = log_message
        for pattern, replacement in patterns:
            result = re.sub(pattern, replacement, result)
            
        return result
