import logging
from cryptography.hazmat.primitives.asymmetric import ed25519
import config

def setup_logger():
    log_level = getattr(logging, config.log_level, logging.INFO)
    
    class NoRootFilter(logging.Filter):
        def filter(self, record):
            if record.name == 'root':
                record.name = ''
            return True
    
    class MessageFilter(logging.Filter):
        def filter(self, record):
            message = record.getMessage()
            filters = [
                '{"op":1,"d":1}',
                "{'op': 1, 'd': 1}",
                "收到原始消息:",
                "b'{",
                "添加消息ID到缓存",
                "统计信息已写入文件:",
                "Webhook转发跳过",
                "转发消息内容:",
                "INFO::转发消息内容:",
                "收到WS消息:",
                "INFO::收到WS消息:",
                "解析WS消息:",
                "INFO::解析WS消息:",
                "connection rejected (403 Forbidden)",
            ]
            
            for f in filters:
                if f in message:
                    return False
            
            if "Webhook转发全部失败" in message and "失败数：0/0" in message:
                return False
            if "connection closed" in message and record.levelname == "INFO":
                return False
            if "WebSocket" in message and "403" in message:
                return False
                
            return True
    
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        handlers=[logging.StreamHandler()]
    )
    
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('uvicorn.error').setLevel(logging.INFO)
    
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    
    for handler in root_logger.handlers:
        handler.addFilter(NoRootFilter())
        handler.addFilter(MessageFilter())
    
    return root_logger

def generate_signature(bot_secret, event_ts, plain_token):
    while len(bot_secret) < 32:
        bot_secret = (bot_secret + bot_secret)[:32]

    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(bot_secret.encode())
    message = f"{event_ts}{plain_token}".encode()
    signature = private_key.sign(message).hex()

    return {
        "plain_token": plain_token,
        "signature": signature
    }
