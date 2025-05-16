from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime

# 创建数据库引擎
engine = create_engine('sqlite:///stats.db', echo=False)
Base = declarative_base()

# 定义统计表
class WebhookStats(Base):
    __tablename__ = 'webhook_stats'
    
    id = Column(Integer, primary_key=True)
    secret = Column(String(50), index=True)
    url = Column(String(255))
    count = Column(Integer, default=0)
    total_bytes = Column(Integer, default=0)
    last_updated = Column(DateTime, default=datetime.now)

# 定义连接统计表
class ConnectionStats(Base):
    __tablename__ = 'connection_stats'
    
    id = Column(Integer, primary_key=True)
    secret = Column(String(50), index=True)
    history_connections = Column(Integer, default=0)
    is_active = Column(Integer, default=0)  # 0: 非活跃, 1: 活跃
    last_updated = Column(DateTime, default=datetime.now)

# 创建所有表
Base.metadata.create_all(engine)

# 创建会话工厂
Session = sessionmaker(bind=engine)

def get_session():
    return Session() 