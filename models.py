from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import declarative_base, mapped_column
from sqlalchemy import Column, Integer, String, Float, DateTime, Text
from datetime import datetime
import asyncio

# 创建异步数据库引擎
engine = create_async_engine('sqlite+aiosqlite:///stats.db', echo=False)
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

# 异步创建所有表
async def create_tables():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

# 创建异步会话工厂
async_session = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

async def get_session():
    return async_session()

# 确保数据库表已创建
async def ensure_tables():
    try:
        async with engine.begin() as conn:
            # 检查表是否存在
            tables_exist = await conn.run_sync(
                lambda sync_conn: sync_conn.dialect.has_table(sync_conn, WebhookStats.__tablename__)
            )
            if not tables_exist:
                await conn.run_sync(Base.metadata.create_all)
    except Exception as e:
        print(f"确保数据库表创建时出错: {e}")

# 不要在模块级别调用异步函数
# asyncio.create_task(ensure_tables()) 