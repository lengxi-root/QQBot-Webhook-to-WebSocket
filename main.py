"""
Webhook to WebSocket代理服务
用于将webhook消息转发到websocket连接
"""

from fastapi import FastAPI, Request, Header, WebSocket, WebSocketDisconnect, Depends, HTTPException, status, Form, Cookie, Response, Query
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm, OAuth2
from pydantic import BaseModel, Field, validator, field_validator, ValidationError
from contextlib import asynccontextmanager

# 添加安全相关的模型，用于验证输入数据
class SystemSettings(BaseModel):
    log_level: str = Field(..., pattern='^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$')
    deduplication_ttl: int = Field(..., ge=0, le=3600)
    raw_content: dict = Field(default_factory=dict)

import asyncio
import logging
import os
import time
import sys
import json
from collections import deque
from typing import Optional, Dict, List, Any
from urllib.parse import urlparse
import jwt  # Using jwt package instead of pyjwt
from datetime import datetime, timedelta, timezone
import secrets
import re
import hashlib
import uuid
import copy

# 允许的HTML标签和属性，用于HTML清理
ALLOWED_HTML_TAGS = ['h1', 'h2', 'h3', 'p', 'br', 'strong', 'em', 'u', 'ol', 'ul', 'li', 'a', 'span', 'div']
ALLOWED_HTML_ATTRIBUTES = {
    'a': ['href', 'title'],
    'span': ['style'],
    'div': ['style'],
}

# 添加当前目录到路径
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

# 导入JSON库
try:
    import orjson
    json_module = orjson
    JSONDecodeError = orjson.JSONDecodeError
except ImportError:
    import json
    json_module = json
    JSONDecodeError = json.JSONDecodeError

# 从模块导入功能组件
from modules.config import config
from modules.monitoring import watch_config, log_config_changes, monitor_service_health
from modules.stats import stats_manager
from modules.user_manager import app_id_manager
from modules.privacy import PrivacyUtils
from modules.cache import cache_manager
from modules.utils import setup_logger, generate_signature
from modules.connections import (
    active_connections, send_to_all, handle_ws_message,
    forward_webhook, send_heartbeat, resend_token_cache, 
    resend_public_cache, service_health
)

# 设置日志
logger = setup_logger()
# 确保日志级别正确
logging.getLogger().setLevel(logging.INFO)

# JWT相关配置
JWT_SECRET = os.environ.get("JWT_SECRET", secrets.token_hex(32))  # 使用环境变量或生成随机密钥
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = 60 * 24 * 7  # 7天

# Cookie配置
COOKIE_NAME = "wh_access_token"
TEMP_COOKIE_NAME = "wh_temp_session"
COOKIE_MAX_AGE = 60 * 60 * 24 * 7  # 7天，以秒为单位
TEMP_COOKIE_MAX_AGE = 60 * 60 * 3  # 3小时，以秒为单位

# 安全配置
# 删除csrf_tokens = {}  # 用于存储CSRF令牌

# 请求体模型
class Payload(BaseModel):
    d: dict

# 用户相关模型



class Token(BaseModel):
    access_token: str
    token_type: str

class AppIdCreate(BaseModel):
    appid: str
    secret: str
    description: str = ""

class AppIdResponse(BaseModel):
    appid: str
    secret: str
    description: str
    create_time: float
    status: str



# 创建OAuth2密码流（对于API用）
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# 安全相关函数
# 删除generate_csrf_token函数

# JWT相关函数
def create_access_token(data: dict):
    to_encode = data.copy()
    expires = datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRE_MINUTES)
    to_encode.update({"exp": expires, "iat": datetime.now(timezone.utc)})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return encoded_jwt

def verify_token(token: str) -> Optional[str]:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        username = payload.get("sub")
        if username is None:
            return None
        return username
    except Exception as e:
        # Handle JWT exceptions as a general exception
        if 'jwt' in str(e).lower():
            logging.warning(f"JWT verification failed: {str(e)}")
        return None

# 用户认证依赖项
async def get_current_user_from_token(token: str = Depends(oauth2_scheme)) -> str:
    """从Bearer令牌获取当前用户（API使用）"""
    username = verify_token(token)
    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="无效的身份验证凭据",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return username

async def get_current_user_from_cookie(request: Request) -> Optional[str]:
    """从Cookie获取当前用户（网页使用）"""
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return None
    return verify_token(token)

async def get_current_user(
    request: Request,
    token: str = Depends(oauth2_scheme)
) -> str:
    """综合Cookie和Bearer令牌获取当前用户"""
    # 先尝试从Bearer令牌获取
    try:
        return await get_current_user_from_token(token)
    except Exception as e:
        # 如果失败，尝试从Cookie获取
        username = await get_current_user_from_cookie(request)
        if not username:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="未登录或会话已过期",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return username

# 管理员身份验证
async def get_current_admin(request: Request = None, token: str = Depends(oauth2_scheme)) -> str:
    """验证管理员身份"""
    # 先尝试从Bearer令牌获取
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        username = payload.get("sub")
        is_admin = payload.get("is_admin", False)
        
        if not username or not is_admin:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="无效的管理员凭据",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # 管理员用户名固定为admin，无需验证配置中的用户名
        if username != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="无管理员权限",
            )
            
        return username
    except Exception as e:
        # 如果从请求中获取，也要检查是否为管理员
        if request:
            token = request.cookies.get(COOKIE_NAME)
            if token:
                try:
                    payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
                    username = payload.get("sub")
                    is_admin = payload.get("is_admin", False)
                    
                    if username and is_admin and username == "admin":
                        return username
                except Exception:
                    logging.warning("从cookie解析管理员令牌失败")
                    pass
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="需要管理员权限",
            headers={"WWW-Authenticate": "Bearer"},
        )

@asynccontextmanager
async def lifespan(app: FastAPI):
    """应用生命周期管理"""
    # 启动配置监控任务
    config_task = asyncio.create_task(watch_config())
    # 启动健康监控任务
    health_task = asyncio.create_task(monitor_service_health())
    # 启动缓存清理线程
    cache_manager.start_cleaning_thread()
    # 启动统计信息写入线程
    stats_manager.start_write_thread()

    logger.info(f"服务已启动 - 监听端口: {config.port}")

    yield

    # 清理资源
    config_task.cancel()
    health_task.cancel()
    # 停止缓存清理线程
    cache_manager.stop_cleaning_thread()
    # 停止统计信息写入线程
    stats_manager.stop_write_thread()

    try:
        await config_task
        await health_task
    except asyncio.CancelledError:
        pass
    logger.info("服务已停止")


app = FastAPI(
    lifespan=lifespan,
    # 设置日志级别为INFO，以便显示WebSocket连接和消息转发日志
    log_level="info"
)

# 跨域配置
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 确保web目录存在
os.makedirs("web", exist_ok=True)
os.makedirs("web/js", exist_ok=True)
os.makedirs("web/css", exist_ok=True)

# 提供静态文件服务
app.mount("/static", StaticFiles(directory="web"), name="static") 

# 用户面板路由
@app.get("/console", response_class=HTMLResponse)
async def user_console(request: Request):
    """返回用户面板HTML页面 - 重定向至新的统一控制台"""
    # 检查用户是否已登录
    username = await get_current_user_from_cookie(request)
    if not username:
        # 用户未登录，重定向到统一登录页
        return RedirectResponse(url="/login")
    
    # 已登录用户重定向到控制台
    return FileResponse("web/console.html")

# 管理员面板路由
@app.get("/admin", response_class=HTMLResponse)
async def admin_panel(request: Request):
    """返回管理员面板HTML页面 - 重定向至新的统一控制台"""
    if not config.admin.get("enabled", True):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="管理员功能已禁用"
        )
    
    # 检查管理员是否已登录
    try:
        admin = await get_current_admin(request)
        # 已登录管理员重定向到控制台
        return RedirectResponse(url="/console")
    except HTTPException:
        # 管理员未登录，重定向到登录页面（包含token）
        return RedirectResponse(url=f"/login?token={config.access_token}")

# 重定向根目录到登录页面
@app.get("/", response_class=HTMLResponse)
async def root_redirect():
    """主页重定向到管理员登录页面"""
    return RedirectResponse(url=f"/login?token={config.access_token}")

# 新的统一登录/注册页面
@app.get("/login", response_class=HTMLResponse)
async def unified_login_page(request: Request, token: str = Query(None)):
    """返回统一登录和注册页面，需要token验证"""
    # 二层验证：检查访问token
    if not token or token != config.access_token:
        return Response(status_code=403)
    
    # 检查用户是否已登录
    username = await get_current_user_from_cookie(request)
    if username:
        # 检查是否来自console页面的重定向，避免循环重定向
        referer = request.headers.get("referer", "")
        if "/console" in referer:
            # 来自控制台的请求，直接返回登录页面而不是重定向
            return FileResponse("web/login.html")
        # 用户已登录，重定向到控制台
        return RedirectResponse(url="/console")
    
    # 直接返回登录页面
    return FileResponse("web/login.html")

# 获取临时会话
def get_temp_session_id(request: Request) -> str:
    """获取临时会话ID"""
    # 从cookie中获取会话ID（优先使用新的wh_temp_session，兼容旧的session_id）
    session_id = request.cookies.get(TEMP_COOKIE_NAME) or request.cookies.get("session_id")
    
    # 如果用户已登录，使用特殊会话ID
    if not session_id and request.cookies.get(COOKIE_NAME):
        logging.debug("用户已登录，使用特殊临时会话ID")
        return "logged_in_user"
    
    # 如果没有会话ID，生成一个简单的随机ID
    if not session_id:
        import secrets
        session_id = secrets.token_hex(16)
    
    return session_id

# 发送验证码API
# 已删除 - 邮箱验证码功能不再提供
    """发送验证码"""
    return JSONResponse({
        "status": "error",
        "message": "邮箱验证码功能已被移除"
    }, status_code=410)

# 已删除 - 用户注册功能不再提供
    """用户注册处理"""
    return JSONResponse({
        "status": "error",
        "message": "注册功能已被移除"
    }, status_code=403)


    """
    用户登录API
    使用表单数据进行登录验证，成功后返回访问令牌并设置cookie
    """
    try:
        username = form_data.username
        password = form_data.password
        
        logging.info(f"用户尝试登录: {username}")
        
        # 验证用户凭据
        if not app_id_manager.authenticate(username, password):
            logging.warning(f"登录失败: {username} - 用户名或密码错误")
            return JSONResponse(
                status_code=401,
                content={"detail": "用户名或密码错误"}
            )
        
        # 生成访问令牌
        access_token = create_access_token(data={"sub": username})
        
        # 设置cookie - 默认启用"记住我"功能
        response.set_cookie(
            key=COOKIE_NAME,
            value=access_token,
            httponly=True,
            max_age=COOKIE_MAX_AGE,  # 7天有效期
            samesite="lax"  # 添加SameSite属性
        )
        
        logging.info(f"用户登录成功: {username}")
        # 返回令牌
        return {"access_token": access_token, "token_type": "bearer"}
        
    except Exception as e:
        logging.error(f"登录处理过程发生错误: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="服务器内部错误，请稍后重试"
        )


    """
    用户注销API
    清除用户session和cookie
    """
    try:
        # 清除访问令牌cookie
        response.delete_cookie(key=COOKIE_NAME)
    
        # 清除临时会话cookie（如果有）
        response.delete_cookie(key=TEMP_COOKIE_NAME)
        
        # 清除旧的session_id（如果有）
        response.delete_cookie(key="session_id")
    
        return {"status": "success", "message": "已成功注销"}
        
    except Exception as e:
        logging.error(f"注销处理过程发生错误: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={"status": "error", "message": "注销失败，请稍后重试"}
        )

# 管理员登录API
@app.post("/api/admin/login")
async def admin_login(response: Response, admin_data: Dict[str, Any]):
    """管理员登录
    
    只需要验证密码，无需用户名
    """
    try:
        # 记录登录尝试
        logging.info("管理员登录尝试")
        
        # 验证请求数据
        if not isinstance(admin_data, dict):
            logging.error("管理员登录错误: 无效的请求数据格式")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="无效的请求数据格式"
            )
        
        password = admin_data.get("password", "")
    
        # 验证管理员密码
        stored_password = config.admin.get("password")
        if not stored_password or stored_password != password:
            logging.warning("管理员登录失败: 密码错误")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="管理员密码错误"
            )
    
        # 生成访问令牌，包含管理员标记（固定用户名为admin）
        access_token = create_access_token(data={"sub": "admin", "is_admin": True})
        logging.info("管理员登录成功")
    
        # 设置cookie
        response.set_cookie(
            key=COOKIE_NAME,
            value=access_token,
            httponly=True,
            max_age=COOKIE_MAX_AGE,  # 7天有效期
            samesite="lax"  # 添加SameSite属性
        )
    
        # 返回令牌
        return {"access_token": access_token, "token_type": "bearer"}
    except HTTPException:
        # 直接重新抛出HTTP异常
        raise
    except Exception as e:
        # 记录详细错误信息
        logging.error(f"管理员登录过程中发生未处理的异常: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="服务器内部错误"
        )

@app.post("/webhook")
async def handle_webhook(
        request: Request,
        payload: Payload,
        user_agent: str = Header(None),
        x_bot_appid: str = Header(None)
):
    """处理Webhook请求入口"""
    start_time = time.time()
    secret = request.query_params.get('secret')
    body_bytes = await request.body()
    
    # 原始消息记录功能
    if hasattr(config, 'raw_content') and config.raw_content.get('enabled', False):
        try:
            import os
            from datetime import datetime
            
            # 确保日志目录存在
            log_dir = config.raw_content.get('path', 'logs')
            os.makedirs(log_dir, exist_ok=True)
            
            # 生成日志文件名（按日期分文件）
            current_date = datetime.now().strftime('%Y-%m-%d')
            log_file = os.path.join(log_dir, f'raw_messages_{current_date}.log')
            
            # 记录原始消息
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            client_ip = request.client.host if request.client else "unknown"
            
            # 尝试解析原始消息体为JSON，避免双重转义
            try:
                raw_body_str = body_bytes.decode('utf-8', errors='ignore')
                if raw_body_str.strip():
                    # 尝试解析为JSON对象
                    if json_module.__name__ == 'orjson':
                        raw_body = json_module.loads(raw_body_str.encode('utf-8'))
                    else:
                        raw_body = json_module.loads(raw_body_str)
                else:
                    raw_body = raw_body_str
            except Exception as parse_error:
                # 如果不是有效JSON，则存储原始字符串
                logging.debug(f"原始消息不是有效JSON，存储为字符串: {str(parse_error)}")
                raw_body = body_bytes.decode('utf-8', errors='ignore')
            
            log_entry = {
                'timestamp': timestamp,
                'client_ip': client_ip,
                'secret': secret,
                'user_agent': user_agent,
                'x_bot_appid': x_bot_appid,
                'content_length': len(body_bytes),
                'raw_body': raw_body
            }
            
            # 写入日志文件，根据JSON库选择合适的序列化方法
            with open(log_file, 'a', encoding='utf-8') as f:
                if json_module.__name__ == 'orjson':
                    # orjson不支持ensure_ascii参数，但默认就是UTF-8输出
                    json_str = json_module.dumps(log_entry).decode('utf-8')
                else:
                    # 标准json库
                    json_str = json_module.dumps(log_entry, ensure_ascii=False)
                f.write(f"{json_str}\n")
                
            logging.debug(f"原始消息已记录到: {log_file}")
            
        except Exception as e:
            logging.error(f"记录原始消息失败: {str(e)}")

    # 增加消息总数统计
    stats_manager.increment_message_count()

    # 获取客户端IP地址
    client_host = request.client.host if request.client else "unknown"
    client_port = request.client.port if request.client else 0
    client_ip = f"{client_host}:{client_port}"

    message_id = None
    # 消息ID检查和去重处理
    try:
        message_data = json_module.loads(body_bytes)
        message_id = message_data.get('id')

        # 如果存在消息ID，检查是否已经处理过
        if message_id:
            # 检查当前消息是否已存在于缓存中
            if cache_manager.has_message_id(message_id):
                return {"status": "success"}  # 直接返回，不进行后续任何处理

            # 将当前消息ID添加到缓存中，有效期从配置中读取
            cache_manager.add_message_id(message_id, config.deduplication_ttl)
            # 移除消息ID缓存日志
    except Exception as e:
        logging.error(f"消息去重处理异常: {str(e)}")
        service_health["error_count"] += 1

    # 处理回调验证
    if "event_ts" in payload.d and "plain_token" in payload.d:
        try:
            event_ts = payload.d["event_ts"]
            plain_token = payload.d["plain_token"]
            result = generate_signature(secret, event_ts, plain_token)
            service_health["last_successful_webhook"] = time.time()
            return result
        except Exception as e:
            logging.error(f"签名错误: {e}")
            service_health["error_count"] += 1
            return {"status": "error"}

    # 转发状态
    forward_status = "转发状态：未知"
    
    # 使用根日志记录器确保消息被处理
    root_logger = logging.getLogger()

    # 处理webhook转发
    webhook_config = config.webhook_forward
    if webhook_config['enabled'] and webhook_config['targets']:
        # 获取原始请求头
        forward_headers = {
            k: v for k, v in request.headers.items()
            if k.lower() not in ['host', 'content-length']
        }

        try:
            # 异步转发
            forward_results = await forward_webhook(
                webhook_config['targets'],
                body_bytes,
                forward_headers,
                webhook_config['timeout'],
                secret
            )

            # 记录转发结果
            success_count = 0
            retry_success_count = 0
            fail_count = 0

            for result in forward_results:
                sanitized_url = PrivacyUtils.sanitize_url(result['url'])
                if result.get('skipped', False):
                    pass
                elif result['success']:
                    if result.get('retry', False):
                        retry_success_count += 1
                        # 保留前台显示的日志
                        current_time = time.strftime('%m-%d %H:%M:%S')
                        root_logger.info(f"{current_time} - Webhook重试后转发成功 | URL: {sanitized_url}")
                    else:
                        success_count += 1
                        # 保留前台显示的日志
                        current_time = time.strftime('%m-%d %H:%M:%S')
                        root_logger.info(f"{current_time} - Webhook转发成功 | URL: {sanitized_url}")
                else:
                    fail_count += 1
                    if result.get('retry', False):
                        retry_error = result.get('retry_error', '未知错误')
                        current_time = time.strftime('%m-%d %H:%M:%S')
                        root_logger.error(f"{current_time} - Webhook重试转发失败 | URL: {sanitized_url} | 错误: {retry_error}")
                    else:
                        current_time = time.strftime('%m-%d %H:%M:%S')
                        root_logger.error(f"{current_time} - Webhook转发失败 | URL: {sanitized_url} | 错误: {result.get('error', '未知错误')}")

            # 更新Webhook转发统计
            total_success = success_count + retry_success_count
            stats_manager.batch_update_wh_stats(secret, total_success, fail_count)

            # 记录总体转发状态，避免同时记录成功和失败日志
            if total_success > 0:
                # 至少有一个成功
                if fail_count > 0:
                    # 部分成功部分失败
                    forward_status = f"Webhook转发：部分成功 {total_success}，失败 {fail_count}"
                    # 只记录部分成功的信息日志，不再记录单独的失败警告
                    # 保留前台显示的日志
                    root_logger.info(f"Webhook部分转发成功 | 密钥：{PrivacyUtils.sanitize_secret(secret)} | 成功：{total_success}，失败：{fail_count}")
                else:
                    # 全部成功
                    forward_status = f"Webhook转发：全部成功 {total_success}"
            else:
                # 全部失败，但如果没有目标或全部跳过则不记录警告
                forward_status = f"Webhook转发：全部失败 {fail_count}"
                
                # 检查是否有WebSocket连接，如果有则不记录Webhook失败警告
                has_ws_connections = secret in active_connections and len(active_connections[secret]) > 0
                
                # 只有当确实有失败项且没有WebSocket连接时才记录警告
                if fail_count > 0 and not has_ws_connections:
                    # 保留error级别日志
                    root_logger.warning(f"Webhook转发全部失败 | 密钥：{PrivacyUtils.sanitize_secret(secret)} | 失败数：{fail_count}/{fail_count}")
                elif fail_count == 0:
                    # 如果失败数为0，说明全部被跳过，不需要记录日志
                    pass
        except Exception as e:
            root_logger.error(f"Webhook转发处理异常: {e}")
            service_health["error_count"] += 1
            forward_status = f"Webhook转发异常: {str(e)}"

    # 检查当前密钥是否在不缓存列表中
    skip_cache = secret in config.no_cache_secrets
    if skip_cache:
        forward_status += " | 不缓存密钥"

    # 检查是否有在线连接
    has_online = secret in active_connections and len(active_connections[secret]) > 0

    # 消息处理逻辑
    try:
        # 没有在线连接且不跳过缓存时，添加到缓存
        if not has_online and not skip_cache:
            await cache_manager.add_message(secret, body_bytes)
            forward_status += " | WS：无在线连接-已缓存"
        elif not has_online:
            forward_status += " | WS：无在线连接-不缓存"
        else:
            forward_status += " | WS：有在线连接"
            # 只有当确实有WebSocket连接时才尝试转发
        try:
            await send_to_all(secret, body_bytes)
        except Exception as e:
            logging.error(f"实时转发异常: {e}")
            service_health["error_count"] += 1
            forward_status += f" | 转发异常: {str(e)}"
    except Exception as e:
        logging.error(f"消息缓存处理异常: {e}")
        service_health["error_count"] += 1
        forward_status += f" | 缓存异常: {str(e)}"

    # 更新健康状态
    process_time = time.time() - start_time
    if process_time > 2:
        logging.warning(f"Webhook处理耗时较长: {process_time:.2f}秒 | 密钥: {PrivacyUtils.sanitize_secret(secret)}")

    service_health["last_successful_webhook"] = time.time()

    return {"status": "success"}

# 新增短密钥webhook处理端点
@app.post("/api/{appid}")
async def handle_appid_webhook(
        appid: str,
        request: Request,
        payload: Payload,
        user_agent: str = Header(None),
        x_bot_appid: str = Header(None),
        signature: str = Query(None),
        timestamp: str = Query(None),
        nonce: str = Query(None)
):
    """通过AppID处理Webhook请求"""
    # 根据AppID获取原始密钥
    secret = app_id_manager.get_secret_by_appid(appid)
    if not secret:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="无效的AppID"
        )
    
    # 验证签名（如果提供了签名参数）
    if signature and timestamp and nonce:
        if not app_id_manager.verify_signature(appid, signature, timestamp, nonce):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="签名验证失败"
            )
    
    # 将请求重定向到标准Webhook处理流程
    request.query_params._dict["secret"] = secret
    return await handle_webhook(
        request=request,
        payload=payload,
        user_agent=user_agent,
        x_bot_appid=x_bot_appid
    )


@app.websocket("/ws/{secret}")
async def websocket_endpoint(
        websocket: WebSocket,
        secret: str,
        token: str = None,
        group: str = None,
        member: str = None,
        content: str = None
):
    """WebSocket连接处理"""
    try:
        # 检查密钥是否在黑名单中
        if config.is_secret_blacklisted(secret):
            # 直接拒绝连接，不显示日志
            await websocket.close(code=1008)
            return
            
        await websocket.accept()

        # 发送初始心跳
        await websocket.send_bytes(json_module.dumps({
            "op": 10,
            "d": {"heartbeat_interval": 30000}
        }))

        is_sandbox = any([group, member, content])
        environment = "沙盒环境" if is_sandbox else "正式环境"

        lock = await cache_manager.get_lock_for_secret(secret)
        async with lock:
            if secret not in active_connections:
                active_connections[secret] = {}

            active_connections[secret][websocket] = {
                "token": token,
                "failure_count": 0,
                "group": group,
                "member": member,
                "content": content,
                "is_sandbox": is_sandbox,
                "last_activity": time.time()
            }

            current_count = len(active_connections[secret])

            # 确保token缓存队列存在
            if token and secret not in config.no_cache_secrets:
                cache_manager.message_cache.setdefault(secret, {
                    "public": deque(maxlen=config.cache["max_public_messages"]), 
                    "tokens": {}
                })
                cache_manager.message_cache[secret]["tokens"].setdefault(token, deque(maxlen=config.cache["max_token_messages"]))

        logging.info(
            f"WS连接成功 | 密钥：{PrivacyUtils.sanitize_secret(secret)} | Token：{PrivacyUtils.sanitize_secret(token) if token else '无'} | "
            f"环境：{environment} | 连接数：{current_count}"
        )

        # 触发补发任务
        if token:
            asyncio.create_task(resend_token_cache(secret, token, websocket))
        asyncio.create_task(resend_public_cache(secret, websocket))

        # 心跳任务
        heartbeat_task = asyncio.create_task(send_heartbeat(websocket, secret))

        try:
            while True:
                try:
                    # 设置超时接收，避免永久阻塞
                    data = await asyncio.wait_for(websocket.receive_text(), timeout=60)

                    # 更新活动时间
                    async with lock:
                        if secret in active_connections and websocket in active_connections[secret]:
                            active_connections[secret][websocket]["last_activity"] = time.time()

                    # 移除所有WS消息日志，不再记录
                    pass
                    await handle_ws_message(data, websocket)
                    service_health["last_successful_ws_message"] = time.time()
                except asyncio.TimeoutError:
                    # 检查连接是否活跃
                    async with lock:
                        if secret in active_connections and websocket in active_connections[secret]:
                            last_activity = active_connections[secret][websocket]["last_activity"]
                            if time.time() - last_activity > 120:  # 2分钟无活动
                                logging.warning(f"WS连接超时无活动 | 密钥：{PrivacyUtils.sanitize_secret(secret)}")
                                break
                        else:
                            break
                    continue  # 继续等待消息
        except WebSocketDisconnect:
            logging.info(f"WS正常断开连接 | 密钥：{PrivacyUtils.sanitize_secret(secret)}")
        except Exception as e:
            logging.error(f"WS消息接收异常: {str(e)}")
            service_health["error_count"] += 1
        finally:
            # 取消心跳任务
            heartbeat_task.cancel()

            # 清理连接
            async with lock:
                if secret in active_connections and websocket in active_connections[secret]:
                    conn_info = active_connections[secret][websocket]
                    token = conn_info["token"]
                    del active_connections[secret][websocket]
                    remaining = len(active_connections[secret])

                    # 确保离线token的缓存队列存在
                    if token and secret not in config.no_cache_secrets:
                        cache_manager.message_cache.setdefault(secret, {
                            "public": deque(maxlen=config.cache["max_public_messages"]), 
                            "tokens": {}
                        })
                        cache_manager.message_cache[secret]["tokens"].setdefault(token, deque(maxlen=config.cache["max_token_messages"]))
                        # 移除准备离线缓存日志

                    logging.info(
                        f"WS断开连接处理完成 | 密钥：{PrivacyUtils.sanitize_secret(secret)} | Token：{PrivacyUtils.sanitize_secret(token) if token else '无'} | "
                        f"剩余连接：{remaining}"
                    )

                    if not active_connections[secret]:
                        del active_connections[secret]
    except Exception as e:
        logging.error(f"WS连接全局异常: {str(e)}")
        service_health["error_count"] += 1
        try:
            await websocket.close()
        except:
            pass

# 验证管理员令牌API
@app.get("/api/admin/verify")
async def verify_admin_token(admin: str = Depends(get_current_admin)):
    """验证管理员令牌有效性"""
    return {"status": "success", "username": admin}

# 管理员登出
@app.post("/api/admin/logout")
async def admin_logout(response: Response, admin: str = Depends(get_current_admin)):
    """管理员登出"""
    # 清除认证Cookie
    response.delete_cookie(key=COOKIE_NAME)
    return {"status": "success", "message": "已成功退出登录"}

# 获取系统统计信息
@app.get("/api/admin/stats")
async def get_admin_stats(admin: str = Depends(get_current_admin)):
    """获取管理员统计信息"""
    # 获取统计数据副本
    with stats_manager.stats_lock:
        stats_copy = copy.deepcopy(stats_manager.stats)
    
    # 获取连接信息
    online_status = {}
    for secret, connections in active_connections.items():
        online_status[secret] = len(connections)
    
    # 获取转发配置
    forward_config = []
    for target in config.webhook_forward["targets"]:
        forward_config.append({
            "url": target["url"],
            "secret": target["secret"]
        })
    
    # 统计总AppID数量
    total_appids = len(app_id_manager.appids) if hasattr(app_id_manager, 'appids') else 0
    
    # 统计每个密钥配置了多少个webhook链接
    webhook_links_count = {}
    for target in config.webhook_forward["targets"]:
        secret = target["secret"]
        if secret not in webhook_links_count:
            webhook_links_count[secret] = 0
        webhook_links_count[secret] += 1
    
    # 确保per_secret统计数据正确转换（不是defaultdict）
    per_secret_dict = {}
    if "per_secret" in stats_copy:
        for secret, data in stats_copy["per_secret"].items():
            if isinstance(data, dict):
                per_secret_dict[secret] = {
                    "ws": {
                        "success": data.get("ws", {}).get("success", 0),
                        "failure": data.get("ws", {}).get("failure", 0)
                    },
                    "wh": {
                        "success": data.get("wh", {}).get("success", 0),
                        "failure": data.get("wh", {}).get("failure", 0)
                    },
                    "webhook_links": webhook_links_count.get(secret, 0)
                }
    
    # 返回整合的统计信息
    return {
        "total_appids": total_appids,
        "ws": stats_copy.get("ws", {}),
        "wh": stats_copy.get("wh", {}),
        "total_messages": stats_copy.get("total_messages", 0),
        "online": online_status,
        "forward_config": forward_config,
        "webhook_enabled": config.webhook_forward["enabled"],
        "per_secret": per_secret_dict,
        "webhook_links_count": webhook_links_count
    }

# 创建AppID API - 简化版
@app.post("/api/admin/appids/create")
async def admin_create_appid(request: Request):
    """管理员创建AppID"""
    # 验证管理员身份
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="未提供有效的认证令牌"
        )
    
    token = auth_header.split(" ")[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        username = payload.get("sub")
        is_admin = payload.get("is_admin", False)
        
        if not username or not is_admin or username != config.admin.get("username"):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="无效的管理员凭据"
            )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="无效的认证令牌"
        )
    
    # 解析请求数据
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="无效的JSON数据"
        )
    
    # 获取参数
    appid = data.get("appid")
    secret = data.get("secret")
    description = data.get("description", "")
    
    # 验证参数
    if not appid or not appid.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="AppID不能为空"
        )
    
    if not secret or len(secret) < 10:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="密钥长度必须至少为10个字符"
        )
    
    # 创建AppID
    success, status_msg = app_id_manager.create_appid(appid.strip(), secret.strip(), description.strip())
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"创建AppID失败: {status_msg}"
        )
    
    # 返回成功结果
    return {
        "appid": appid,
        "secret": secret,
        "description": description,
        "create_time": time.time(),
        "status": status_msg
    }

# 简化版创建AppID接口 - 支持GET请求
@app.get("/api/admin/create_appid")
async def admin_create_appid_get(
    request: Request,
    appid: str = Query(..., description="要创建的AppID"),
    secret: str = Query(..., description="密钥，至少10个字符"),
    description: str = Query("", description="可选的描述信息"),
    token: str = Query(None, description="管理员令牌")
):
    """通过GET请求创建AppID - 简化版接口"""
    # 验证管理员身份
    auth_header = request.headers.get("Authorization")
    admin_token = None
    
    # 先尝试从Authorization头获取令牌
    if auth_header and auth_header.startswith("Bearer "):
        admin_token = auth_header.split(" ")[1]
    
    # 如果没有Authorization头，尝试从token参数获取
    if not admin_token and token:
        admin_token = token
    
    # 如果还是没有，尝试从Cookie获取
    if not admin_token:
        admin_token = request.cookies.get(COOKIE_NAME)
    
    if not admin_token:
        # 如果是浏览器请求，重定向到登录页面
        if "text/html" in request.headers.get("accept", ""):
            return RedirectResponse(url="/login", status_code=302)
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="未提供有效的认证令牌"
            )
    
    try:
        payload = jwt.decode(admin_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        username = payload.get("sub")
        is_admin = payload.get("is_admin", False)
        
        if not username or not is_admin or username != config.admin.get("username"):
            # 如果是浏览器请求，重定向到登录页面
            if "text/html" in request.headers.get("accept", ""):
                return RedirectResponse(url="/login", status_code=302)
            else:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="无效的管理员凭据"
                )
    except Exception:
        # 如果是浏览器请求，重定向到登录页面
        if "text/html" in request.headers.get("accept", ""):
            return RedirectResponse(url="/login", status_code=302)
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="无效的认证令牌"
            )
    
    # 验证参数
    if not appid or not appid.strip():
        # 如果是浏览器请求，重定向回表单页面
        if "text/html" in request.headers.get("accept", ""):
            return RedirectResponse(url="/console#appids", status_code=302)
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="AppID不能为空"
            )
    
    if not secret or len(secret) < 10:
        # 如果是浏览器请求，重定向回表单页面
        if "text/html" in request.headers.get("accept", ""):
            return RedirectResponse(url="/console#appids", status_code=302)
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="密钥长度必须至少为10个字符"
            )
    
    # 创建AppID
    success, status_msg = app_id_manager.create_appid(appid.strip(), secret.strip(), description.strip())
    
    if not success:
        # 如果是浏览器请求，重定向回表单页面
        if "text/html" in request.headers.get("accept", ""):
            return RedirectResponse(url="/console#appids", status_code=302)
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"创建AppID失败: {status_msg}"
            )
    
    # 如果是浏览器请求，重定向回控制台
    if "text/html" in request.headers.get("accept", ""):
        return RedirectResponse(url="/console#appids", status_code=302)
    
    # 返回成功结果
    return {
        "appid": appid,
        "secret": secret,
        "description": description,
        "create_time": time.time(),
        "status": status_msg
    }

# 获取所有AppID
@app.get("/api/admin/appids")
async def get_all_appids(admin: str = Depends(get_current_admin)):
    """获取所有AppID信息"""
    result = []
    
    # 获取统计数据
    with stats_manager.stats_lock:
        stats_copy = stats_manager.stats.copy()
    
    for appid_info in app_id_manager.get_all_appids():
        appid = appid_info["appid"]
        secret = appid_info["secret"]
        description = appid_info["description"]
        create_time = appid_info["create_time"]
        
        # 获取该密钥的统计数据
        ws_stats = {"success": 0, "failure": 0}
        wh_stats = {"success": 0, "failure": 0}
        if "per_secret" in stats_copy and secret in stats_copy["per_secret"]:
            ws_stats = stats_copy["per_secret"][secret].get("ws", ws_stats)
            wh_stats = stats_copy["per_secret"][secret].get("wh", wh_stats)
        
        result.append({
            "appid": appid,
            "secret": secret,  # 对管理员显示完整密钥
            "secret_masked": PrivacyUtils.sanitize_secret(secret),  # 同时提供脱敏版本，以便管理员可以选择使用
            "description": description,
            "create_time": create_time,
            "ws": ws_stats,
            "wh": wh_stats
        })
    
    # 按创建时间排序
    result.sort(key=lambda x: x["create_time"], reverse=True)
    return result

# 删除AppID
@app.delete("/api/admin/appids/{appid}")
async def delete_appid(appid: str, admin: str = Depends(get_current_admin)):
    """删除指定AppID"""
    if not app_id_manager.delete_appid(appid):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="AppID不存在"
        )
    
    return {"status": "success", "appid": appid}

# 获取系统设置
@app.get("/api/admin/settings")
async def get_system_settings(admin: str = Depends(get_current_admin)):
    """获取系统设置"""
    return {
        "log_level": config.log_level,
        "deduplication_ttl": config.deduplication_ttl,
        "raw_content": getattr(config, 'raw_content', {"enabled": False, "path": "logs"}),
        "ssl": config.ssl
    }

# 更新系统设置
@app.post("/api/admin/settings/update")
async def update_system_settings(
    settings_data: SystemSettings, 
    admin: str = Depends(get_current_admin),
    request: Request = None
):
    """更新系统设置，使用Pydantic模型验证输入"""
    # 使用验证过的数据更新配置
    settings_dict = settings_data.dict()
    
    # 验证raw_content配置
    if "raw_content" in settings_dict:
        raw_content = settings_dict["raw_content"]
        
        # 验证必需的字段
        if not isinstance(raw_content, dict):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="raw_content配置必须是对象格式"
            )
        
        # 设置默认值
        if "enabled" not in raw_content:
            raw_content["enabled"] = False
        if "path" not in raw_content:
            raw_content["path"] = "logs"
        
        # 验证enabled字段
        if not isinstance(raw_content["enabled"], bool):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="raw_content.enabled必须是布尔值"
            )
        
        # 验证path字段
        path = raw_content["path"]
        if not isinstance(path, str) or not path.strip():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="raw_content.path必须是非空字符串"
            )
        
        # 安全检查路径
        if ".." in path or path.startswith("/") or ":" in path:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="raw_content.path路径格式不安全"
            )
        
        settings_dict["raw_content"] = raw_content
    
    result = config.update_settings(settings_dict)
    
    # 额外处理日志级别的更新
    if "log_level" in settings_dict:
        logging.getLogger().setLevel(settings_dict["log_level"])
    
    # 记录操作日志
    client_ip = request.client.host if request else "未知IP"
    logging.info(f"管理员 {admin} ({client_ip}) 更新了系统设置")
    
    return {"status": "success", "message": "系统设置已更新"}

# 更新注册设置
@app.post("/api/admin/registration/settings/update")
async def update_registration_settings(
    request: Request,
    admin: str = Depends(get_current_admin)
):
    """更新注册设置"""
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="注册功能已被移除"
    )

# 获取用户短密钥列表
@app.get("/api/admin/users/{username}/shortkeys")
async def get_user_shortkeys(username: str, include_secrets: bool = False, admin: str = Depends(get_current_admin)):
    """获取指定用户的所有短密钥"""
    # 用户功能已移除
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="用户功能已移除"
    )

# 黑名单相关API
@app.get("/api/admin/blacklist")
async def get_blacklist(admin: str = Depends(get_current_admin)):
    """获取黑名单配置"""
    if not hasattr(config, 'blacklist'):
        config.blacklist = {
            'secrets': [],
            'enabled': True
        }
    return config.blacklist

@app.post("/api/admin/blacklist/add")
async def add_to_blacklist(data: Dict[str, str], admin: str = Depends(get_current_admin)):
    """添加密钥到黑名单"""
    secret = data.get('secret')
    if not secret:
        return JSONResponse(
            status_code=400,
            content={"status": "error", "message": "缺少密钥参数"}
        )
    
    # 确保黑名单存在
    if not hasattr(config, 'blacklist'):
        config.blacklist = {
            'secrets': [],
            'enabled': True
        }
    
    # 检查密钥是否已在黑名单中
    if secret in config.blacklist['secrets']:
        return {"status": "success", "message": "密钥已在黑名单中"}
    
    # 添加到黑名单
    config.blacklist['secrets'].append(secret)
    config.update_blacklist(config.blacklist)
    
    # 断开该密钥的所有WebSocket连接，不记录日志
    disconnected_count = 0
    if secret in active_connections:
        connections = list(active_connections[secret].keys())
        for ws in connections:
            try:
                await ws.close(code=1008)
                disconnected_count += 1
            except Exception:
                pass
    
    return {
        "status": "success", 
        "message": f"密钥已添加到黑名单，断开了 {disconnected_count} 个连接"
    }

@app.post("/api/admin/blacklist/remove")
async def remove_from_blacklist(data: Dict[str, str], admin: str = Depends(get_current_admin)):
    """从黑名单移除密钥"""
    secret = data.get('secret')
    if not secret:
        return JSONResponse(
            status_code=400,
            content={"status": "error", "message": "缺少密钥参数"}
        )
    
    # 确保黑名单存在
    if not hasattr(config, 'blacklist'):
        config.blacklist = {
            'secrets': [],
            'enabled': True
        }
    
    # 检查密钥是否在黑名单中
    if secret not in config.blacklist['secrets']:
        return {"status": "success", "message": "密钥不在黑名单中"}
    
    # 从黑名单移除
    config.blacklist['secrets'].remove(secret)
    config.update_blacklist(config.blacklist)
    
    return {"status": "success", "message": "密钥已从黑名单移除"}

@app.post("/api/admin/blacklist/toggle")
async def toggle_blacklist(data: Dict[str, bool], admin: str = Depends(get_current_admin)):
    """启用或禁用黑名单功能"""
    enabled = data.get('enabled')
    if enabled is None:
        return JSONResponse(
            status_code=400,
            content={"status": "error", "message": "缺少enabled参数"}
        )
    
    # 确保黑名单存在
    if not hasattr(config, 'blacklist'):
        config.blacklist = {
            'secrets': [],
            'enabled': True
        }
    
    # 更新黑名单状态
    config.blacklist['enabled'] = enabled
    config.update_blacklist(config.blacklist)
    
    return {
        "status": "success", 
        "message": f"黑名单功能已{'启用' if enabled else '禁用'}"
    }

@app.websocket("/api/ws/{appid}")
async def appid_websocket_endpoint(
        websocket: WebSocket,
        appid: str,
        token: str = None,
        group: str = None,
        member: str = None,
        content: str = None,
        signature: str = None,
        timestamp: str = None,
        nonce: str = None
):
    """通过AppID处理WebSocket连接"""
    # 根据AppID获取原始密钥
    secret = app_id_manager.get_secret_by_appid(appid)
    if not secret:
        try:
            await websocket.accept()
            await websocket.close(code=1008, reason="无效的AppID")
        except Exception:
            pass
        return
    
    # 验证签名（如果提供了签名参数）
    if signature and timestamp and nonce:
        if not app_id_manager.verify_signature(appid, signature, timestamp, nonce):
            try:
                await websocket.accept()
                await websocket.close(code=1008, reason="签名验证失败")
            except Exception:
                pass
            return
        
    # 检查原始密钥是否在黑名单中
    if config.is_secret_blacklisted(secret):
        try:
            # 直接拒绝连接，不显示日志
            await websocket.close(code=1008)
        except Exception:
            pass
        return
    
    # 转发到标准WebSocket处理流程
    await websocket_endpoint(
        websocket=websocket,
        secret=secret,
        token=token,
        group=group,
        member=member,
        content=content
    )

if __name__ == "__main__":
    import uvicorn
    
    # 使用配置文件中的SSL设置
    ssl_config = config.ssl
    port = config.port
    use_ssl = ssl_config["ssl_keyfile"] and ssl_config["ssl_certfile"]

    # 创建UVICORN配置
    uvicorn_config = uvicorn.Config(
        app,
        host="0.0.0.0",
        port=port,
        log_level="info",
        log_config=None,
        access_log=False
    )
    # 只有当证书都不为空时才添加SSL配置
    if use_ssl:
        uvicorn_config.ssl_keyfile = ssl_config["ssl_keyfile"]
        uvicorn_config.ssl_certfile = ssl_config["ssl_certfile"]
        logging.info(f"启用SSL，监听端口: {port}")
    else:
        logging.info(f"未启用SSL，监听端口: {port}")

    # 再次确保日志级别正确
    logging.getLogger().setLevel(logging.INFO)

    # 启动服务
    server = uvicorn.Server(uvicorn_config)
    asyncio.run(server.serve())

