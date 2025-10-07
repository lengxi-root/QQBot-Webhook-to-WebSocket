import asyncio
import logging
import os
import time
import sys
import json
import secrets
import hmac
import hashlib
import uvicorn
from collections import deque
from typing import Optional, Dict, List, Any
from datetime import datetime, timedelta
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Header, WebSocket, WebSocketDisconnect, Depends, HTTPException, status, Response, Query
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

import config
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

json_module = json
JSONDecodeError = json.JSONDecodeError

class SystemSettings(BaseModel):
    log_level: str = Field(..., pattern='^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$')
    deduplication_ttl: int = Field(..., ge=0, le=3600)
    raw_content: dict = Field(default_factory=dict)

logger = setup_logger()
logging.getLogger().setLevel(logging.INFO)

COOKIE_NAME = "admin_session"
COOKIE_SECRET = os.environ.get("COOKIE_SECRET", secrets.token_hex(32))
COOKIE_MAX_AGE = 60 * 60 * 24 * 7

valid_sessions: Dict[str, Dict] = {}

IP_DATA_FILE = "data/ip_access.json"
ip_access_data: Dict[str, Dict] = {}
_last_ip_cleanup = 0

class Payload(BaseModel):
    d: dict

def load_ip_data():
    global ip_access_data
    try:
        if os.path.exists(IP_DATA_FILE):
            with open(IP_DATA_FILE, 'r', encoding='utf-8') as f:
                ip_access_data = json.load(f)
        else:
            ip_access_data = {}
    except Exception as e:
        logging.error(f"加载IP数据失败: {e}")
        ip_access_data = {}

def save_ip_data():
    try:
        os.makedirs(os.path.dirname(IP_DATA_FILE), exist_ok=True)
        with open(IP_DATA_FILE, 'w', encoding='utf-8') as f:
            json.dump(ip_access_data, f, ensure_ascii=False, indent=2)
    except Exception as e:
        logging.error(f"保存IP数据失败: {e}")

def record_ip_access(ip_address: str, access_type: str = 'token_success'):
    global ip_access_data
    current_time = datetime.now()
    
    if ip_address not in ip_access_data:
        ip_access_data[ip_address] = {
            'last_access': current_time.isoformat(),
            'password_fail_times': [],
            'is_banned': False,
            'ban_time': None
        }
    
    ip_data = ip_access_data[ip_address]
    ip_data['last_access'] = current_time.isoformat()
    
    if access_type == 'password_fail':
        ip_data['password_fail_times'].append(current_time.isoformat())
        ip_data['password_fail_times'] = [
            t for t in ip_data['password_fail_times']
            if (current_time - datetime.fromisoformat(t)).total_seconds() < 86400
        ]
        
        if len(ip_data['password_fail_times']) >= 5:
            ip_data['is_banned'] = True
            ip_data['ban_time'] = current_time.isoformat()
            logging.warning(f"IP {ip_address} 因密码错误次数过多被封禁24小时")
    elif access_type == 'password_success':
        ip_data['password_fail_times'] = []
    
    save_ip_data()

def is_ip_banned(ip_address: str) -> bool:
    if ip_address not in ip_access_data or not ip_access_data[ip_address].get('is_banned'):
        return False
    
    ip_data = ip_access_data[ip_address]
    if not ip_data.get('ban_time'):
        return True
    
    try:
        if (datetime.now() - datetime.fromisoformat(ip_data['ban_time'])).total_seconds() >= 86400:
            ip_data.update({'is_banned': False, 'ban_time': None, 'password_fail_times': []})
            save_ip_data()
            logging.info(f"IP {ip_address} 封禁期满，已解封")
            return False
        return True
    except:
        return True

def cleanup_expired_ip_bans():
    global ip_access_data, _last_ip_cleanup
    if time.time() - _last_ip_cleanup < 3600:
        return
    
    _last_ip_cleanup = time.time()
    current_datetime = datetime.now()
    cleaned = 0
    
    for ip_data in ip_access_data.values():
        if 'password_fail_times' in ip_data:
            ip_data['password_fail_times'] = [
                t for t in ip_data['password_fail_times']
                if (current_datetime - datetime.fromisoformat(t)).total_seconds() < 86400
            ]
        
        if ip_data.get('is_banned') and ip_data.get('ban_time'):
            try:
                if (current_datetime - datetime.fromisoformat(ip_data['ban_time'])).total_seconds() >= 86400:
                    ip_data.update({'is_banned': False, 'ban_time': None, 'password_fail_times': []})
                    cleaned += 1
            except:
                pass
    
    if cleaned > 0:
        save_ip_data()
        logging.info(f"清理了 {cleaned} 个过期的IP封禁")

def sign_cookie_value(value: str) -> str:
    signature = hmac.new(COOKIE_SECRET.encode(), value.encode(), hashlib.sha256).hexdigest()
    return f"{value}.{signature}"

def verify_cookie_value(signed_value: str) -> tuple[bool, Optional[str]]:
    try:
        value, signature = signed_value.rsplit('.', 1)
        expected_sig = hmac.new(COOKIE_SECRET.encode(), value.encode(), hashlib.sha256).hexdigest()
        if hmac.compare_digest(signature, expected_sig):
            return True, value
        return False, None
    except:
        return False, None

def generate_session_token() -> str:
    return secrets.token_hex(32)

def cleanup_expired_sessions():
    global valid_sessions
    now = datetime.now()
    expired = [token for token, info in valid_sessions.items() if now >= info['expires']]
    for token in expired:
        del valid_sessions[token]

def is_logged_in(request: Request) -> bool:
    cleanup_expired_sessions()
    
    cookie_value = request.cookies.get(COOKIE_NAME)
    if not cookie_value:
        return False
    
    is_valid, session_token = verify_cookie_value(cookie_value)
    if not is_valid or session_token not in valid_sessions:
        return False
    
    session_info = valid_sessions[session_token]
    if datetime.now() >= session_info['expires']:
        del valid_sessions[session_token]
        return False
    
    return True

async def get_current_admin(request: Request) -> str:
    if not is_logged_in(request):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="未登录或会话已过期"
        )
    return "admin"

@asynccontextmanager
async def lifespan(app: FastAPI):
    load_ip_data()
    config_task = asyncio.create_task(watch_config())
    health_task = asyncio.create_task(monitor_service_health())
    cache_manager.start_cleaning_thread()
    stats_manager.start_write_thread()

    logger.info(f"服务已启动 - 监听端口: {config.port}")

    yield

    config_task.cancel()
    health_task.cancel()
    cache_manager.stop_cleaning_thread()
    stats_manager.stop_write_thread()

    try:
        await config_task
        await health_task
    except asyncio.CancelledError:
        pass
    logger.info("服务已停止")


app = FastAPI(
    lifespan=lifespan,
    log_level="info"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

os.makedirs("web", exist_ok=True)
os.makedirs("web/js", exist_ok=True)
os.makedirs("web/css", exist_ok=True)

app.mount("/static", StaticFiles(directory="web"), name="static") 

@app.get("/console")
async def user_console(request: Request):
    if not is_logged_in(request):
        return RedirectResponse(url=f"/login?token={config.access_token}")
    
    return FileResponse("web/console.html")

@app.get("/admin")
async def admin_panel(request: Request):
    if not config.admin.get("enabled", True):
        raise HTTPException(status_code=404, detail="管理员功能已禁用")
    
    try:
        await get_current_admin(request)
        return RedirectResponse(url="/console")
    except HTTPException:
        return RedirectResponse(url=f"/login?token={config.access_token}")

@app.get("/")
async def root_redirect():
    return RedirectResponse(url=f"/login?token={config.access_token}")

@app.get("/login")
async def unified_login_page(request: Request, token: str = Query(None)):
    if not token or token != config.access_token:
        return Response(status_code=403)
    
    if is_logged_in(request):
        referer = request.headers.get("referer", "")
        if "/console" in referer:
            return FileResponse("web/login.html")
        return RedirectResponse(url="/console")
    
    return FileResponse("web/login.html")

@app.post("/api/admin/login")
async def admin_login(request: Request, response: Response, admin_data: Dict[str, Any]):
    try:
        cleanup_expired_ip_bans()
        client_ip = request.client.host
        
        if is_ip_banned(client_ip):
            ip_data = ip_access_data.get(client_ip, {})
            fail_count = len(ip_data.get('password_fail_times', []))
            logging.warning(f"IP {client_ip} 已被封禁，拒绝登录")
            raise HTTPException(status_code=418, detail=f"由于密码错误次数过多（{fail_count}次），您的IP已被封禁24小时。请稍后再试。")
        
        if not isinstance(admin_data, dict):
            raise HTTPException(status_code=400, detail="无效的请求数据格式")
        
        if admin_data.get("password", "") != config.admin.get("password"):
            record_ip_access(client_ip, 'password_fail')
            fail_count = len(ip_access_data.get(client_ip, {}).get('password_fail_times', []))
            remaining = max(0, 5 - fail_count)
            logging.warning(f"IP {client_ip} 管理员登录失败: 密码错误 (剩余 {remaining} 次)")
            
            if remaining > 0:
                raise HTTPException(status_code=401, detail=f"密码错误，您还有 {remaining} 次尝试机会")
            else:
                raise HTTPException(status_code=418, detail="由于密码错误次数过多，您的IP已被封禁24小时")
    
        record_ip_access(client_ip, 'password_success')
        cleanup_expired_sessions()
        
        session_token = generate_session_token()
        valid_sessions[session_token] = {'created': datetime.now(), 'expires': datetime.now() + timedelta(days=7)}
        
        response.set_cookie(key=COOKIE_NAME, value=sign_cookie_value(session_token), httponly=True, max_age=COOKIE_MAX_AGE, samesite="lax")
        logging.info(f"IP {client_ip} 管理员登录成功")
        return {"status": "success", "message": "登录成功"}
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"管理员登录异常: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="服务器内部错误")

@app.post("/webhook")
async def handle_webhook(
        request: Request,
        payload: Payload,
        user_agent: str = Header(None),
        x_bot_appid: str = Header(None)
):
    start_time = time.time()
    secret = request.query_params.get('secret')
    body_bytes = await request.body()
    
    if hasattr(config, 'raw_content') and config.raw_content.get('enabled', False):
        try:
            log_dir = config.raw_content.get('path', 'logs')
            os.makedirs(log_dir, exist_ok=True)
            
            current_date = datetime.now().strftime('%Y-%m-%d')
            log_file = os.path.join(log_dir, f'raw_messages_{current_date}.log')
            
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            client_ip = request.client.host if request.client else "unknown"
            
            try:
                raw_body_str = body_bytes.decode('utf-8', errors='ignore')
                if raw_body_str.strip():
                    raw_body = json_module.loads(raw_body_str)
                else:
                    raw_body = raw_body_str
            except Exception as parse_error:
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
            
            with open(log_file, 'a', encoding='utf-8') as f:
                json_str = json_module.dumps(log_entry, ensure_ascii=False)
                f.write(f"{json_str}\n")
                
            logging.debug(f"原始消息已记录到: {log_file}")
            
        except Exception as e:
            logging.error(f"记录原始消息失败: {str(e)}")

    stats_manager.increment_message_count()

    client_host = request.client.host if request.client else "unknown"
    client_port = request.client.port if request.client else 0
    client_ip = f"{client_host}:{client_port}"

    message_id = None
    try:
        message_data = json_module.loads(body_bytes)
        message_id = message_data.get('id')

        if message_id:
            if cache_manager.has_message_id(message_id):
                return {"status": "success"}

            cache_manager.add_message_id(message_id, config.deduplication_ttl)
    except Exception as e:
        logging.error(f"消息去重处理异常: {str(e)}")
        service_health["error_count"] += 1

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

    forward_status = "转发状态：未知"
    
    root_logger = logging.getLogger()

    webhook_config = config.webhook_forward
    if webhook_config['enabled'] and webhook_config['targets']:
        forward_headers = {
            k: v for k, v in request.headers.items()
            if k.lower() not in ['host', 'content-length']
        }

        try:
            forward_results = await forward_webhook(
                webhook_config['targets'],
                body_bytes,
                forward_headers,
                webhook_config['timeout'],
                secret
            )

            success_count = 0
            retry_success_count = 0
            fail_count = 0

            for result in forward_results:
                if result.get('skipped', False):
                    pass
                elif result['success']:
                    if result.get('retry', False):
                        retry_success_count += 1
                        current_time = time.strftime('%m-%d %H:%M:%S')
                        duration = result.get('duration', 0)
                        retry_count = result.get('retry_count', 0)
                        root_logger.info(f"{current_time} - Webhook重试转发成功 | 密钥: {PrivacyUtils.sanitize_secret(secret)} | 耗时: {duration}秒 | 重试: {retry_count}次")
                    else:
                        success_count += 1
                        current_time = time.strftime('%m-%d %H:%M:%S')
                        duration = result.get('duration', 0)
                        root_logger.info(f"{current_time} - Webhook转发成功 | 密钥: {PrivacyUtils.sanitize_secret(secret)} | 耗时: {duration}秒")
                else:
                    fail_count += 1
                    if result.get('retry', False):
                        retry_error = result.get('retry_error', '未知错误')
                        current_time = time.strftime('%m-%d %H:%M:%S')
                        retry_count = result.get('retry_count', 0)
                        root_logger.error(f"{current_time} - Webhook重试转发失败 | 密钥: {PrivacyUtils.sanitize_secret(secret)} | 重试: {retry_count}次 | 错误: {retry_error}")
                    else:
                        current_time = time.strftime('%m-%d %H:%M:%S')
                        root_logger.error(f"{current_time} - Webhook转发失败 | 密钥: {PrivacyUtils.sanitize_secret(secret)} | 错误: {result.get('error', '未知错误')}")

            total_success = success_count + retry_success_count
            stats_manager.batch_update_wh_stats(secret, total_success, fail_count)

            if total_success > 0:
                if fail_count > 0:
                    forward_status = f"Webhook转发：部分成功 {total_success}，失败 {fail_count}"
                    root_logger.info(f"Webhook部分转发成功 | 密钥：{PrivacyUtils.sanitize_secret(secret)} | 成功：{total_success}，失败：{fail_count}")
                else:
                    forward_status = f"Webhook转发：全部成功 {total_success}"
            else:
                forward_status = f"Webhook转发：全部失败 {fail_count}"
                
                has_ws_connections = secret in active_connections and len(active_connections[secret]) > 0
                
                if fail_count > 0 and not has_ws_connections:
                    root_logger.warning(f"Webhook转发全部失败 | 密钥：{PrivacyUtils.sanitize_secret(secret)} | 失败数：{fail_count}/{fail_count}")
                elif fail_count == 0:
                    pass
        except Exception as e:
            root_logger.error(f"Webhook转发处理异常: {e}")
            service_health["error_count"] += 1
            forward_status = f"Webhook转发异常: {str(e)}"

    skip_cache = secret in config.no_cache_secrets
    if skip_cache:
        forward_status += " | 不缓存密钥"

    has_online = secret in active_connections and len(active_connections[secret]) > 0

    try:
        if not has_online and not skip_cache:
            await cache_manager.add_message(secret, body_bytes)
            forward_status += " | WS：无在线连接-已缓存"
        elif not has_online:
            forward_status += " | WS：无在线连接-不缓存"
        else:
            forward_status += " | WS：有在线连接"
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

    process_time = time.time() - start_time
    if process_time > 2:
        logging.warning(f"Webhook处理耗时较长: {process_time:.2f}秒 | 密钥: {PrivacyUtils.sanitize_secret(secret)}")

    service_health["last_successful_webhook"] = time.time()

    return {"status": "success"}

@app.post("/api/{appid}")
async def handle_appid_webhook(
        appid: str, request: Request, payload: Payload,
        user_agent: str = Header(None), x_bot_appid: str = Header(None),
        signature: str = Query(None), timestamp: str = Query(None), nonce: str = Query(None)
):
    secret = app_id_manager.get_secret_by_appid(appid)
    if not secret:
        raise HTTPException(status_code=404, detail="无效的AppID")
    
    if signature and timestamp and nonce:
        if not app_id_manager.verify_signature(appid, signature, timestamp, nonce):
            raise HTTPException(status_code=403, detail="签名验证失败")
    
    request.query_params._dict["secret"] = secret
    return await handle_webhook(request=request, payload=payload, user_agent=user_agent, x_bot_appid=x_bot_appid)


@app.websocket("/ws/{secret}")
async def websocket_endpoint(
        websocket: WebSocket,
        secret: str,
        token: str = None,
        group: str = None,
        member: str = None,
        content: str = None
):
    try:
        await websocket.accept()

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

        if token:
            asyncio.create_task(resend_token_cache(secret, token, websocket))
        asyncio.create_task(resend_public_cache(secret, websocket))

        heartbeat_task = asyncio.create_task(send_heartbeat(websocket, secret))

        try:
            while True:
                try:
                    data = await asyncio.wait_for(websocket.receive_text(), timeout=60)

                    async with lock:
                        if secret in active_connections and websocket in active_connections[secret]:
                            active_connections[secret][websocket]["last_activity"] = time.time()

                    await handle_ws_message(data, websocket)
                    service_health["last_successful_ws_message"] = time.time()
                except asyncio.TimeoutError:
                    async with lock:
                        if secret in active_connections and websocket in active_connections[secret]:
                            last_activity = active_connections[secret][websocket]["last_activity"]
                            if time.time() - last_activity > 120:
                                logging.warning(f"WS连接超时无活动 | 密钥：{PrivacyUtils.sanitize_secret(secret)}")
                                break
                        else:
                            break
                    continue
        except WebSocketDisconnect:
            logging.info(f"WS正常断开连接 | 密钥：{PrivacyUtils.sanitize_secret(secret)}")
        except Exception as e:
            logging.error(f"WS消息接收异常: {str(e)}")
            service_health["error_count"] += 1
        finally:
            heartbeat_task.cancel()

            async with lock:
                if secret in active_connections and websocket in active_connections[secret]:
                    conn_info = active_connections[secret][websocket]
                    token = conn_info["token"]
                    del active_connections[secret][websocket]
                    remaining = len(active_connections[secret])

                    if token and secret not in config.no_cache_secrets:
                        cache_manager.message_cache.setdefault(secret, {
                            "public": deque(maxlen=config.cache["max_public_messages"]), 
                            "tokens": {}
                        })
                        cache_manager.message_cache[secret]["tokens"].setdefault(token, deque(maxlen=config.cache["max_token_messages"]))

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

@app.get("/api/admin/verify")
async def verify_admin_token(admin: str = Depends(get_current_admin)):
    return {"status": "success", "username": admin}

@app.post("/api/admin/logout")
async def admin_logout(response: Response, admin: str = Depends(get_current_admin)):
    response.delete_cookie(COOKIE_NAME)
    return {"status": "success", "message": "已成功退出登录"}

@app.get("/api/admin/stats")
async def get_admin_stats(admin: str = Depends(get_current_admin)):
    with stats_manager.stats_lock:
        stats_copy = {
            "ws": dict(stats_manager.stats.get("ws", {})),
            "wh": dict(stats_manager.stats.get("wh", {})),
            "total_messages": stats_manager.stats.get("total_messages", 0),
            "per_secret": {k: dict(v) for k, v in stats_manager.stats.get("per_secret", {}).items()}
        }
    
    webhook_links_count = {}
    for target in config.webhook_forward["targets"]:
        webhook_links_count[target["secret"]] = webhook_links_count.get(target["secret"], 0) + 1
    
    per_secret_dict = {}
    for secret, data in stats_copy.get("per_secret", {}).items():
        if isinstance(data, dict):
            per_secret_dict[secret] = {
                "ws": {"success": data.get("ws", {}).get("success", 0), "failure": data.get("ws", {}).get("failure", 0)},
                "wh": {"success": data.get("wh", {}).get("success", 0), "failure": data.get("wh", {}).get("failure", 0)},
                "webhook_links": webhook_links_count.get(secret, 0)
            }
    
    return {
        "total_appids": len(app_id_manager.appids) if hasattr(app_id_manager, 'appids') else 0,
        "ws": stats_copy.get("ws", {}),
        "wh": stats_copy.get("wh", {}),
        "total_messages": stats_copy.get("total_messages", 0),
        "online": {s: len(c) for s, c in active_connections.items()},
        "forward_config": [{"url": t["url"], "secret": t["secret"]} for t in config.webhook_forward["targets"]],
        "webhook_enabled": config.webhook_forward["enabled"],
        "per_secret": per_secret_dict,
        "webhook_links_count": webhook_links_count
    }

def _validate_and_create_appid(appid: str, secret: str, description: str):
    if not appid or not appid.strip():
        raise HTTPException(status_code=400, detail="AppID不能为空")
    if not secret or len(secret) < 10:
        raise HTTPException(status_code=400, detail="密钥长度必须至少为10个字符")
    
    success, status_msg = app_id_manager.create_appid(appid.strip(), secret.strip(), description.strip())
    if not success:
        raise HTTPException(status_code=400, detail=f"创建AppID失败: {status_msg}")
    
    return {"appid": appid, "secret": secret, "description": description, "create_time": time.time(), "status": status_msg}

@app.post("/api/admin/appids/create")
async def admin_create_appid(request: Request, admin: str = Depends(get_current_admin)):
    try:
        data = await request.json()
    except:
        raise HTTPException(status_code=400, detail="无效的JSON数据")
    
    return _validate_and_create_appid(data.get("appid", ""), data.get("secret", ""), data.get("description", ""))

@app.get("/api/admin/create_appid")
async def admin_create_appid_get(
    appid: str = Query(...), secret: str = Query(...), description: str = Query(""),
    admin: str = Depends(get_current_admin)
):
    return _validate_and_create_appid(appid, secret, description)

@app.get("/api/admin/appids")
async def get_all_appids(admin: str = Depends(get_current_admin)):
    with stats_manager.stats_lock:
        stats_copy = stats_manager.stats.copy()
    
    result = []
    for info in app_id_manager.get_all_appids():
        secret_stats = stats_copy.get("per_secret", {}).get(info["secret"], {})
        result.append({
            **info,
            "secret_masked": PrivacyUtils.sanitize_secret(info["secret"]),
            "ws": secret_stats.get("ws", {"success": 0, "failure": 0}),
            "wh": secret_stats.get("wh", {"success": 0, "failure": 0})
        })
    
    return sorted(result, key=lambda x: x["create_time"], reverse=True)

@app.delete("/api/admin/appids/{appid}")
async def delete_appid(appid: str, admin: str = Depends(get_current_admin)):
    if not app_id_manager.delete_appid(appid):
        raise HTTPException(status_code=404, detail="AppID不存在")
    return {"status": "success", "appid": appid}

@app.get("/api/admin/settings")
async def get_system_settings(admin: str = Depends(get_current_admin)):
    return {
        "log_level": config.log_level,
        "deduplication_ttl": config.deduplication_ttl,
        "raw_content": getattr(config, 'raw_content', {"enabled": False, "path": "logs"}),
        "ssl": config.ssl
    }

@app.post("/api/admin/settings/update")
async def update_system_settings(settings_data: SystemSettings, admin: str = Depends(get_current_admin), request: Request = None):
    settings_dict = settings_data.dict()
    
    if "raw_content" in settings_dict:
        raw_content = settings_dict["raw_content"]
        if not isinstance(raw_content, dict):
            raise HTTPException(status_code=400, detail="raw_content配置必须是对象格式")
        
        raw_content.setdefault("enabled", False)
        raw_content.setdefault("path", "logs")
        
        if not isinstance(raw_content["enabled"], bool):
            raise HTTPException(status_code=400, detail="raw_content.enabled必须是布尔值")
        
        path = raw_content["path"]
        if not isinstance(path, str) or not path.strip():
            raise HTTPException(status_code=400, detail="raw_content.path必须是非空字符串")
        
        if ".." in path or path.startswith("/") or ":" in path:
            raise HTTPException(status_code=400, detail="raw_content.path路径格式不安全")
        
        settings_dict["raw_content"] = raw_content
    
    config.update_settings(settings_dict)
    
    if "log_level" in settings_dict:
        logging.getLogger().setLevel(settings_dict["log_level"])
    
    logging.info(f"管理员 {admin} ({request.client.host if request else '未知IP'}) 更新了系统设置")
    return {"status": "success", "message": "系统设置已更新"}

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
    secret = app_id_manager.get_secret_by_appid(appid)
    if not secret:
        try:
            await websocket.accept()
            await websocket.close(code=1008, reason="无效的AppID")
        except Exception:
            pass
        return
    
    if signature and timestamp and nonce:
        if not app_id_manager.verify_signature(appid, signature, timestamp, nonce):
            try:
                await websocket.accept()
                await websocket.close(code=1008, reason="签名验证失败")
            except Exception:
                pass
            return
    
    await websocket_endpoint(
        websocket=websocket,
        secret=secret,
        token=token,
        group=group,
        member=member,
        content=content
    )

if __name__ == "__main__":
    ssl_config = config.ssl
    port = config.port
    use_ssl = ssl_config["ssl_keyfile"] and ssl_config["ssl_certfile"]

    uvicorn_config = uvicorn.Config(
        app,
        host="0.0.0.0",
        port=port,
        log_level="info",
        log_config=None,
        access_log=False
    )
    if use_ssl:
        uvicorn_config.ssl_keyfile = ssl_config["ssl_keyfile"]
        uvicorn_config.ssl_certfile = ssl_config["ssl_certfile"]
    
    logging.info(f"{'启用' if use_ssl else '未启用'}SSL，监听端口: {port}")

    logging.getLogger().setLevel(logging.INFO)

    server = uvicorn.Server(uvicorn_config)
    asyncio.run(server.serve())
