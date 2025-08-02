// 格式化数字显示
function formatNumber(num) {
    return num.toString().replace(/(\d)(?=(\d{3})+(?!\d))/g, '$1,');
}

// 更新时间格式化
function formatDate(date) {
    const options = {
        year: 'numeric',
        month: 'numeric',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false
    };
    return new Date(date).toLocaleString('zh-CN', options);
}

// 脱敏处理函数 - 只显示前两位字符
function maskSensitiveData(text) {
    if (!text) return "**";
    if (text.length <= 2) return text;
    return text.substring(0, 2) + "*".repeat(Math.min(8, text.length - 2));
}

// 脱敏URL
function maskUrl(url) {
    if (!url) return "**";
    try {
        const urlObj = new URL(url);
        const maskedHost = maskSensitiveData(urlObj.hostname);
        const maskedPath = urlObj.pathname.replace(/\/[^\/]+/g, "/*");
        return `${urlObj.protocol}//${maskedHost}${maskedPath}`;
    } catch (e) {
        return maskSensitiveData(url);
    }
}

// 渲染密钥卡片
function renderSecretCard(secret, stats, online, forwardUrls, webhookEnabled) {
    const wsSuccess = stats.ws?.success || 0;
    const wsFailure = stats.ws?.failure || 0;
    const whSuccess = stats.wh?.success || 0;
    const whFailure = stats.wh?.failure || 0;
    
    const isOnline = (online && online > 0) ? true : false;
    const hasForwardConfig = forwardUrls && forwardUrls.length > 0;
    const webhookForwardEnabled = webhookEnabled && hasForwardConfig;
    
    // 脱敏处理密钥
    const maskedSecret = maskSensitiveData(secret);
    
    const card = document.createElement('div');
    card.className = 'col-md-6 mb-4';
    card.innerHTML = `
        <div class="stats-card secret-card bg-white">
            <div class="secret-header d-flex justify-content-between align-items-center">
                <h5 class="m-0 key-hidden" title="敏感数据已脱敏">${maskedSecret}</h5>
                <div>
                    <span class="badge ${isOnline ? 'bg-success' : 'bg-danger'}">
                        <i class="bi ${isOnline ? 'bi-wifi' : 'bi-wifi-off'}"></i>
                        ${isOnline ? '在线 (' + online + ')' : '离线'}
                    </span>
                    <span class="badge ${webhookForwardEnabled ? 'bg-primary' : 'bg-secondary'}">
                        <i class="bi ${webhookForwardEnabled ? 'bi-arrow-repeat' : 'bi-x-circle'}"></i>
                        ${webhookForwardEnabled ? 'WebHook已启用' : 'WebHook未启用'}
                    </span>
                </div>
            </div>
            <div class="secret-body">
                <div class="secret-stats mb-3">
                    <div class="stat-block">
                        <h6>WebSocket成功</h6>
                        <div class="fs-4 text-success">${formatNumber(wsSuccess)}</div>
                    </div>
                    <div class="stat-block">
                        <h6>WebSocket失败</h6>
                        <div class="fs-4 text-danger">${formatNumber(wsFailure)}</div>
                    </div>
                    <div class="stat-block">
                        <h6>WebHook成功</h6>
                        <div class="fs-4 text-success">${formatNumber(whSuccess)}</div>
                    </div>
                    <div class="stat-block">
                        <h6>WebHook失败</h6>
                        <div class="fs-4 text-danger">${formatNumber(whFailure)}</div>
                    </div>
                </div>
                ${hasForwardConfig ? `
                    <div class="forward-config mt-3">
                        <h6><i class="bi bi-arrow-right-circle"></i> 转发目标</h6>
                        <ul class="list-group">
                            ${forwardUrls.map(url => `
                                <li class="list-group-item forward-url">${maskUrl(url)}</li>
                            `).join('')}
                        </ul>
                    </div>
                ` : ''}
            </div>
        </div>
    `;
    return card;
}

// 加载统计数据
async function loadStats() {
    try {
        const response = await fetch('/api/stats');
        const data = await response.json();
        
        // 更新全局统计信息
        document.getElementById('totalMessages').textContent = formatNumber(data.stats.total_messages || 0);
        document.getElementById('wsSuccess').textContent = formatNumber(data.stats.ws?.total_success || 0);
        document.getElementById('wsFailure').textContent = formatNumber(data.stats.ws?.total_failure || 0);
        document.getElementById('whSuccess').textContent = formatNumber(data.stats.wh?.total_success || 0);
        document.getElementById('whFailure').textContent = formatNumber(data.stats.wh?.total_failure || 0);
        
        // 更新最后更新时间
        document.getElementById('lastUpdated').textContent = '最后更新: ' + formatDate(new Date());
        
        // 获取密钥列表
        const activeContainer = document.getElementById('activeSecrets');
        const allContainer = document.getElementById('allSecrets');
        
        // 清空容器
        activeContainer.innerHTML = '';
        allContainer.innerHTML = '';
        
        // 获取所有密钥
        const secrets = Object.keys(data.stats.per_secret);
        
        if (secrets.length === 0) {
            activeContainer.innerHTML = '<div class="col-12 no-data-message"><i class="bi bi-info-circle"></i> 暂无数据</div>';
            allContainer.innerHTML = '<div class="col-12 no-data-message"><i class="bi bi-info-circle"></i> 暂无数据</div>';
            return;
        }
        
        // 处理所有密钥
        secrets.forEach(secret => {
            const stats = data.stats.per_secret[secret];
            const online = data.online[secret] || 0;
            const forwardUrls = data.forward_config[secret] || [];
            
            // 添加到所有密钥标签页
            allContainer.appendChild(renderSecretCard(secret, stats, online, forwardUrls, data.webhook_enabled));
            
            // 如果在线或有最近的统计数据，则添加到活跃密钥标签页
            // 判断条件：在线连接数>0 或 启用了webhook并且有转发配置
            const hasWebhookConfig = data.webhook_enabled && forwardUrls.length > 0;
            const isActive = online > 0 || hasWebhookConfig;
            
            if (isActive) {
                activeContainer.appendChild(renderSecretCard(secret, stats, online, forwardUrls, data.webhook_enabled));
            }
        });
        
        // 如果没有活跃密钥
        if (activeContainer.children.length === 0) {
            activeContainer.innerHTML = '<div class="col-12 no-data-message"><i class="bi bi-info-circle"></i> 当前无活跃密钥</div>';
        }
    } catch (error) {
        console.error('加载统计数据失败:', error);
        document.getElementById('lastUpdated').textContent = '刷新失败: ' + error.message;
    }
}

// 初始加载
document.addEventListener('DOMContentLoaded', () => {
    loadStats();
    
    // 绑定刷新按钮
    document.getElementById('refreshBtn').addEventListener('click', function() {
        const icon = this.querySelector('i');
        icon.classList.add('bi-arrow-repeat-animate');
        this.disabled = true;
        
        loadStats().finally(() => {
            setTimeout(() => {
                icon.classList.remove('bi-arrow-repeat-animate');
                this.disabled = false;
            }, 500);
        });
    });
});

// 设置自动刷新 (每30秒)
setInterval(loadStats, 30000); 