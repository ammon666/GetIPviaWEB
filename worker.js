// Cloudflare Workers 最终版（提示框状态与UUID绑定，跨浏览器生效）
const KV_EXPIRATION = 60 * 60 * 24 * 90; // 数据保存90天
// API_KEY 默认值（环境变量未配置时使用）
const DEFAULT_API_KEY = 'default-secret-api-key-123456';

// 验证API密钥（优先环境变量，其次默认值）
function verifyAPIKey(request, env) {
  const serverApiKey = env.API_KEY || DEFAULT_API_KEY;
  const clientApiKey = request.headers.get('X-API-Key');
  return clientApiKey === serverApiKey;
}

// 处理CORS
function setCORSHeaders(response) {
  response.headers.set('Access-Control-Allow-Origin', '*');
  response.headers.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  response.headers.set('Access-Control-Allow-Headers', 'Content-Type, X-API-Key');
  return response;
}

// 处理OPTIONS预检请求
function handleOptions() {
  return setCORSHeaders(new Response(null, { status: 204 }));
}

// 接收并存储客户端数据（移除网关/子网掩码存储）
async function handleReport(request, env) {
  if (!env.IP_MONITOR_KV) {
    return setCORSHeaders(new Response(JSON.stringify({
      success: false,
      error: 'KV namespace not bound (IP_MONITOR_KV)'
    }), { status: 200, headers: { 'Content-Type': 'application/json' } }));
  }

  if (!verifyAPIKey(request, env)) {
    return setCORSHeaders(new Response(JSON.stringify({
      success: false,
      error: 'Invalid API Key'
    }), { status: 200, headers: { 'Content-Type': 'application/json' } }));
  }

  try {
    const data = await request.json();
    const uuid = (data.uuid || '').toLowerCase().trim();
    
    if (!uuid || !data.username || !Array.isArray(data.networks)) {
      return setCORSHeaders(new Response(JSON.stringify({
        success: false,
        error: 'Missing required fields (uuid/username/networks)'
      }), { status: 200, headers: { 'Content-Type': 'application/json' } }));
    }

    const nowTimestamp = Date.now();
    const storeData = {
      uuid: uuid,
      username: data.username.trim(),
      hostname: (data.hostname || 'Unknown').trim(),
      networks: data.networks.map(net => ({
        interface_name: (net.interface_name || '').trim(),
        ip_address: (net.ip_address || '').trim()
      })),
      timestamp: nowTimestamp,
      lastUpdate: nowTimestamp
    };

    await env.IP_MONITOR_KV.put(
      `device_${uuid}`,
      JSON.stringify(storeData),
      { expirationTtl: KV_EXPIRATION }
    );

    const historyKey = `history_${uuid}`;
    let history = [];
    const existingHistory = await env.IP_MONITOR_KV.get(historyKey, 'json');
    if (existingHistory && Array.isArray(existingHistory)) {
      history = existingHistory;
    }
    history.unshift({
      timestamp: nowTimestamp,
      networks: storeData.networks,
      username: storeData.username,
      hostname: storeData.hostname
    });
    if (history.length > 50) history = history.slice(0, 50);
    await env.IP_MONITOR_KV.put(historyKey, JSON.stringify(history), { expirationTtl: KV_EXPIRATION });

    return setCORSHeaders(new Response(JSON.stringify({
      success: true,
      message: 'Data stored successfully',
      uuid: uuid,
      query_url: `https://${new URL(request.url).hostname}/view/${uuid}`
    }), { status: 200, headers: { 'Content-Type': 'application/json' } }));

  } catch (error) {
    return setCORSHeaders(new Response(JSON.stringify({
      success: false,
      error: `Report failed: ${error.message}`
    }), { status: 200, headers: { 'Content-Type': 'application/json' } }));
  }
}

// 新增：设置UUID的不再提示状态
async function handleSetNoRemind(uuid, env) {
  if (!env.IP_MONITOR_KV) {
    return setCORSHeaders(new Response(JSON.stringify({
      success: false,
      error: 'KV namespace not bound (IP_MONITOR_KV)'
    }), { status: 200, headers: { 'Content-Type': 'application/json' } }));
  }

  const lowerUUID = uuid.toLowerCase().trim();
  try {
    // 存储不再提示状态，过期时间和设备数据一致
    await env.IP_MONITOR_KV.put(
      `no_remind_${lowerUUID}`,
      'true',
      { expirationTtl: KV_EXPIRATION }
    );
    return setCORSHeaders(new Response(JSON.stringify({
      success: true,
      message: 'No remind set successfully'
    }), { status: 200, headers: { 'Content-Type': 'application/json' } }));
  } catch (error) {
    return setCORSHeaders(new Response(JSON.stringify({
      success: false,
      error: error.message
    }), { status: 200, headers: { 'Content-Type': 'application/json' } }));
  }
}

// 处理单个设备查询
async function handleView(uuid, env) {
  if (!env.IP_MONITOR_KV) {
    return new Response(generateErrorHTML('KV namespace not bound (IP_MONITOR_KV)'), {
      status: 500,
      headers: { 'Content-Type': 'text/html; charset=utf-8' }
    });
  }

  const lowerUUID = uuid.toLowerCase().trim();
  try {
    const deviceData = await env.IP_MONITOR_KV.get(`device_${lowerUUID}`, 'json');
    const historyData = await env.IP_MONITOR_KV.get(`history_${lowerUUID}`, 'json');
    // 新增：读取该UUID的不再提示状态
    const noRemind = await env.IP_MONITOR_KV.get(`no_remind_${lowerUUID}`) === 'true';

    if (!deviceData) {
      return new Response(generateNotFoundHTML(lowerUUID), {
        status: 404,
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
      });
    }

    // 新增：将noRemind状态传入HTML生成函数
    return new Response(generateViewHTML(deviceData, historyData || [], noRemind), {
      status: 200,
      headers: { 'Content-Type': 'text/html; charset=utf-8' }
    });

  } catch (error) {
    return new Response(generateErrorHTML(`Query failed: ${error.message}`), {
      status: 500,
      headers: { 'Content-Type': 'text/html; charset=utf-8' }
    });
  }
}

// 处理所有设备列表查询
async function handleList(env) {
  if (!env.IP_MONITOR_KV) {
    return new Response(generateErrorHTML('KV namespace not bound (IP_MONITOR_KV)'), {
      status: 500,
      headers: { 'Content-Type': 'text/html; charset=utf-8' }
    });
  }

  try {
    const listOptions = {
      prefix: 'device_',
      limit: 100
    };
    const deviceKeys = await env.IP_MONITOR_KV.list(listOptions);
    
    if (deviceKeys.keys.length === 0) {
      return new Response(generateListHTML([]), {
        status: 200,
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
      });
    }

    const devices = [];
    for (const key of deviceKeys.keys) {
      const deviceData = await env.IP_MONITOR_KV.get(key.name, 'json');
      if (deviceData) {
        devices.push(deviceData);
      }
    }

    devices.sort((a, b) => b.lastUpdate - a.lastUpdate);

    return new Response(generateListHTML(devices), {
      status: 200,
      headers: { 'Content-Type': 'text/html; charset=utf-8' }
    });

  } catch (error) {
    return new Response(generateErrorHTML(`List query failed: ${error.message}`), {
      status: 500,
      headers: { 'Content-Type': 'text/html; charset=utf-8' }
    });
  }
}

// 生成查看页面HTML（新增noRemind参数，控制提示框显示）
function generateViewHTML(data, history, noRemind) {
  const networks = data.networks || [];
  const formatBeijingTime = (timestamp) => {
    return new Date(timestamp).toLocaleString('zh-CN', {
      timeZone: 'Asia/Shanghai',
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    }).replace(/\//g, '-');
  };

  const timestamp = formatBeijingTime(data.lastUpdate);
  // 控制提示框初始显示状态：noRemind为true则隐藏
  const modalDisplay = noRemind ? 'none' : 'flex';
  
  // 处理IP地址展示（多个IP分行显示，每个带复制按钮）
  const ipContent = networks.length > 0 
    ? networks.map((net, idx) => `
        <div class="copy-item" style="margin-bottom: 8px;${idx === networks.length - 1 ? 'margin-bottom: 0;' : ''}">
            ${net.interface_name}: ${net.ip_address}
            <div class="copy-btn-wrap">
                <span class="copy-tooltip">复制成功</span>
                <button class="copy-btn" onclick="copyText('${net.ip_address}', this)">复制</button>
            </div>
        </div>
      `).join('')
    : '无IP信息';

  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>设备IP信息 - ${data.uuid}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Microsoft YaHei", sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; padding: 20px; }
        .container { max-width: 1000px; margin: 0 auto; background: white; border-radius: 20px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); overflow: hidden; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; }
        .header h1 { font-size: 28px; margin-bottom: 10px; }
        .content { padding: 30px; }
        /* 竖向表格样式 */
        .vertical-table { width: 100%; border-collapse: collapse; background: #f8f9fa; border-radius: 12px; overflow: hidden; margin-bottom: 20px; }
        .vertical-table tr { border-bottom: 1px solid #e0e0e0; }
        .vertical-table tr:last-child { border-bottom: none; }
        .vertical-table th { 
            width: 120px; 
            padding: 15px; 
            text-align: left; 
            font-weight: 600; 
            color: #555; 
            background: #f0f0f0;
        }
        .vertical-table td { 
            padding: 15px; 
            color: #333; 
            word-break: break-all;
        }
        .section-title { font-size: 22px; color: #333; margin: 30px 0 15px 0; padding-bottom: 10px; border-bottom: 3px solid #667eea; }
        .history-item { background: #f8f9fa; border-left: 4px solid #667eea; padding: 15px; margin-bottom: 10px; border-radius: 4px; }
        .history-time { font-weight: 600; color: #667eea; margin-bottom: 8px; }
        .history-detail { font-size: 14px; color: #666; margin: 4px 0; }
        /* 复制相关样式 - 已修复定位 */
        .copy-item {
            display: flex;
            align-items: center;
            gap: 8px;
            flex-wrap: wrap;
        }
        .copy-btn-wrap {
            position: relative; /* 关键：提示框相对按钮容器定位 */
            display: inline-block;
        }
        .copy-btn { 
            padding: 4px 10px; 
            border: none; 
            background: #667eea; 
            color: white; 
            border-radius: 6px; 
            font-size: 12px; 
            cursor: pointer; 
            transition: background 0.2s;
        }
        .copy-btn:hover { background: #5568d3; }
        /* 复制提示框精准定位在按钮正上方 */
        .copy-tooltip {
            position: absolute;
            top: -28px;          
            left: 50%;           
            transform: translateX(-50%); 
            background: #4CAF50;
            color: white;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            white-space: nowrap;
            opacity: 0;
            pointer-events: none;
            transition: opacity 0.2s ease;
            z-index: 999;
        }
        .copy-tooltip.show {
            opacity: 1;
        }
        /* 唯一地址提示框样式 */
        .reminder-modal {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.5);
            display: ${modalDisplay};
            justify-content: center;
            align-items: center;
            z-index: 9999;
        }
        .reminder-content {
            background: white;
            padding: 30px;
            border-radius: 12px;
            max-width: 400px;
            width: 90%;
            text-align: center;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.2);
        }
        .reminder-content p {
            font-size: 16px;
            margin-bottom: 20px;
            line-height: 1.5;
            color: #333;
        }
        .reminder-buttons {
            display: flex;
            gap: 10px;
            justify-content: center;
        }
        .reminder-btn {
            padding: 8px 20px;
            border: none;
            border-radius: 6px;
            font-size: 14px;
            cursor: pointer;
            transition: background 0.2s;
        }
        .btn-confirm {
            background: #e0e0e0;
            color: #333;
        }
        .btn-confirm:hover {
            background: #d0d0d0;
        }
        .btn-no-remind {
            background: #667eea;
            color: white;
        }
        .btn-no-remind:hover {
            background: #5568d3;
        }
        @media (max-width: 768px) { 
            .vertical-table th { width: 100px; padding: 12px; font-size: 14px; }
            .vertical-table td { padding: 12px; font-size: 14px; }
            .history-detail { flex-direction: column; align-items: flex-start; gap: 5px; }
        }
    </style>
</head>
<body>
    <!-- 唯一地址提示框：由服务端noRemind参数控制初始显示 -->
    <div id="reminderModal" class="reminder-modal">
        <div class="reminder-content">
            <p>请保存该地址，这是唯一的查询地址！</p>
            <div class="reminder-buttons">
                <button class="reminder-btn btn-confirm" onclick="closeReminder(false, '${data.uuid}')">好的</button>
                <button class="reminder-btn btn-no-remind" onclick="closeReminder(true, '${data.uuid}')">不再提示</button>
            </div>
        </div>
    </div>

    <div class="container">
        <div class="header">
            <h1>🖥️ 设备IP信息</h1>
        </div>
        <div class="content">
            <!-- 整合后的基础信息竖向表格 -->
            <table class="vertical-table">
                <tr>
                    <th>设备UUID</th>
                    <td>${data.uuid}</td>
                </tr>
                <tr>
                    <th>用户名</th>
                    <td>
                        ${data.username}
                        <div class="copy-btn-wrap">
                            <span class="copy-tooltip">复制成功</span>
                            <button class="copy-btn" onclick="copyText('${data.username.replace(/'/g, "\\'")}', this)">复制</button>
                        </div>
                    </td>
                </tr>
                <tr>
                    <th>IP地址</th>
                    <td>${ipContent}</td>
                </tr>
                <tr>
                    <th>最后更新时间</th>
                    <td>${timestamp}</td>
                </tr>
            </table>

            <!-- 历史记录 -->
            ${history.length > 0 ? `
                <div class="section-title">历史记录 (最近${Math.min(history.length, 3)}条)</div>
                ${history.slice(0, 3).map(item => `
                    <div class="history-item">
                        <div class="history-time">⏰ ${formatBeijingTime(item.timestamp)}</div>
                        <div class="history-detail">
                            👤 用户: ${item.username}
                        </div>
                        ${item.networks.map((net, idx) => `
                            <div class="history-detail">
                                🌐 ${net.interface_name}: ${net.ip_address}
                            </div>
                        `).join('')}
                    </div>
                `).join('')}
            ` : ''}
        </div>
    </div>

    <script>
        // 通用复制函数
        function copyText(text, btn) {
            if (!text || text.trim() === '') {
                alert('暂无可复制内容！');
                return;
            }
            
            navigator.clipboard.writeText(text).then(() => {
                const tooltip = btn.parentElement.querySelector('.copy-tooltip');
                if (tooltip) {
                    tooltip.classList.add('show');
                    setTimeout(() => {
                        tooltip.classList.remove('show');
                    }, 2000);
                }
            }).catch(err => {
                alert('复制失败，请手动复制！');
                console.error('复制失败: ', err);
            });
        }

        // 关闭提示框函数（修改：不再提示时调用后端接口存储状态）
        function closeReminder(setNoRemind, uuid) {
            document.getElementById('reminderModal').style.display = 'none';
            // 如果点击"不再提示"，调用后端接口存储状态
            if (setNoRemind) {
                fetch(\`/api/no-remind/\${uuid}\`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    }
                }).then(res => res.json())
                .catch(err => console.error('设置不再提示失败:', err));
            }
        }
    </script>
</body>
</html>`;
}

// 生成设备列表页面HTML（无复制按钮）
function generateListHTML(devices) {
  const formatBeijingTime = (timestamp) => {
    return new Date(timestamp).toLocaleString('zh-CN', {
      timeZone: 'Asia/Shanghai',
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    }).replace(/\//g, '-');
  };

  // 拼接表格行（无复制按钮）
  const tableRows = devices.map((device, index) => {
    const allIPs = device.networks && device.networks.length > 0
      ? device.networks.map(net => `${net.interface_name}: ${net.ip_address}`).join('<br>')
      : '无IP信息';

    return `
    <tr>
        <td>${index + 1}</td>
        <td class="uuid-cell">${device.uuid}</td>
        <td>${device.username || '未知'}</td>
        <td class="ip-cell">${allIPs}</td>
        <td>${formatBeijingTime(device.lastUpdate)}</td>
        <td>
            <a href="/view/${device.uuid}" class="detail-btn">查看详情</a>
        </td>
    </tr>
    `;
  }).join('');

  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>所有设备列表 - IP查询服务</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Microsoft YaHei", sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; background: white; border-radius: 20px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); overflow: hidden; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; }
        .header h1 { font-size: 28px; margin-bottom: 10px; }
        .header p { font-size: 16px; opacity: 0.9; }
        .content { padding: 30px; }
        /* 表格样式 */
        .device-table { width: 100%; border-collapse: collapse; margin: 20px 0; background: white; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.1); }
        .device-table th { background: #667eea; color: white; padding: 15px; text-align: left; font-weight: 600; font-size: 14px; }
        .device-table td { padding: 12px 15px; border-bottom: 1px solid #f0f0f0; font-size: 14px; color: #333; vertical-align: top; }
        .device-table tr:hover { background: #f8f9fa; }
        .device-table tr:last-child td { border-bottom: none; }
        /* 按钮样式 */
        .detail-btn { 
            display: inline-block;
            padding: 6px 12px;
            background: #667eea; 
            color: white;
            text-decoration: none;
            border-radius: 6px;
            font-size: 12px;
            transition: background 0.2s;
        }
        .detail-btn:hover { background: #5568d3; }
        /* 空数据提示 */
        .empty-state { text-align: center; padding: 60px 20px; color: #666; }
        .empty-state-icon { font-size: 60px; margin-bottom: 20px; color: #ddd; }
        .empty-state h2 { margin-bottom: 10px; font-size: 22px; }
        .empty-state p { font-size: 16px; }
        /* 响应式适配 */
        .uuid-cell { word-break: break-all; }
        .ip-cell { word-break: break-all; }
        @media (max-width: 768px) {
            .content { padding: 15px; }
            .device-table th:nth-child(1), .device-table td:nth-child(1) { min-width: 40px; }
            .device-table th, .device-table td { padding: 10px 8px; font-size: 13px; }
            .detail-btn { padding: 4px 8px; font-size: 11px; }
        }
        @media (max-width: 480px) {
            .device-table th:nth-child(2), .device-table td:nth-child(2) { min-width: 100px; }
            .device-table th:nth-child(5), .device-table td:nth-child(5) { font-size: 12px; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📋 所有设备列表</h1>
            <p>共 ${devices.length} 台设备 | 按最后更新时间排序</p>
        </div>
        <div class="content">
            ${devices.length > 0 ? `
                <table class="device-table">
                    <thead>
                        <tr>
                            <th>序号</th>
                            <th>设备UUID</th>
                            <th>用户名</th>
                            <th>IP地址</th>
                            <th>最后更新时间</th>
                            <th>操作</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${tableRows}
                    </tbody>
                </table>
            ` : `
                <div class="empty-state">
                    <div class="empty-state-icon">📭</div>
                    <h2>暂无设备数据</h2>
                    <p>还没有设备上报信息，设备上报后会在此显示</p>
                </div>
            `}
        </div>
    </div>
</body>
</html>`;
}

// 生成未找到页面
function generateNotFoundHTML(uuid) {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>设备未找到</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Microsoft YaHei", sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; display: flex; justify-content: center; align-items: center; padding: 20px; }
        .error-card { background: white; border-radius: 20px; padding: 40px; text-align: center; max-width: 500px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); }
        .error-icon { font-size: 80px; margin-bottom: 20px; }
        h1 { color: #333; margin-bottom: 10px; }
        p { color: #666; line-height: 1.6; }
        .uuid { background: #f0f0f0; padding: 10px; border-radius: 5px; margin: 20px 0; word-break: break-all; font-family: monospace; }
    </style>
</head>
<body>
    <div class="error-card">
        <div class="error-icon">❌</div>
        <h1>设备未找到</h1>
        <p>未找到UUID为以下值的设备信息：</p>
        <div class="uuid">${uuid}</div>
        <p>可能原因：<br>• 设备尚未上报数据<br>• UUID不正确（区分大小写？）<br>• 数据已过期（超过90天）<br>• KV命名空间未绑定</p>
    </div>
</body>
</html>`;
}

// 生成错误页面
function generateErrorHTML(error) {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>服务器错误</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Microsoft YaHei", sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; display: flex; justify-content: center; align-items: center; padding: 20px; }
        .error-card { background: white; border-radius: 20px; padding: 40px; text-align: center; max-width: 500px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); }
        .error-icon { font-size: 80px; margin-bottom: 20px; }
        h1 { color: #dc3545; margin-bottom: 10px; }
        p { color: #666; }
    </style>
</head>
<body>
    <div class="error-card">
        <div class="error-icon">⚠️</div>
        <h1>服务器错误</h1>
        <p>${error}</p>
    </div>
</body>
</html>`;
}

// 生成首页HTML（仅保留数据查询接口信息）
function generateIndexHTML() {
  const domain = "https://getip.ammon.de5.net";
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IP查询服务</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Microsoft YaHei", sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; display: flex; justify-content: center; align-items: center; padding: 20px; }
        .welcome-card { background: white; border-radius: 20px; padding: 40px; max-width: 600px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); }
        h1 { color: #667eea; margin-bottom: 20px; }
        p { color: #666; line-height: 1.8; margin-bottom: 15px; }
        .code { 
            background: #f5f5f5; 
            padding: 15px; 
            border-radius: 8px; 
            font-family: monospace; 
            margin: 10px 0; 
            line-height: 1.8;
            color: #333;
        }
        .feature { 
            background: #f8f9fa; 
            padding: 20px; 
            border-radius: 8px; 
            margin: 15px 0; 
            border-left: 4px solid #667eea; 
        }
        .feature h3 {
            color: #667eea;
            margin-bottom: 10px;
            font-size: 18px;
        }
        .api-link {
            display: inline-block;
            margin-top: 20px;
            padding: 8px 16px;
            background: #667eea;
            color: white;
            text-decoration: none;
            border-radius: 6px;
            transition: background 0.2s;
        }
        .api-link:hover {
            background: #5568d3;
        }
        .tip {
            color: #999;
            font-size: 14px;
            margin-top: 5px;
        }
    </style>
</head>
<body>
    <div class="welcome-card">
        <h1>🖥️ IP查询服务</h1>
        <p>快速查询设备IP信息，简单易用</p>
        
        <div class="feature">
            <h3>🔍 设备信息查询</h3>
            <div class="code">
访问地址：${domain}/view/{设备UUID}<br>
示例：${domain}/view/12345678-1234-5678-1234-567812345678
            </div>
            <p class="tip">说明：将 {设备UUID} 替换为实际设备的唯一标识即可查询</p>
        </div>
        
        <a href="/api" class="api-link">查看完整API文档</a>
        
        <p style="margin-top: 30px; text-align: center; color: #999;">
            Powered by Cloudflare Workers
        </p>
    </div>
</body>
</html>`;
}

// 生成API文档页面（/api路径）- 包含上报和查询接口
function generateApiDocHTML() {
  const domain = "https://getip.ammon.de5.net";
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>API文档 - IP查询服务</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Microsoft YaHei", sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; padding: 20px; }
        .container { max-width: 800px; margin: 0 auto; background: white; border-radius: 20px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); overflow: hidden; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; }
        .header h1 { font-size: 28px; margin-bottom: 10px; }
        .content { padding: 30px; }
        .back-home {
            display: inline-block;
            margin-bottom: 20px;
            color: #667eea;
            text-decoration: none;
            font-size: 14px;
        }
        .back-home:hover {
            text-decoration: underline;
        }
        .feature { 
            background: #f8f9fa; 
            padding: 20px; 
            border-radius: 8px; 
            margin: 15px 0; 
            border-left: 4px solid #667eea; 
        }
        .feature h3 {
            color: #667eea;
            margin-bottom: 10px;
            font-size: 18px;
        }
        .code { 
            background: #f5f5f5; 
            padding: 15px; 
            border-radius: 8px; 
            font-family: monospace; 
            margin: 10px 0; 
            line-height: 1.8;
            color: #333;
            overflow-x: auto;
        }
        .tip {
            color: #999;
            font-size: 14px;
            margin-top: 5px;
        }
        .list-info {
            margin-top: 20px;
            padding: 15px;
            background: #e8f4f8;
            border-radius: 8px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📖 API接口文档</h1>
            <p>IP查询服务完整接口说明</p>
        </div>
        <div class="content">
            <a href="/" class="back-home">← 返回首页</a>
            
            <div class="feature">
                <h3>📡 数据上报接口</h3>
                <div class="code">
请求方法：POST<br>
访问地址：${domain}/api/report<br>
请求头：X-API-Key: 你的API密钥<br>
Content-Type: application/json<br>
<br>
请求示例：<br>
{
  "uuid": "12345678-1234-5678-1234-567812345678",
  "username": "test_user",
  "networks": [
    {
      "interface_name": "eth0",
      "ip_address": "192.168.1.100"
    }
  ]
}
                </div>
                <p class="tip">说明：用于客户端程序上报设备UUID、用户名、IP地址等信息</p>
            </div>
            
            <div class="feature">
                <h3>🔍 数据查询接口</h3>
                <div class="code">
请求方法：GET<br>
访问地址：${domain}/view/{设备UUID}<br>
示例：${domain}/view/12345678-1234-5678-1234-567812345678
                </div>
                <p class="tip">说明：将 {设备UUID} 替换为实际设备的唯一标识即可查询单设备信息</p>
            </div>
            
            <div class="list-info">
                <h4>📋 设备列表访问</h4>
                <div class="code">
访问地址：${domain}/all/你的API_KEY<br>
示例：${domain}/all/default-secret-api-key-123456
                </div>
                <p class="tip">说明：通过该地址可访问所有设备的列表信息</p>
            </div>
        </div>
    </div>
</body>
</html>`;
}

// 主处理函数（新增/api/no-remind路径处理）
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const rawPath = url.pathname.toLowerCase().trim();
    const serverApiKey = (env.API_KEY || DEFAULT_API_KEY).toLowerCase();
    
    // 处理OPTIONS预检请求
    if (request.method === 'OPTIONS') return handleOptions();

    // 1. 处理/api路径 - API文档页面
    if (rawPath === '/api' && request.method === 'GET') {
      return new Response(generateApiDocHTML(), { 
        status: 200, 
        headers: { 'Content-Type': 'text/html; charset=utf-8' } 
      });
    }

    // 2. 新增：处理设置不再提示接口 /api/no-remind/{uuid}
    const noRemindMatch = rawPath.match(/^\/api\/no-remind\/([a-f0-9\-]+)$/);
    if (noRemindMatch && request.method === 'POST') {
      return await handleSetNoRemind(noRemindMatch[1], env);
    }

    // 3. 数据上报接口 /api/report
    if (rawPath === '/api/report') {
      return request.method === 'POST' ? await handleReport(request, env) : setCORSHeaders(new Response(JSON.stringify({
        success: false,
        error: 'Only POST method is allowed for /api/report'
      }), { status: 200, headers: { 'Content-Type': 'application/json' } }));
    }

    // 4. 处理设备列表路径 /all/api_key
    const listPathMatch = rawPath.match(/^\/all\/([^\/]+)$/);
    if (listPathMatch && request.method === 'GET') {
      const inputApiKey = listPathMatch[1].toLowerCase().trim();
      if (inputApiKey === serverApiKey) {
        return await handleList(env);
      } else {
        return new Response(generateErrorHTML('Invalid API Key for list access'), {
          status: 403,
          headers: { 'Content-Type': 'text/html; charset=utf-8' }
        });
      }
    }

    // 5. 设备详情查询 /view/uuid
    const viewMatch = rawPath.match(/^\/view\/([a-f0-9\-]+)$/);
    if (viewMatch && request.method === 'GET') {
      return await handleView(viewMatch[1], env);
    }

    // 6. 首页 /
    if (rawPath === '/' && request.method === 'GET') {
      return new Response(generateIndexHTML(), { 
        status: 200, 
        headers: { 'Content-Type': 'text/html; charset=utf-8' } 
      });
    }

    // 7. 404提示
    const tipText = `正确路径：<br>
1. 首页: ${url.protocol}//${url.hostname}/<br>
2. API文档: ${url.protocol}//${url.hostname}/api<br>
3. 设备查询: ${url.protocol}//${url.hostname}/view/你的UUID<br>
4. 设备列表: ${url.protocol}//${url.hostname}/all/你的API_KEY`;
    
    return setCORSHeaders(new Response(JSON.stringify({
      success: false,
      error: 'Resource not found',
      tip: tipText
    }), { status: 404, headers: { 'Content-Type': 'application/json' } }));
  }
};