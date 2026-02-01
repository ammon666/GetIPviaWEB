// Cloudflare Workers 服务端代码
// 需要绑定一个KV命名空间，变量名为: IP_MONITOR_KV

const API_KEY = 'your-secret-api-key'; // 修改为你的API密钥，需与客户端一致
const KV_EXPIRATION = 60 * 60 * 24 * 90; // 数据保存90天

// 验证API密钥
function verifyAPIKey(request) {
  const apiKey = request.headers.get('X-API-Key');
  return apiKey === API_KEY;
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
  return setCORSHeaders(new Response(null, {
    status: 204
  }));
}

// 接收并存储客户端数据
async function handleReport(request, env) {
  // 验证API密钥
  if (!verifyAPIKey(request)) {
    return setCORSHeaders(new Response(JSON.stringify({
      success: false,
      error: 'Invalid API Key'
    }), {
      status: 200, // 改为200兼容Go程序（原401，避免客户端判定为失败）
      headers: { 'Content-Type': 'application/json' }
    }));
  }

  try {
    const data = await request.json();
    
    // 验证必需字段
    if (!data.uuid || !data.username || !data.networks) {
      return setCORSHeaders(new Response(JSON.stringify({
        success: false,
        error: 'Missing required fields'
      }), {
        status: 200, // 改为200兼容Go程序（原400）
        headers: { 'Content-Type': 'application/json' }
      }));
    }

    // 准备存储的数据
    const storeData = {
      uuid: data.uuid,
      username: data.username,
      hostname: data.hostname || 'Unknown',
      networks: data.networks,
      timestamp: data.timestamp || new Date().toISOString(),
      lastUpdate: new Date().toISOString()
    };

    // 获取历史记录
    const historyKey = `history_${data.uuid}`;
    let history = [];
    const existingHistory = await env.IP_MONITOR_KV.get(historyKey, 'json');
    if (existingHistory && Array.isArray(existingHistory)) {
      history = existingHistory;
    }

    // 添加新记录到历史（保留最近50条）
    history.unshift({
      timestamp: storeData.timestamp,
      networks: storeData.networks,
      username: storeData.username,
      hostname: storeData.hostname
    });
    if (history.length > 50) {
      history = history.slice(0, 50);
    }

    // 存储当前数据
    await env.IP_MONITOR_KV.put(
      `device_${data.uuid}`,
      JSON.stringify(storeData),
      { expirationTtl: KV_EXPIRATION }
    );

    // 存储历史记录
    await env.IP_MONITOR_KV.put(
      historyKey,
      JSON.stringify(history),
      { expirationTtl: KV_EXPIRATION }
    );

    return setCORSHeaders(new Response(JSON.stringify({
      success: true,
      message: 'Data stored successfully',
      uuid: data.uuid
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    }));

  } catch (error) {
    return setCORSHeaders(new Response(JSON.stringify({
      success: false,
      error: error.message
    }), {
      status: 200, // 改为200兼容Go程序（原500）
      headers: { 'Content-Type': 'application/json' }
    }));
  }
}

// 查询页面
async function handleView(uuid, env) {
  try {
    const deviceData = await env.IP_MONITOR_KV.get(`device_${uuid}`, 'json');
    const historyData = await env.IP_MONITOR_KV.get(`history_${uuid}`, 'json');

    if (!deviceData) {
      return new Response(generateNotFoundHTML(uuid), {
        status: 404,
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
      });
    }

    return new Response(generateViewHTML(deviceData, historyData || []), {
      status: 200,
      headers: { 'Content-Type': 'text/html; charset=utf-8' }
    });

  } catch (error) {
    return new Response(generateErrorHTML(error.message), {
      status: 500,
      headers: { 'Content-Type': 'text/html; charset=utf-8' }
    });
  }
}

// 生成查看页面HTML
function generateViewHTML(data, history) {
  const networks = data.networks || [];
  const timestamp = new Date(data.lastUpdate).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' });

  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>设备信息 - ${data.uuid}</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Microsoft YaHei", sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container {
            max-width: 1000px;
            margin: 0 auto;
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        .header h1 {
            font-size: 28px;
            margin-bottom: 10px;
        }
        .header p {
            opacity: 0.9;
            font-size: 14px;
        }
        .content {
            padding: 30px;
        }
        .info-card {
            background: #f8f9fa;
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 20px;
        }
        .info-row {
            display: flex;
            justify-content: space-between;
            padding: 12px 0;
            border-bottom: 1px solid #e0e0e0;
        }
        .info-row:last-child {
            border-bottom: none;
        }
        .info-label {
            font-weight: 600;
            color: #555;
            min-width: 120px;
        }
        .info-value {
            color: #333;
            flex: 1;
            text-align: right;
            word-break: break-all;
        }
        .network-card {
            background: white;
            border: 2px solid #667eea;
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 15px;
        }
        .network-card h3 {
            color: #667eea;
            margin-bottom: 15px;
            font-size: 18px;
        }
        .section-title {
            font-size: 22px;
            color: #333;
            margin: 30px 0 15px 0;
            padding-bottom: 10px;
            border-bottom: 3px solid #667eea;
        }
        .history-item {
            background: #f8f9fa;
            border-left: 4px solid #667eea;
            padding: 15px;
            margin-bottom: 10px;
            border-radius: 4px;
        }
        .history-time {
            font-weight: 600;
            color: #667eea;
            margin-bottom: 8px;
        }
        .history-detail {
            font-size: 14px;
            color: #666;
            margin: 4px 0;
        }
        .badge {
            display: inline-block;
            background: #667eea;
            color: white;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 12px;
            margin-right: 8px;
        }
        .refresh-btn {
            background: #667eea;
            color: white;
            border: none;
            padding: 12px 30px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 16px;
            margin: 20px auto;
            display: block;
            transition: background 0.3s;
        }
        .refresh-btn:hover {
            background: #5568d3;
        }
        @media (max-width: 768px) {
            .info-row {
                flex-direction: column;
            }
            .info-value {
                text-align: left;
                margin-top: 5px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🖥️ 设备监控信息</h1>
            <p>最后更新时间: ${timestamp}</p>
        </div>
        
        <div class="content">
            <div class="section-title">基本信息</div>
            <div class="info-card">
                <div class="info-row">
                    <span class="info-label">设备UUID</span>
                    <span class="info-value">${data.uuid}</span>
                </div>
                <div class="info-row">
                    <span class="info-label">用户名</span>
                    <span class="info-value">${data.username}</span>
                </div>
                <div class="info-row">
                    <span class="info-label">主机名</span>
                    <span class="info-value">${data.hostname}</span>
                </div>
                <div class="info-row">
                    <span class="info-label">上报时间</span>
                    <span class="info-value">${timestamp}</span>
                </div>
            </div>

            <div class="section-title">当前网络信息</div>
            ${networks.map((net, idx) => `
                <div class="network-card">
                    <h3>网络接口 ${idx + 1}: ${net.interface_name}</h3>
                    <div class="info-row">
                        <span class="info-label">IP地址</span>
                        <span class="info-value"><span class="badge">IPv4</span>${net.ip_address}</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">网关</span>
                        <span class="info-value">${net.gateway || '未知'}</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">子网掩码</span>
                        <span class="info-value">${net.subnet_mask || '未知'}</span>
                    </div>
                </div>
            `).join('')}

            ${history.length > 0 ? `
                <div class="section-title">历史记录 (最近${Math.min(history.length, 10)}条)</div>
                ${history.slice(0, 10).map(item => `
                    <div class="history-item">
                        <div class="history-time">⏰ ${new Date(item.timestamp).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' })}</div>
                        <div class="history-detail">👤 用户: ${item.username} @ ${item.hostname}</div>
                        ${item.networks.map((net, idx) => `
                            <div class="history-detail">🌐 ${net.interface_name}: ${net.ip_address} (网关: ${net.gateway || '未知'})</div>
                        `).join('')}
                    </div>
                `).join('')}
            ` : ''}

            <button class="refresh-btn" onclick="location.reload()">🔄 刷新页面</button>
        </div>
    </div>

    <script>
        // 每30秒自动刷新
        setTimeout(() => location.reload(), 30000);
    </script>
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
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Microsoft YaHei", sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }
        .error-card {
            background: white;
            border-radius: 20px;
            padding: 40px;
            text-align: center;
            max-width: 500px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        }
        .error-icon {
            font-size: 80px;
            margin-bottom: 20px;
        }
        h1 {
            color: #333;
            margin-bottom: 10px;
        }
        p {
            color: #666;
            line-height: 1.6;
        }
        .uuid {
            background: #f0f0f0;
            padding: 10px;
            border-radius: 5px;
            margin: 20px 0;
            word-break: break-all;
            font-family: monospace;
        }
    </style>
</head>
<body>
    <div class="error-card">
        <div class="error-icon">❌</div>
        <h1>设备未找到</h1>
        <p>未找到UUID为以下值的设备信息：</p>
        <div class="uuid">${uuid}</div>
        <p>可能原因：</p>
        <p>• 设备尚未上报数据<br>• UUID不正确<br>• 数据已过期（超过90天）</p>
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
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Microsoft YaHei", sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }
        .error-card {
            background: white;
            border-radius: 20px;
            padding: 40px;
            text-align: center;
            max-width: 500px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        }
        .error-icon {
            font-size: 80px;
            margin-bottom: 20px;
        }
        h1 {
            color: #dc3545;
            margin-bottom: 10px;
        }
        p {
            color: #666;
        }
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

// 首页HTML
function generateIndexHTML() {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IP监控服务</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Microsoft YaHei", sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }
        .welcome-card {
            background: white;
            border-radius: 20px;
            padding: 40px;
            max-width: 600px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        }
        h1 {
            color: #667eea;
            margin-bottom: 20px;
        }
        p {
            color: #666;
            line-height: 1.8;
            margin-bottom: 15px;
        }
        .code {
            background: #f5f5f5;
            padding: 10px;
            border-radius: 5px;
            font-family: monospace;
            margin: 10px 0;
        }
        .feature {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            margin: 10px 0;
            border-left: 4px solid #667eea;
        }
    </style>
</head>
<body>
    <div class="welcome-card">
        <h1>🖥️ IP监控服务</h1>
        <p>欢迎使用IP地址监控服务！</p>
        
        <div class="feature">
            <h3>📡 API端点</h3>
            <div class="code">POST /api/report</div>
            <p>用于客户端上报设备信息</p>
        </div>
        
        <div class="feature">
            <h3>🔍 查询页面</h3>
            <div class="code">GET /view/{UUID}</div>
            <p>查看指定设备的信息和历史记录</p>
        </div>
        
        <p style="margin-top: 30px; text-align: center; color: #999;">
            Powered by Cloudflare Workers
        </p>
    </div>
</body>
</html>`;
}

// 主处理函数（核心修复：严格限定/api/report仅处理POST）
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    // 1. 优先处理OPTIONS预检请求（跨域必备）
    if (request.method === 'OPTIONS') {
      return handleOptions();
    }

    // 2. 严格限定 /api/report 仅处理 POST 请求
    if (path === '/api/report') {
      if (request.method === 'POST') {
        return await handleReport(request, env);
      } else {
        // 非POST请求返回200 + JSON，避免Go程序404/405
        return setCORSHeaders(new Response(JSON.stringify({
          success: false,
          error: 'Only POST method is allowed for /api/report'
        }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' }
        }));
      }
    }

    // 3. 查询路由：展示设备信息（仅GET）
    const viewMatch = path.match(/^\/view\/([a-f0-9\-]+)$/i);
    if (viewMatch && request.method === 'GET') {
      return await handleView(viewMatch[1], env);
    }

    // 4. 根路径：显示使用说明（仅GET）
    if ((path === '/' || path === '') && request.method === 'GET') {
      return new Response(generateIndexHTML(), {
        status: 200,
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
      });
    }

    // 5. 所有未匹配的路由/方法，返回200 + JSON（兼容Go程序，避免404）
    return setCORSHeaders(new Response(JSON.stringify({
      success: false,
      error: 'Resource not found'
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    }));
  }
};