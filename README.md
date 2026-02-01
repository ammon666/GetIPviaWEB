# Windows IP地址监控系统

完整的Windows设备IP地址监控解决方案，包含Go客户端和Cloudflare Workers服务端。

## 📋 系统架构

```
┌─────────────────┐
│  Windows客户端  │
│   (Go程序)      │
│                 │
│  - 获取网络信息 │
│  - 生成UUID     │
│  - 定时上报     │
│  - IP变化检测   │
└────────┬────────┘
         │ HTTPS
         │ (每小时 + IP变化时)
         ▼
┌─────────────────┐
│ Cloudflare      │
│   Workers       │
│                 │
│  - 接收数据     │
│  - 存储到KV     │
│  - 提供查询页面 │
└─────────────────┘
```

## ✨ 功能特性

### 客户端功能
- ✅ 自动获取活动网卡的IPv4地址、网关、子网掩码
- ✅ 获取Windows登录用户名和主机名
- ✅ 首次运行生成唯一UUID并持久化存储
- ✅ 每小时自动上报数据到Cloudflare
- ✅ 检测IP地址变化（5分钟检查一次）
- ✅ 开机自动上报
- ✅ 开发模式：带日志输出窗口
- ✅ 轻量级：编译后仅2-3MB
- ✅ 无需.NET、Python等运行时环境

### 服务端功能
- ✅ 接收并存储设备信息
- ✅ 按UUID分别存储不同设备数据
- ✅ 保存最近50条历史记录
- ✅ 提供美观的Web查询界面
- ✅ 数据自动过期（90天）
- ✅ 免费（Cloudflare免费套餐）

## 🚀 快速开始

### 1. 部署Cloudflare Workers

#### 1.1 创建KV命名空间

1. 登录 [Cloudflare Dashboard](https://dash.cloudflare.com/)
2. 进入 Workers & Pages → KV
3. 点击 "Create namespace"
4. 命名为 `IP_MONITOR_KV`
5. 复制创建后的命名空间ID

#### 1.2 部署Worker

**方法A：使用Wrangler CLI（推荐）**

```bash
# 安装Wrangler
npm install -g wrangler

# 登录Cloudflare
wrangler login

# 修改wrangler.toml，填入你的KV命名空间ID
# id = "your_kv_namespace_id"

# 修改worker.js中的API密钥
# const API_KEY = 'your-secret-api-key';

# 部署
wrangler deploy
```

**方法B：通过Dashboard手动部署**

1. 进入 Workers & Pages → Create Application → Create Worker
2. 点击 "Quick Edit"，将 `worker.js` 的内容粘贴进去
3. 点击 Settings → Variables → KV Namespace Bindings
4. 添加绑定：变量名 `IP_MONITOR_KV`，选择刚创建的KV命名空间
5. 保存并部署

#### 1.3 获取Worker URL

部署成功后，会得到一个URL，格式如：
```
https://ip-monitor-worker.your-account.workers.dev
```

记录这个URL，后续客户端配置需要用到。

### 2. 配置并编译客户端

#### 2.1 克隆仓库

```bash
git clone https://github.com/your-username/ip-monitor-client.git
cd ip-monitor-client
```

#### 2.2 修改配置

编辑 `main.go`，修改以下常量：

```go
const (
    APIEndpoint = "https://your-worker.workers.dev/api/report"  // 改为你的Worker URL
    APIKey      = "your-secret-api-key"                         // 改为你设置的API密钥
)
```

**重要**：`APIKey` 必须与 `worker.js` 中的 `API_KEY` 保持一致！

#### 2.3 本地编译（可选）

如果想本地编译测试：

```bash
# 下载依赖
go mod download

# 编译（带日志窗口）
go build -ldflags="-s -w -H windowsgui" -o ip-monitor.exe

# 运行测试
./ip-monitor.exe
```

#### 2.4 推送到GitHub

```bash
git add .
git commit -m "Initial commit"
git push origin main
```

### 3. GitHub Actions自动构建

#### 3.1 启用Actions

1. 进入你的GitHub仓库
2. 点击 Actions 标签
3. 如果提示启用，点击启用

#### 3.2 自动构建

每次推送到 `main` 或 `master` 分支时，GitHub Actions会自动：
- 编译Windows可执行文件
- 生成构建信息
- 上传为Artifacts

#### 3.3 创建Release（可选）

如果想发布版本：

```bash
# 创建标签
git tag v1.0.0
git push origin v1.0.0
```

GitHub Actions会自动创建Release并上传编译好的文件。

### 4. 部署客户端到Windows

#### 4.1 下载程序

从GitHub Actions的Artifacts或Release中下载 `ip-monitor.exe`

#### 4.2 首次运行

双击运行 `ip-monitor.exe`，会看到日志窗口，显示：
- 生成的UUID
- 当前网络信息
- 数据上报状态

#### 4.3 设置开机自启（可选）

**方法A：任务计划程序**

1. Win+R 输入 `taskschd.msc` 打开任务计划程序
2. 创建基本任务
3. 触发器：计算机启动时
4. 操作：启动程序，选择 `ip-monitor.exe`
5. 条件：取消勾选"只有在使用交流电源时才启动"

**方法B：启动文件夹**

将 `ip-monitor.exe` 的快捷方式放到：
```
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp
```

**注意**：如需在登录前运行，建议使用任务计划程序方法。

## 📖 使用说明

### 查看设备信息

1. 运行客户端后，在日志窗口找到UUID
2. 在浏览器访问：`https://your-worker.workers.dev/view/你的UUID`
3. 页面会显示：
   - 设备基本信息（UUID、用户名、主机名）
   - 当前网络信息（IP、网关、子网掩码）
   - 历史记录（最近10条）

### 日志文件位置

- 配置文件：`%APPDATA%\IPMonitor\config.json`
- 日志文件：`%APPDATA%\IPMonitor\monitor.log`

通常位于：
```
C:\Users\你的用户名\AppData\Roaming\IPMonitor\
```

## 🔧 配置说明

### 客户端配置

在 `main.go` 中可以调整：

```go
const (
    CheckInterval  = 1 * time.Hour          // 定时上报间隔
    APIEndpoint    = "..."                  // Worker API地址
    APIKey         = "..."                  // API密钥
)
```

### 服务端配置

在 `worker.js` 中可以调整：

```javascript
const API_KEY = 'your-secret-api-key';      // API密钥
const KV_EXPIRATION = 60 * 60 * 24 * 90;    // 数据保存时长（秒）
```

## 🛠️ 高级功能

### 关闭日志窗口

如果不需要日志窗口，修改编译命令：

```bash
# 去掉 -H windowsgui 参数
go build -ldflags="-s -w" -o ip-monitor.exe
```

或修改 `.github/workflows/build.yml`：

```yaml
- name: Build
  run: |
    go build -ldflags="-s -w" -o ip-monitor.exe
```

### 进一步压缩体积

使用UPX压缩（可选）：

```bash
# 安装UPX：https://upx.github.io/
upx --best ip-monitor.exe
```

可将体积压缩到1-2MB。

### 自定义网关检测

默认的网关检测是通过IP推导（最后一位改为.1），如需精确检测：

1. 安装 `github.com/jackpal/gateway` 包
2. 修改 `getDefaultGateway()` 函数使用该包

## 📊 成本分析

### Cloudflare Workers免费额度

- 每天100,000次请求
- 每天1,000次KV写入
- 100,000次KV读取

### 实际使用

假设40台设备，每小时上报一次：
- 每天写入：40 × 24 = 960次 ✅ 在限额内
- 查询页面访问：取决于实际使用

**结论**：中小规模使用完全免费！

如果设备数量超过40台：
- 考虑升级到Workers付费计划（$5/月）
- 或调整上报频率（如改为2小时）

## 🔐 安全建议

1. **API密钥**：使用强密码，客户端和服务端保持一致
2. **HTTPS**：Cloudflare自动提供，确保数据传输安全
3. **访问控制**：UUID作为访问凭证，保管好UUID
4. **数据隐私**：避免在公共环境暴露查询页面URL

## ❓ 常见问题

### 1. 编译失败：找不到包

运行：
```bash
go mod download
go mod tidy
```

### 2. 运行时提示"无法连接到服务器"

检查：
- Worker是否正确部署
- `APIEndpoint` 地址是否正确
- API密钥是否匹配
- 网络连接是否正常

### 3. 查询页面显示"设备未找到"

可能原因：
- 客户端还未成功上报过数据
- UUID不正确
- 数据已过期（超过90天）

查看客户端日志确认是否上报成功。

### 4. GitHub Actions构建失败

检查：
- `.github/workflows/build.yml` 文件格式是否正确
- 仓库是否启用了Actions
- 查看Actions日志了解具体错误

### 5. Windows Defender报毒

Go编译的程序可能被误报，解决方法：
- 添加到白名单
- 使用代码签名证书签名程序

## 📝 开发计划

- [ ] 支持IPv6地址获取
- [ ] 添加邮件通知（IP变化时）
- [ ] Web管理界面（管理多个设备）
- [ ] 数据导出功能（CSV/JSON）
- [ ] 支持自定义上报间隔（通过配置文件）

## 📄 许可证

MIT License

## 🤝 贡献

欢迎提交Issue和Pull Request！

## 📧 联系方式

如有问题，请通过GitHub Issues联系。

---

**温馨提示**：首次使用建议先在测试环境部署，确认功能正常后再大规模部署。
