# Windows IP监控系统 - 完整项目包

## 📦 项目内容

本项目包含完整的Windows IP地址监控系统，包括：

### 1. 客户端程序（ip-monitor-client/）
- ✅ Go语言源代码
- ✅ GitHub Actions自动构建配置
- ✅ 完整的依赖管理
- ✅ 开发模式日志窗口

### 2. 服务端程序（cloudflare-worker/）
- ✅ Cloudflare Workers完整代码
- ✅ KV存储集成
- ✅ 美观的Web查询界面
- ✅ Wrangler部署配置

### 3. 完整文档
- ✅ QUICKSTART.md - 15分钟快速部署指南
- ✅ ARCHITECTURE.md - 详细技术架构文档
- ✅ README.md - 完整使用说明

## 🚀 快速开始

### 推荐阅读顺序

1. **首次部署用户** → 先阅读 `QUICKSTART.md`
2. **了解技术细节** → 再阅读 `ARCHITECTURE.md`
3. **日常使用参考** → 查看 `ip-monitor-client/README.md`

### 三步部署

```
第一步：部署Cloudflare Worker（5分钟）
├─ 创建KV命名空间
├─ 部署worker.js
└─ 获取Worker URL

第二步：配置并推送客户端（5分钟）
├─ 修改main.go配置
├─ 推送到GitHub
└─ 等待自动构建

第三步：运行测试（5分钟）
├─ 下载编译好的exe
├─ 运行程序
└─ 访问Web查询页面
```

## 📁 文件结构

```
.
├── ip-monitor-client/              # 客户端项目（推送到GitHub）
│   ├── .github/workflows/
│   │   └── build.yml              # 自动构建配置
│   ├── main.go                    # 主程序（需修改配置）
│   ├── go.mod                     # Go依赖
│   ├── .gitignore                 # Git忽略配置
│   └── README.md                  # 客户端说明
│
├── cloudflare-worker/             # 服务端项目
│   ├── worker.js                  # Worker代码（需修改API密钥）
│   └── wrangler.toml              # Wrangler配置（可选）
│
├── QUICKSTART.md                  # 快速开始指南 ⭐
├── ARCHITECTURE.md                # 架构设计文档
└── PROJECT_README.md              # 本文件
```

## ⚙️ 必须修改的配置

### 在worker.js中（第4行）
```javascript
const API_KEY = 'your-secret-api-key';  // 改成一个复杂密码
```

### 在main.go中（第17-18行）
```go
APIEndpoint = "https://你的worker地址.workers.dev/api/report"
APIKey      = "与worker.js中一致的密码"
```

**重要**：两个API密钥必须完全一致！

## 🎯 核心功能

### 客户端
- [x] 获取网络信息（IP、网关、子网掩码）
- [x] 获取Windows用户名和主机名
- [x] 生成持久化UUID（重启不变）
- [x] 每小时自动上报
- [x] IP变化自动检测（5分钟）
- [x] 开机自动运行
- [x] 日志窗口实时显示

### 服务端
- [x] 接收并验证数据
- [x] KV存储（90天自动过期）
- [x] 历史记录（保存50条）
- [x] 精美Web查询页面
- [x] 全球CDN加速
- [x] 完全免费（中小规模）

## 💡 使用场景

- ✅ 远程设备IP地址跟踪
- ✅ 多台办公电脑统一管理
- ✅ DDNS替代方案
- ✅ 网络环境变化监控
- ✅ 设备在线状态检查

## 📊 技术栈

| 组件 | 技术 | 特点 |
|------|------|------|
| 客户端 | Go 1.21 | 单文件exe，2-3MB |
| 服务端 | Cloudflare Workers | 免费，全球CDN |
| 存储 | Cloudflare KV | NoSQL键值存储 |
| 构建 | GitHub Actions | 自动化CI/CD |
| GUI | lxn/walk | Windows原生界面 |

## 🔐 安全特性

- ✅ API密钥验证
- ✅ HTTPS强制加密
- ✅ UUID访问控制
- ✅ 数据隔离存储
- ✅ 自动过期清理

## 💰 成本分析

### Cloudflare免费额度
- 每天100,000次请求
- 每天1,000次KV写入
- 100,000次KV读取

### 实际用量（每设备）
- 写入：24次/天（每小时1次）
- 流量：约24KB/天

### 容量估算
- **免费支持**：约40台设备
- **调整频率到2小时**：可支持80台设备
- **付费版（$5/月）**：无限设备

## 📝 部署检查清单

部署前：
- [ ] 已安装Git
- [ ] 已有GitHub账号
- [ ] 已有Cloudflare账号
- [ ] 已下载本项目所有文件

Cloudflare配置：
- [ ] 创建KV命名空间
- [ ] 复制命名空间ID
- [ ] worker.js已修改API_KEY
- [ ] Worker已部署
- [ ] KV已绑定到Worker
- [ ] 获得Worker URL

客户端配置：
- [ ] main.go中APIEndpoint已修改
- [ ] main.go中APIKey已修改
- [ ] API密钥与Worker一致
- [ ] 代码已推送到GitHub
- [ ] GitHub Actions已启用

测试验证：
- [ ] 客户端能启动
- [ ] 日志显示上报成功
- [ ] Web页面能访问
- [ ] 页面显示设备信息正确

## 🆘 常见问题

### Q1: 编译后exe太大？
A: 使用以下命令优化：
```bash
go build -ldflags="-s -w" -o ip-monitor.exe
upx --best ip-monitor.exe  # 进一步压缩
```

### Q2: Worker返回401错误？
A: 检查API密钥是否一致：
- worker.js第4行 `API_KEY`
- main.go第18行 `APIKey`

### Q3: 查询页面404？
A: 确认：
- UUID是否正确
- 客户端是否成功上报过
- Worker是否正确部署

### Q4: 如何设置开机自启？
A: 使用Windows任务计划程序：
1. Win+R → `taskschd.msc`
2. 创建基本任务
3. 触发器：系统启动时
4. 操作：运行 ip-monitor.exe

### Q5: GitHub Actions构建失败？
A: 检查：
- `.github/workflows/build.yml` 是否存在
- 文件夹结构是否正确
- 查看Actions日志了解错误

## 📖 文档说明

### QUICKSTART.md
- **适合**: 快速上手用户
- **内容**: 15分钟部署指南
- **特点**: 分步骤，有时间估算

### ARCHITECTURE.md
- **适合**: 技术人员、开发者
- **内容**: 完整技术架构
- **特点**: 详细流程图，实现细节

### ip-monitor-client/README.md
- **适合**: 所有用户
- **内容**: 完整使用说明
- **特点**: 功能介绍，配置说明

## 🔄 版本更新

### v1.0 (当前版本)
- ✅ 基础功能完整实现
- ✅ GitHub Actions自动构建
- ✅ 日志窗口支持
- ✅ 完整文档

### 计划功能
- [ ] IPv6支持
- [ ] 邮件通知
- [ ] Web管理后台
- [ ] 数据导出
- [ ] 配置文件热更新

## 📧 获取帮助

1. **查看文档**
   - QUICKSTART.md - 快速问题
   - ARCHITECTURE.md - 技术问题
   - README.md - 使用问题

2. **GitHub Issues**
   - 提交Bug报告
   - 功能建议
   - 使用疑问

3. **社区支持**
   - 欢迎贡献代码
   - 欢迎完善文档
   - 欢迎分享经验

## 📄 许可证

MIT License - 可自由使用、修改和分发

## 🙏 致谢

感谢以下开源项目：
- Go语言团队
- Cloudflare Workers
- lxn/walk
- GitHub Actions

---

## ⚡ 现在开始

推荐步骤：

1. **阅读 QUICKSTART.md**（必读）
2. **按步骤部署Cloudflare Worker**
3. **修改并推送客户端代码**
4. **下载并测试运行**
5. **访问Web页面验证**

预计总耗时：**15分钟**

祝使用愉快！🎉
