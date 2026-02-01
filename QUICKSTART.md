# 快速开始指南

本指南将帮助你在15分钟内完成整个系统的部署。

## 前置要求

- Windows 10/11 电脑
- GitHub账号
- Cloudflare账号（免费）
- Git（可选）

## 第一步：部署Cloudflare Workers（5分钟）

### 1.1 创建KV命名空间

1. 打开 https://dash.cloudflare.com/
2. 左侧菜单选择 **Workers & Pages**
3. 点击 **KV**
4. 点击 **Create a namespace**
5. 名称填写：`IP_MONITOR_KV`
6. 点击 **Add**
7. **重要**：复制生成的命名空间ID（类似：`a1b2c3d4e5f6...`）

### 1.2 创建Worker

1. 返回 **Workers & Pages** 主页
2. 点击 **Create Application**
3. 点击 **Create Worker**
4. 名称填写：`ip-monitor-worker`（可自定义）
5. 点击 **Deploy**

### 1.3 配置Worker

1. 部署成功后，点击 **Edit Code**
2. 删除所有默认代码
3. 打开本项目的 `cloudflare-worker/worker.js` 文件
4. **重要**：修改第4行的API密钥：
   ```javascript
   const API_KEY = 'your-secret-api-key';  // 改成一个复杂的密码，例如：MyS3cr3tK3y!2024
   ```
5. 复制全部代码，粘贴到Worker编辑器
6. 点击右上角 **Save and Deploy**

### 1.4 绑定KV存储

1. 点击顶部的 **Settings**
2. 找到 **Variables** 部分
3. 滚动到 **KV Namespace Bindings**
4. 点击 **Edit variables**
5. 点击 **Add binding**
   - Variable name: `IP_MONITOR_KV`
   - KV namespace: 选择刚才创建的 `IP_MONITOR_KV`
6. 点击 **Save**

### 1.5 获取Worker URL

1. 点击顶部的项目名称（如 `ip-monitor-worker`）
2. 右侧会显示URL，格式类似：
   ```
   https://ip-monitor-worker.你的账号.workers.dev
   ```
3. **重要**：复制这个URL，后面要用

## 第二步：配置客户端代码（3分钟）

### 2.1 下载项目

**方法A：使用Git**
```bash
git clone https://github.com/your-username/ip-monitor-client.git
cd ip-monitor-client
```

**方法B：直接下载**
1. 下载本项目的所有文件
2. 放在一个文件夹中，如 `D:\ip-monitor-client`

### 2.2 修改配置

1. 用记事本或VS Code打开 `main.go` 文件
2. 找到第17-18行：
   ```go
   APIEndpoint    = "https://your-worker.workers.dev/api/report"
   APIKey         = "your-secret-api-key"
   ```
3. 修改为：
   ```go
   APIEndpoint    = "https://ip-monitor-worker.你的账号.workers.dev/api/report"  // 替换为你的Worker URL + /api/report
   APIKey         = "MyS3cr3tK3y!2024"  // 替换为你在worker.js中设置的密钥（必须一致！）
   ```
4. 保存文件

## 第三步：推送到GitHub（3分钟）

### 3.1 创建GitHub仓库

1. 打开 https://github.com/new
2. Repository name: `ip-monitor-client`
3. 选择 **Public** 或 **Private**
4. **不要**勾选 "Add a README file"
5. 点击 **Create repository**

### 3.2 推送代码

在项目文件夹中打开命令行（或Git Bash），执行：

```bash
# 初始化Git（如果还没有）
git init

# 添加远程仓库（替换为你的仓库地址）
git remote add origin https://github.com/你的用户名/ip-monitor-client.git

# 添加所有文件
git add .

# 提交
git commit -m "Initial commit"

# 推送（第一次需要设置upstream）
git push -u origin main
```

如果推送到master分支：
```bash
git push -u origin master
```

## 第四步：等待构建（2分钟）

### 4.1 查看构建状态

1. 打开你的GitHub仓库页面
2. 点击 **Actions** 标签
3. 应该能看到一个正在运行的工作流："Build and Release"
4. 等待约1-2分钟，直到显示绿色✓

### 4.2 下载编译好的程序

1. 点击完成的工作流
2. 滚动到底部 **Artifacts** 部分
3. 点击 `ip-monitor-windows` 下载
4. 解压zip文件，得到 `ip-monitor.exe`

## 第五步：运行测试（2分钟）

### 5.1 首次运行

1. 双击 `ip-monitor.exe`
2. 会弹出一个日志窗口
3. 查看日志，应该看到：
   ```
   [时间] ========== 程序启动 ==========
   [时间] 生成新UUID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
   [时间] 收集到的信息:
   [时间]   UUID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
   [时间]   用户名: DESKTOP\你的用户名
   [时间]   网络接口 1:
   [时间]     IP地址: 192.168.1.xxx
   [时间] 数据已成功发送到Cloudflare
   ```
4. **重要**：复制显示的UUID

### 5.2 查看Web页面

1. 打开浏览器
2. 访问：`https://你的Worker地址/view/你的UUID`
   
   例如：
   ```
   https://ip-monitor-worker.xxx.workers.dev/view/12345678-1234-1234-1234-123456789abc
   ```
3. 应该能看到漂亮的信息展示页面

## 完成！🎉

如果你能看到Web页面显示了你的设备信息，说明部署成功！

### 下一步

1. **设置开机自启**（可选）
   - 参考主README的"设置开机自启"部分

2. **部署到更多设备**
   - 从GitHub下载 `ip-monitor.exe`
   - 复制到其他Windows电脑
   - 直接运行即可（会自动生成新的UUID）

3. **查看所有设备**
   - 每台设备都有独立的UUID
   - 访问 `https://你的Worker地址/view/UUID` 查看各自信息

## 常见问题

### Q1: 日志显示"服务器返回错误: 401"

**原因**：API密钥不匹配

**解决**：
1. 检查 `main.go` 中的 `APIKey`
2. 检查 `worker.js` 中的 `API_KEY`
3. 确保两者完全一致
4. 重新编译并部署

### Q2: Actions构建失败

**原因**：可能是工作流文件格式问题

**解决**：
1. 检查 `.github/workflows/build.yml` 是否存在
2. 查看Actions页面的错误日志
3. 确保文件夹结构正确

### Q3: Web页面显示"设备未找到"

**原因**：数据还没上报成功

**解决**：
1. 查看客户端日志确认是否上报成功
2. 确认UUID是否正确
3. 等待1-2分钟后刷新页面

### Q4: 程序无法启动

**原因**：可能是Windows Defender阻止

**解决**：
1. 右键程序 → 属性 → 解除锁定
2. 添加到Windows Defender白名单
3. 或者在本地自己编译

## 获取帮助

如果遇到问题：
1. 查看主README的"常见问题"部分
2. 查看ARCHITECTURE.md了解技术细节
3. 在GitHub仓库提交Issue

---

**预计总耗时**: 15分钟  
**难度等级**: ⭐⭐☆☆☆（简单）
