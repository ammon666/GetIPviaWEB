package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings" // 新增：导入strings包
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

// 全局配置
var (
	// 路径配置（使用ProgramData，确保Local System账户可读写）
	logDir         = filepath.Join(os.Getenv("ProgramData"), "IPReportService")
	logPath        = filepath.Join(logDir, "service.log")
	firstRunFlag   = filepath.Join(logDir, "first_run.flag") // 首次运行标记

	// 服务核心配置
	serviceName    = "IPReportService"       // 服务内部名称（唯一）
	displayName    = "IP自动上报服务"          // 服务显示名称
	serviceDesc    = "后台运行，每次启动上报IP，仅首次打开弹浏览器"

	// 业务配置
	APIKey         = "" // 编译时通过-ldflags注入：-X main.APIKey=你的密钥
	reportURL      = "https://getip.ammon.de5.net/api/report"
	viewURL        = "https://getip.ammon.de5.net/view/%s"
	timeout        = 10 * time.Second
	reportInterval = 1 * time.Minute

	// 全局变量
	logger         *eventlog.Log
	machineUUID    string
	isFirstRun     bool
)

// init：初始化基础配置（优先执行）
func init() {
	// 1. 创建日志目录（确保权限）
	if err := os.MkdirAll(logDir, 0700); err != nil {
		panic(fmt.Sprintf("创建日志目录失败：%v", err))
	}

	// 2. 校验APIKey（强制编译时注入）
	if APIKey == "" {
		errMsg := "APIKey未配置！请使用编译命令：go build -ldflags \"-X main.APIKey=你的密钥\""
		writeLog(errMsg)
		panic(errMsg)
	}

	// 3. 检测是否首次运行
	if _, err := os.Stat(firstRunFlag); os.IsNotExist(err) {
		isFirstRun = true
		writeLog("检测到首次运行，将弹出浏览器")
	} else {
		isFirstRun = false
		writeLog("非首次运行，跳过浏览器弹窗")
	}

	// 4. 生成机器唯一标识（简化版，可替换为硬件信息）
	machineUUID = fmt.Sprintf("uuid_%d", time.Now().UnixNano())
}

// 主函数：服务入口（处理安装/卸载/运行）
func main() {
	// 初始化事件日志（Windows服务标准日志）
	var err error
	logger, err = eventlog.Open(serviceName)
	if err != nil {
		writeLog(fmt.Sprintf("事件日志初始化失败：%v", err))
		// 即使事件日志失败，仍继续运行（写入文件日志）
	}
	defer func() {
		if logger != nil {
			logger.Close()
		}
	}()

	// 解析命令行参数
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "install":
			if err := installService(); err != nil {
				logError(fmt.Sprintf("安装服务失败：%v", err))
				return
			}
			logInfo("服务安装成功")
			return
		case "uninstall":
			if err := uninstallService(); err != nil {
				logError(fmt.Sprintf("卸载服务失败：%v", err))
				return
			}
			logInfo("服务卸载成功")
			return
		case "start":
			if err := startService(); err != nil {
				logError(fmt.Sprintf("启动服务失败：%v", err))
				return
			}
			logInfo("服务启动成功")
			return
		case "stop":
			if err := stopService(); err != nil {
				logError(fmt.Sprintf("停止服务失败：%v", err))
				return
			}
			logInfo("服务停止成功")
			return
		}
	}

	// 无参数：以服务方式运行（核心）
	isService, err := svc.IsWindowsService()
	if err != nil {
		logError(fmt.Sprintf("检测服务环境失败：%v", err))
		return
	}
	if isService {
		// 作为Windows服务运行（后台）
		if err := svc.Run(serviceName, &ipReportService{}); err != nil {
			logError(fmt.Sprintf("服务运行失败：%v", err))
		}
	} else {
		// 控制台调试运行（方便测试）
		logInfo("非服务模式，控制台运行（调试用）")
		runConsole()
	}
}

// ipReportService：实现Windows服务接口
type ipReportService struct{}

// Execute：服务核心逻辑（Windows服务入口）
func (s *ipReportService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	// 1. 服务启动中状态
	// 修复：移除错误的svc.AcceptInterrogate，Interrogate是默认支持的，无需显式声明
	const acceptedCmds = svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPauseAndContinue
	changes <- svc.Status{State: svc.StartPending, WaitHint: 2000}

	// 2. 核心逻辑：立即上报IP（每次启动都执行）
	logInfo("服务启动，立即执行首次上报")
	if err := reportIP(); err != nil {
		logError(fmt.Sprintf("首次上报失败：%v", err))
	} else {
		logInfo("首次上报成功")
	}

	// 3. 首次运行弹浏览器（仅第一次）
	if isFirstRun {
		go func() {
			time.Sleep(1 * time.Second) // 延迟1秒，避免服务未就绪
			logInfo("启动浏览器展示IP页面")
			if err := openBrowser(fmt.Sprintf(viewURL, machineUUID)); err != nil {
				logError(fmt.Sprintf("打开浏览器失败：%v", err))
			}
			// 创建首次运行标记（后续不再弹）
			if err := ioutil.WriteFile(firstRunFlag, []byte(time.Now().String()), 0600); err != nil {
				logError(fmt.Sprintf("写入首次运行标记失败：%v", err))
			}
		}()
	}

	// 4. 启动定时上报
	ticker := time.NewTicker(reportInterval)
	defer ticker.Stop()

	// 5. 服务就绪：切换为运行状态
	changes <- svc.Status{State: svc.Running, Accepts: acceptedCmds}
	logInfo("服务已进入运行状态（后台）")

	// 6. 服务主循环（处理指令+定时任务）
loop:
	for {
		select {
		case <-ticker.C:
			// 定时上报
			if err := reportIP(); err != nil {
				logError(fmt.Sprintf("定时上报失败：%v", err))
			} else {
				logInfo("定时上报成功")
			}
		case req := <-r:
			// 处理服务控制指令（停止/暂停/查询等）
			switch req.Cmd {
			case svc.Interrogate:
				changes <- req.CurrentStatus // 响应状态查询（无需额外配置）
			case svc.Stop, svc.Shutdown:
				logInfo("收到停止指令，服务即将退出")
				changes <- svc.Status{State: svc.StopPending, WaitHint: 1000}
				break loop // 退出主循环
			case svc.Pause:
				logInfo("服务暂停")
				ticker.Stop()
				changes <- svc.Status{State: svc.Paused, Accepts: acceptedCmds}
			case svc.Continue:
				logInfo("服务恢复运行")
				ticker.Reset(reportInterval)
				changes <- svc.Status{State: svc.Running, Accepts: acceptedCmds}
			default:
				logError(fmt.Sprintf("收到未知指令：%v", req))
			}
		}
	}

	// 7. 服务停止
	changes <- svc.Status{State: svc.Stopped}
	logInfo("服务已停止")
	return false, 0
}

// reportIP：上报IP到服务器（核心业务逻辑）
func reportIP() error {
	// 1. 获取公网IP
	ip, err := getPublicIP()
	if err != nil {
		return fmt.Errorf("获取公网IP失败：%v", err)
	}

	// 2. 构造上报数据
	payload := map[string]string{
		"api_key":   APIKey,
		"uuid":      machineUUID,
		"ip":        ip,
		"timestamp": time.Now().Format(time.RFC3339),
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("序列化数据失败：%v", err)
	}

	// 3. 发送HTTP请求
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequest("POST", reportURL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return fmt.Errorf("创建请求失败：%v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("发送请求失败：%v", err)
	}
	defer resp.Body.Close()

	// 4. 校验响应
	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("服务器返回错误：%d，内容：%s", resp.StatusCode, string(body))
	}

	return nil
}

// getPublicIP：获取公网IP（稳定接口）
func getPublicIP() (string, error) {
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get("https://api.ipify.org?format=text")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	ipBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(ipBytes), nil
}

// openBrowser：Windows后台打开浏览器（无控制台窗口）
func openBrowser(url string) error {
	// 关键：设置进程属性，隐藏控制台窗口
	cmd := exec.Command("cmd", "/c", "start", "", url)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: windows.CREATE_NO_WINDOW, // 正确的常量使用
	}
	return cmd.Start()
}

// ---------- 服务安装/卸载/启停 辅助函数 ----------
func installService() error {
	// 1. 连接服务管理器
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	// 2. 检查服务是否已存在
	if _, err := m.OpenService(serviceName); err == nil {
		return fmt.Errorf("服务%s已存在", serviceName)
	}

	// 3. 获取当前程序路径
	exePath, err := os.Executable()
	if err != nil {
		return err
	}

	// 4. 创建服务（核心：正确配置服务参数）
	s, err := m.CreateService(
		serviceName,
		exePath,
		mgr.Config{
			DisplayName: displayName,
			Description: serviceDesc,
			StartType:   mgr.StartAutomatic, // 开机自动启动（可选：StartManual手动）
		},
	)
	if err != nil {
		return err
	}
	defer s.Close()

	// 5. 注册事件日志（可选，增强日志）
	return eventlog.InstallAsEventCreate(serviceName, eventlog.Error|eventlog.Warning|eventlog.Info)
}

func uninstallService() error {
	// 1. 先停止服务（如果运行中）
	if err := stopService(); err != nil && !strings.Contains(err.Error(), "服务未运行") {
		return err
	}

	// 2. 连接服务管理器
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	// 3. 删除服务
	s, err := m.OpenService(serviceName)
	if err != nil {
		return err
	}
	defer s.Close()

	if err := s.Delete(); err != nil {
		return err
	}

	// 4. 移除事件日志
	return eventlog.Remove(serviceName)
}

func startService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return err
	}
	defer s.Close()

	return s.Start("is", "manual-start")
}

func stopService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return err
	}
	defer s.Close()

	// 发送停止指令
	status, err := s.Control(svc.Stop)
	if err != nil {
		return err
	}

	// 等待服务停止
	for status.State != svc.Stopped {
		time.Sleep(100 * time.Millisecond)
		status, err = s.Query()
		if err != nil {
			return err
		}
	}
	return nil
}

// ---------- 日志辅助函数 ----------
func writeLog(msg string) {
	logMsg := fmt.Sprintf("[%s] %s\n", time.Now().Format("2006-01-02 15:04:05"), msg)
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		fmt.Printf("写入日志失败：%v，内容：%s\n", err, logMsg)
		return
	}
	defer f.Close()
	_, _ = f.WriteString(logMsg)
}

func logInfo(msg string) {
	writeLog("[INFO] " + msg)
	if logger != nil {
		logger.Info(1, msg)
	}
}

func logError(msg string) {
	writeLog("[ERROR] " + msg)
	if logger != nil {
		logger.Error(1, msg)
	}
}

// ---------- 控制台调试函数（非服务模式） ----------
func runConsole() {
	// 立即上报
	logInfo("控制台模式：立即上报IP")
	if err := reportIP(); err != nil {
		logError(fmt.Sprintf("上报失败：%v", err))
	}

	// 首次弹浏览器
	if isFirstRun {
		logInfo("控制台模式：打开浏览器")
		_ = openBrowser(fmt.Sprintf(viewURL, machineUUID))
		_ = ioutil.WriteFile(firstRunFlag, []byte("1"), 0600)
	}

	// 模拟定时上报（控制台可按Ctrl+C退出）
	ticker := time.NewTicker(reportInterval)
	defer ticker.Stop()
	logInfo("控制台模式：开始定时上报（按Ctrl+C退出）")
	for range ticker.C {
		if err := reportIP(); err != nil {
			logError(fmt.Sprintf("定时上报失败：%v", err))
		} else {
			logInfo("定时上报成功")
		}
	}
}