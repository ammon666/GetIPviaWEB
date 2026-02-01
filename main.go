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
	"strings"
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

	// 业务配置（还原第一版的URL）
	APIKey         = "" // 编译时通过-ldflags注入：-X main.APIKey=你的密钥
	WorkersURL     = "https://getip.ammon.de5.net/api/report"  // 第一版上报地址
	ViewURLTemplate = "https://getip.ammon.de5.net/view/%s"    // 第一版浏览器打开地址
	Timeout        = 10 * time.Second
	DefaultInterval = 1 * time.Minute

	// 全局变量
	logger         *eventlog.Log
	machineFixedUUID string
	isFirstRun     bool
	reportInterval time.Duration
)

// init：初始化基础配置（优先执行）
func init() {
	// 1. 创建日志目录（确保权限）
	if err := os.MkdirAll(logDir, 0700); err != nil {
		panic(fmt.Sprintf("创建日志目录失败：%v", err))
	}

	// 2. 校验APIKey（强制编译时注入）
	if APIKey == "" {
		errMsg := "APIKey未配置！请使用编译命令：go build -ldflags \"-X main.APIKey=你的密钥\" -ldflags -H=windowsgui"
		writeLog(errMsg)
		panic(errMsg)
	}

	// 3. 初始化上报间隔
	reportInterval = DefaultInterval

	// 4. 检测是否首次运行
	if _, err := os.Stat(firstRunFlag); os.IsNotExist(err) {
		isFirstRun = true
		writeLog("检测到首次运行，将弹出浏览器")
	} else {
		isFirstRun = false
		writeLog("非首次运行，跳过浏览器弹窗")
	}

	// 5. 生成机器唯一标识（还原第一版逻辑）
	machineFixedUUID = getMachineUUID()
}

// getMachineUUID 生成机器唯一标识（还原第一版简化版）
func getMachineUUID() string {
	// 实际场景可替换为读取硬件信息（如主板序列号）
	return fmt.Sprintf("machine-%s", time.Now().UnixNano())
}

// 主函数：服务入口（处理安装/卸载/运行）
func main() {
	// 强制隐藏控制台窗口（编译+运行双重保障）
	hideConsoleWindow()

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
		// 作为Windows服务运行（完全后台，不受控制台影响）
		if err := svc.Run(serviceName, &ipReportService{}); err != nil {
			logError(fmt.Sprintf("服务运行失败：%v", err))
		}
	} else {
		// 非服务模式也强制后台运行（无控制台）
		logInfo("非服务模式，后台运行（无控制台）")
		runBackground()
	}
}

// hideConsoleWindow 强制隐藏控制台窗口（运行时保障）
func hideConsoleWindow() {
	hwnd := windows.GetConsoleWindow()
	if hwnd != 0 {
		// 隐藏窗口
		windows.ShowWindow(hwnd, windows.SW_HIDE)
		// 从任务栏移除
		windows.SetWindowPos(hwnd, 0, 0, 0, 0, 0, windows.SWP_HIDEWINDOW|windows.SWP_NOMOVE|windows.SWP_NOSIZE)
	}
}

// runBackground 非服务模式下的纯后台运行逻辑（无控制台、关闭控制台不终止）
func runBackground() {
	// 立即上报IP
	logInfo("后台运行模式：立即执行首次上报")
	if err := reportIP(); err != nil {
		logError(fmt.Sprintf("首次上报失败：%v", err))
	} else {
		logInfo("首次上报成功")
	}

	// 首次运行弹浏览器（还原第一版URL）
	if isFirstRun {
		go func() {
			time.Sleep(1 * time.Second)
			logInfo("后台运行模式：启动浏览器展示IP页面")
			if err := openBrowser(fmt.Sprintf(ViewURLTemplate, machineFixedUUID)); err != nil {
				logError(fmt.Sprintf("打开浏览器失败：%v", err))
			}
			// 创建首次运行标记（后续不再弹）
			if err := ioutil.WriteFile(firstRunFlag, []byte(time.Now().String()), 0600); err != nil {
				logError(fmt.Sprintf("写入首次运行标记失败：%v", err))
			}
		}()
	}

	// 启动定时上报（无限循环，不受控制台关闭影响）
	ticker := time.NewTicker(reportInterval)
	defer ticker.Stop()
	logInfo("后台运行模式：开始定时上报（永久运行）")

	// 阻塞主线程（防止程序退出）
	for {
		select {
		case <-ticker.C:
			if err := reportIP(); err != nil {
				logError(fmt.Sprintf("定时上报失败：%v", err))
			} else {
				logInfo("定时上报成功")
			}
		}
	}
}

// ipReportService：实现Windows服务接口
type ipReportService struct{}

// Execute：服务核心逻辑（Windows服务入口）
func (s *ipReportService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	// 1. 服务启动中状态
	const acceptedCmds = svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPauseAndContinue
	changes <- svc.Status{State: svc.StartPending, WaitHint: 2000}

	// 2. 核心逻辑：立即上报IP（每次启动都执行）
	logInfo("服务启动，立即执行首次上报")
	if err := reportIP(); err != nil {
		logError(fmt.Sprintf("首次上报失败：%v", err))
	} else {
		logInfo("首次上报成功")
	}

	// 3. 首次运行弹浏览器（还原第一版URL）
	if isFirstRun {
		go func() {
			time.Sleep(1 * time.Second) // 延迟1秒，避免服务未就绪
			logInfo("启动浏览器展示IP页面")
			if err := openBrowser(fmt.Sprintf(ViewURLTemplate, machineFixedUUID)); err != nil {
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
	logInfo("服务已进入运行状态（完全后台）")

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
				changes <- req.CurrentStatus // 响应状态查询
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

// reportIP：上报IP到服务器（还原第一版逻辑）
func reportIP() error {
	// 1. 获取公网IP
	ip, err := getPublicIP()
	if err != nil {
		return fmt.Errorf("获取公网IP失败：%v", err)
	}

	// 2. 构造上报数据（还原第一版字段）
	payload := map[string]string{
		"api_key":   APIKey,
		"uuid":      machineFixedUUID,
		"ip":        ip,
		"timestamp": time.Now().Format(time.RFC3339),
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("序列化上报数据失败：%v", err)
	}

	// 3. 发送HTTP请求（使用第一版的WorkersURL）
	client := &http.Client{Timeout: Timeout}
	req, err := http.NewRequest("POST", WorkersURL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return fmt.Errorf("创建HTTP请求失败：%v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("发送HTTP请求失败：%v", err)
	}
	defer resp.Body.Close()

	// 4. 校验响应
	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("服务器返回错误状态码：%d，响应内容：%s", resp.StatusCode, string(body))
	}

	return nil
}

// getPublicIP：获取公网IP（还原第一版逻辑）
func getPublicIP() (string, error) {
	client := &http.Client{Timeout: Timeout}
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

// openBrowser：Windows后台打开浏览器（无控制台窗口，还原第一版逻辑）
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
			StartType:   mgr.StartAutomatic, // 开机自动启动（完全后台）
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
		// 无控制台，仅写入文件，不打印
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