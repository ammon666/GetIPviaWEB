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
	"runtime"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

// 手动声明Windows API常量（解决未定义问题）
const (
	SW_HIDE            = 0
	SWP_HIDEWINDOW     = 0x0080
	SWP_NOMOVE         = 0x0002
	SWP_NOSIZE         = 0x0001
	CREATE_NO_WINDOW   = 0x08000000

	// 日志相关常量
	LogMaxSize    = 10 * 1024 * 1024 // 单个日志文件最大10MB
	LogMaxBackups = 5                // 最多保留5个备份日志
	LogLevelDebug = "DEBUG"
	LogLevelInfo  = "INFO"
	LogLevelWarn  = "WARN"
	LogLevelError = "ERROR"
)

// 手动声明Windows API函数（解决未定义问题）
var (
	kernel32                = syscall.NewLazyDLL("kernel32.dll")
	user32                  = syscall.NewLazyDLL("user32.dll")
	procGetConsoleWindow    = kernel32.NewProc("GetConsoleWindow")
	procShowWindow          = user32.NewProc("ShowWindow")
	procSetWindowPos        = user32.NewProc("SetWindowPos")
)

// 日志配置结构体
type Logger struct {
	logDir        string
	logFile       string
	maxSize       int64
	maxBackups    int
	eventLog      *eventlog.Log
	serviceName   string
}

// 全局配置
var (
	// 路径配置（使用ProgramData，确保Local System账户可读写）
	logDir                 = filepath.Join(os.Getenv("ProgramData"), "IPReportService")
	logPath                = filepath.Join(logDir, "service.log")
	firstRunFlag           = filepath.Join(logDir, "first_run.flag") // 首次运行标记

	// 服务核心配置
	serviceName            = "IPReportService"       // 服务内部名称（唯一）
	displayName            = "IP自动上报服务"          // 服务显示名称
	serviceDesc            = "后台运行，每次启动上报IP，仅首次打开弹浏览器"

	// 业务配置（还原第一版的URL）
	APIKey                 = "" // 编译时通过-ldflags注入：-X main.APIKey=你的密钥
	WorkersURL             = "https://getip.ammon.de5.net/api/report"  // 第一版上报地址
	ViewURLTemplate        = "https://getip.ammon.de5.net/view/%s"    // 第一版浏览器打开地址
	Timeout                = 10 * time.Second
	DefaultInterval        = 1 * time.Minute

	// 全局变量
	logger                 *Logger // 替换原有eventlog，使用增强日志
	machineFixedUUID       string
	isFirstRun             bool
	reportInterval         time.Duration
)

// init：初始化基础配置（优先执行）
func init() {
	// 1. 创建日志目录（确保权限）
	if err := os.MkdirAll(logDir, 0700); err != nil {
		panic(fmt.Sprintf("创建日志目录失败：%v", err))
	}

	// 2. 初始化增强日志器
	var eventLog *eventlog.Log
	el, err := eventlog.Open(serviceName)
	if err != nil {
		fmt.Printf("事件日志初始化失败，仅使用文件日志：%v\n", err)
	} else {
		eventLog = el
	}
	logger = &Logger{
		logDir:        logDir,
		logFile:       logPath,
		maxSize:       LogMaxSize,
		maxBackups:    LogMaxBackups,
		eventLog:      eventLog,
		serviceName:   serviceName,
	}

	// 3. 校验APIKey（强制编译时注入）
	if APIKey == "" {
		errMsg := "APIKey未配置！请使用编译命令：go build -ldflags \"-X main.APIKey=你的密钥\" -H=windowsgui"
		logger.Error(errMsg)
		panic(errMsg)
	}
	logger.Info("APIKey注入成功，长度：%d", len(APIKey))

	// 4. 初始化上报间隔
	reportInterval = DefaultInterval
	logger.Debug("上报间隔初始化：%v", reportInterval)

	// 5. 检测是否首次运行
	if _, err := os.Stat(firstRunFlag); os.IsNotExist(err) {
		isFirstRun = true
		logger.Info("检测到首次运行，将弹出浏览器")
	} else {
		isFirstRun = false
		logger.Info("非首次运行，跳过浏览器弹窗")
	}

	// 6. 生成机器唯一标识（还原第一版逻辑）
	machineFixedUUID = getMachineUUID()
	logger.Debug("生成机器唯一标识：%s", machineFixedUUID)
}

// getMachineUUID 生成机器唯一标识（还原第一版简化版）
func getMachineUUID() string {
	// 实际场景可替换为读取硬件信息（如主板序列号）
	uuid := fmt.Sprintf("machine-%s", time.Now().UnixNano())
	logger.Debug("生成UUID：%s", uuid)
	return uuid
}

// ======== 增强日志核心方法 ========
// Debug 调试日志（详细过程）
func (l *Logger) Debug(format string, v ...interface{}) {
	l.log(LogLevelDebug, format, v...)
}

// Info 信息日志（正常运行状态）
func (l *Logger) Info(format string, v ...interface{}) {
	l.log(LogLevelInfo, format, v...)
}

// Warn 警告日志（非致命问题）
func (l *Logger) Warn(format string, v ...interface{}) {
	l.log(LogLevelWarn, format, v...)
}

// Error 错误日志（致命问题）
func (l *Logger) Error(format string, v ...interface{}) {
	l.log(LogLevelError, format, v...)
}

// log 核心日志写入方法
func (l *Logger) log(level, format string, v ...interface{}) {
	// 1. 获取调用上下文（函数名、行号）
	pc, file, line, ok := runtime.Caller(2)
	funcName := "unknown"
	if ok {
		funcName = runtime.FuncForPC(pc).Name()
		// 简化函数名（只保留最后一部分）
		funcNameParts := strings.Split(funcName, ".")
		if len(funcNameParts) > 0 {
			funcName = funcNameParts[len(funcNameParts)-1]
		}
		file = filepath.Base(file) // 只保留文件名，不保留路径
	}

	// 2. 格式化日志内容
	timestamp := time.Now().Format("2006-01-02 15:04:05.000")
	msg := fmt.Sprintf(format, v...)
	logContent := fmt.Sprintf(
		"[%s] [%s] [%s:%d:%s] %s\n",
		timestamp, level, file, line, funcName, msg,
	)

	// 3. 检查日志文件大小，需要轮转则先轮转
	l.rotateLogIfNeeded()

	// 4. 写入文件日志
	f, err := os.OpenFile(l.logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		fmt.Printf("写入日志文件失败：%v，日志内容：%s\n", err, logContent)
		return
	}
	defer f.Close()
	if _, err := f.WriteString(logContent); err != nil {
		fmt.Printf("写入日志内容失败：%v，日志内容：%s\n", err, logContent)
	}

	// 5. 写入Windows事件日志（如果初始化成功）
	if l.eventLog != nil {
		switch level {
		case LogLevelDebug, LogLevelInfo:
			l.eventLog.Info(1, msg)
		case LogLevelWarn:
			l.eventLog.Warning(1, msg)
		case LogLevelError:
			l.eventLog.Error(1, msg)
		}
	}
}

// rotateLogIfNeeded 日志文件轮转（超过最大大小则备份）
func (l *Logger) rotateLogIfNeeded() {
	// 获取日志文件信息
	fileInfo, err := os.Stat(l.logFile)
	if err != nil {
		// 文件不存在则无需轮转
		if os.IsNotExist(err) {
			return
		}
		l.Warn("获取日志文件信息失败：%v", err)
		return
	}

	// 未超过最大大小则无需轮转
	if fileInfo.Size() < l.maxSize {
		return
	}

	// 开始轮转：先删除最旧的备份，再重命名现有备份
	l.Info("日志文件超过%dMB，开始轮转", l.maxSize/1024/1024)
	for i := l.maxBackups - 1; i > 0; i-- {
		src := fmt.Sprintf("%s.%d", l.logFile, i)
		dst := fmt.Sprintf("%s.%d", l.logFile, i+1)
		if _, err := os.Stat(src); err == nil {
			if err := os.Rename(src, dst); err != nil {
				l.Warn("重命名备份日志失败 %s -> %s：%v", src, dst, err)
			}
		}
	}

	// 重命名当前日志为.1备份
	if err := os.Rename(l.logFile, fmt.Sprintf("%s.1", l.logFile)); err != nil {
		l.Error("重命名当前日志失败：%v", err)
		return
	}

	l.Info("日志轮转完成，创建新日志文件")
}

// ======== 原有功能逻辑 ========
// hideConsoleWindow 强制隐藏控制台窗口（修复API调用问题）
func hideConsoleWindow() {
	logger.Debug("尝试隐藏控制台窗口")
	// 调用Windows API获取控制台窗口句柄
	hwnd, _, _ := procGetConsoleWindow.Call()
	if hwnd != 0 {
		// 隐藏窗口：ShowWindow(hwnd, SW_HIDE)
		procShowWindow.Call(hwnd, uintptr(SW_HIDE))
		// 从任务栏移除窗口
		procSetWindowPos.Call(
			hwnd,
			0,
			0, 0, 0, 0,
			uintptr(SWP_HIDEWINDOW|SWP_NOMOVE|SWP_NOSIZE),
		)
		logger.Debug("控制台窗口已隐藏")
	} else {
		logger.Debug("未找到控制台窗口句柄")
	}
}

// 主函数：服务入口（处理安装/卸载/运行）
func main() {
	logger.Info("程序启动，开始初始化")
	// 强制隐藏控制台窗口（编译+运行双重保障）
	hideConsoleWindow()

	// 解析命令行参数
	if len(os.Args) > 1 {
		logger.Debug("解析命令行参数：%v", os.Args[1])
		switch os.Args[1] {
		case "install":
			if err := installService(); err != nil {
				logger.Error("安装服务失败：%v", err)
				return
			}
			logger.Info("服务安装成功")
			return
		case "uninstall":
			if err := uninstallService(); err != nil {
				logger.Error("卸载服务失败：%v", err)
				return
			}
			logger.Info("服务卸载成功")
			return
		case "start":
			if err := startService(); err != nil {
				logger.Error("启动服务失败：%v", err)
				return
			}
			logger.Info("服务启动成功")
			return
		case "stop":
			if err := stopService(); err != nil {
				logger.Error("停止服务失败：%v", err)
				return
			}
			logger.Info("服务停止成功")
			return
		default:
			logger.Warn("未知命令行参数：%s", os.Args[1])
		}
	}

	// 无参数：以服务方式运行（核心）
	isService, err := svc.IsWindowsService()
	if err != nil {
		logger.Error("检测服务环境失败：%v", err)
		return
	}
	if isService {
		logger.Info("检测到服务模式，以Windows服务方式运行")
		// 作为Windows服务运行（完全后台，不受控制台影响）
		if err := svc.Run(serviceName, &ipReportService{}); err != nil {
			logger.Error("服务运行失败：%v", err)
		}
	} else {
		logger.Info("检测到非服务模式，后台运行（无控制台）")
		// 非服务模式也强制后台运行（无控制台）
		runBackground()
	}
}

// runBackground 非服务模式下的纯后台运行逻辑（无控制台、关闭控制台不终止）
func runBackground() {
	// 立即上报IP
	logger.Info("后台运行模式：立即执行首次上报")
	if err := reportIP(); err != nil {
		logger.Error("首次上报失败：%v", err)
	} else {
		logger.Info("首次上报成功")
	}

	// 首次运行弹浏览器（还原第一版URL）
	if isFirstRun {
		go func() {
			time.Sleep(1 * time.Second)
			logger.Info("后台运行模式：启动浏览器展示IP页面")
			url := fmt.Sprintf(ViewURLTemplate, machineFixedUUID)
			logger.Debug("浏览器打开URL：%s", url)
			if err := openBrowser(url); err != nil {
				logger.Error("打开浏览器失败：%v", err)
			}
			// 创建首次运行标记（后续不再弹）
			if err := ioutil.WriteFile(firstRunFlag, []byte(time.Now().String()), 0600); err != nil {
				logger.Error("写入首次运行标记失败：%v", err)
			} else {
				logger.Debug("首次运行标记已写入：%s", firstRunFlag)
			}
		}()
	}

	// 启动定时上报（无限循环，不受控制台关闭影响）
	ticker := time.NewTicker(reportInterval)
	defer ticker.Stop()
	logger.Info("后台运行模式：开始定时上报（永久运行），间隔：%v", reportInterval)

	// 阻塞主线程（防止程序退出）
	select {}
}

// ipReportService：实现Windows服务接口
type ipReportService struct{}

// Execute：服务核心逻辑（Windows服务入口）
func (s *ipReportService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	logger.Debug("服务Execute方法启动，参数：%v", args)
	// 1. 服务启动中状态
	const acceptedCmds = svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPauseAndContinue
	changes <- svc.Status{State: svc.StartPending, WaitHint: 2000}
	logger.Info("服务进入启动中状态")

	// 2. 核心逻辑：立即上报IP（每次启动都执行）
	logger.Info("服务启动，立即执行首次上报")
	if err := reportIP(); err != nil {
		logger.Error("首次上报失败：%v", err)
	} else {
		logger.Info("首次上报成功")
	}

	// 3. 首次运行弹浏览器（还原第一版URL）
	if isFirstRun {
		go func() {
			time.Sleep(1 * time.Second) // 延迟1秒，避免服务未就绪
			logger.Info("启动浏览器展示IP页面")
			url := fmt.Sprintf(ViewURLTemplate, machineFixedUUID)
			logger.Debug("浏览器打开URL：%s", url)
			if err := openBrowser(url); err != nil {
				logger.Error("打开浏览器失败：%v", err)
			}
			// 创建首次运行标记（后续不再弹）
			if err := ioutil.WriteFile(firstRunFlag, []byte(time.Now().String()), 0600); err != nil {
				logger.Error("写入首次运行标记失败：%v", err)
			} else {
				logger.Debug("首次运行标记已写入：%s", firstRunFlag)
			}
		}()
	}

	// 4. 启动定时上报
	ticker := time.NewTicker(reportInterval)
	defer ticker.Stop()
	logger.Debug("定时上报ticker已启动，间隔：%v", reportInterval)

	// 5. 服务就绪：切换为运行状态
	changes <- svc.Status{State: svc.Running, Accepts: acceptedCmds}
	logger.Info("服务已进入运行状态（完全后台）")

	// 6. 服务主循环（处理指令+定时任务）
loop:
	for {
		select {
		case <-ticker.C:
			// 定时上报
			logger.Debug("定时上报触发")
			if err := reportIP(); err != nil {
				logger.Error("定时上报失败：%v", err)
			} else {
				logger.Info("定时上报成功")
			}
		case req := <-r:
			// 处理服务控制指令（停止/暂停/查询等）
			logger.Debug("收到服务控制指令：%v", req.Cmd)
			switch req.Cmd {
			case svc.Interrogate:
				changes <- req.CurrentStatus // 响应状态查询
				logger.Debug("响应服务状态查询指令")
			case svc.Stop, svc.Shutdown:
				logger.Info("收到停止/关机指令，服务即将退出")
				changes <- svc.Status{State: svc.StopPending, WaitHint: 1000}
				break loop // 退出主循环
			case svc.Pause:
				logger.Info("服务暂停")
				ticker.Stop()
				changes <- svc.Status{State: svc.Paused, Accepts: acceptedCmds}
			case svc.Continue:
				logger.Info("服务恢复运行")
				ticker.Reset(reportInterval)
				changes <- svc.Status{State: svc.Running, Accepts: acceptedCmds}
			default:
				logger.Warn("收到未知指令：%v", req)
			}
		}
	}

	// 7. 服务停止
	changes <- svc.Status{State: svc.Stopped}
	logger.Info("服务已停止")
	return false, 0
}

// reportIP：上报IP到服务器（还原第一版逻辑）
func reportIP() error {
	logger.Debug("开始执行IP上报逻辑")
	// 1. 获取公网IP
	logger.Debug("尝试获取公网IP")
	ip, err := getPublicIP()
	if err != nil {
		return fmt.Errorf("获取公网IP失败：%v", err)
	}
	logger.Debug("获取到公网IP：%s", ip)

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
	logger.Debug("上报数据序列化完成：%s", string(payloadBytes))

	// 3. 发送HTTP请求（使用第一版的WorkersURL）
	client := &http.Client{Timeout: Timeout}
	req, err := http.NewRequest("POST", WorkersURL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return fmt.Errorf("创建HTTP请求失败：%v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	logger.Debug("HTTP请求已创建，目标URL：%s", WorkersURL)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("发送HTTP请求失败：%v", err)
	}
	defer resp.Body.Close()
	logger.Debug("收到HTTP响应，状态码：%d", resp.StatusCode)

	// 4. 校验响应
	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("服务器返回错误状态码：%d，响应内容：%s", resp.StatusCode, string(body))
	}

	logger.Debug("IP上报成功完成")
	return nil
}

// getPublicIP：获取公网IP（还原第一版逻辑）
func getPublicIP() (string, error) {
	logger.Debug("调用ipify.org获取公网IP")
	client := &http.Client{Timeout: Timeout}
	resp, err := client.Get("https://api.ipify.org?format=text")
	if err != nil {
		logger.Error("调用ipify.org失败：%v", err)
		return "", err
	}
	defer resp.Body.Close()

	ipBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logger.Error("读取IP响应失败：%v", err)
		return "", err
	}
	ip := string(ipBytes)
	logger.Debug("获取到公网IP：%s", ip)
	return ip, nil
}

// openBrowser：Windows后台打开浏览器（无控制台窗口，还原第一版逻辑）
func openBrowser(url string) error {
	logger.Debug("尝试打开浏览器，URL：%s", url)
	// 关键：设置进程属性，隐藏控制台窗口
	cmd := exec.Command("cmd", "/c", "start", "", url)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: CREATE_NO_WINDOW, // 修复常量定义问题
	}
	if err := cmd.Start(); err != nil {
		logger.Error("启动浏览器进程失败：%v", err)
		return err
	}
	logger.Debug("浏览器进程已启动，PID：%d", cmd.Process.Pid)
	return nil
}

// ---------- 服务安装/卸载/启停 辅助函数 ----------
func installService() error {
	logger.Debug("开始安装服务：%s", serviceName)
	// 1. 连接服务管理器
	m, err := mgr.Connect()
	if err != nil {
		logger.Error("连接服务管理器失败：%v", err)
		return err
	}
	defer m.Disconnect()

	// 2. 检查服务是否已存在
	if _, err := m.OpenService(serviceName); err == nil {
		errMsg := fmt.Sprintf("服务%s已存在", serviceName)
		logger.Warn(errMsg)
		return fmt.Errorf(errMsg)
	}

	// 3. 获取当前程序路径
	exePath, err := os.Executable()
	if err != nil {
		logger.Error("获取程序路径失败：%v", err)
		return err
	}
	logger.Debug("程序路径：%s", exePath)

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
		logger.Error("创建服务失败：%v", err)
		return err
	}
	defer s.Close()

	// 5. 注册事件日志（可选，增强日志）
	if err := eventlog.InstallAsEventCreate(serviceName, eventlog.Error|eventlog.Warning|eventlog.Info); err != nil {
		logger.Warn("注册事件日志失败：%v", err)
		// 非致命错误，继续执行
	}

	logger.Info("服务%s安装成功", serviceName)
	return nil
}

func uninstallService() error {
	logger.Debug("开始卸载服务：%s", serviceName)
	// 1. 先停止服务（如果运行中）
	if err := stopService(); err != nil {
		if !strings.Contains(err.Error(), "服务未运行") {
			logger.Error("停止服务失败：%v", err)
			return err
		}
		logger.Warn("服务未运行，跳过停止步骤")
	}

	// 2. 连接服务管理器
	m, err := mgr.Connect()
	if err != nil {
		logger.Error("连接服务管理器失败：%v", err)
		return err
	}
	defer m.Disconnect()

	// 3. 删除服务
	s, err := m.OpenService(serviceName)
	if err != nil {
		errMsg := fmt.Sprintf("服务%s不存在：%v", serviceName, err)
		logger.Warn(errMsg)
		return fmt.Errorf(errMsg)
	}
	defer s.Close()

	if err := s.Delete(); err != nil {
		logger.Error("删除服务失败：%v", err)
		return err
	}

	// 4. 移除事件日志
	if err := eventlog.Remove(serviceName); err != nil {
		logger.Warn("移除事件日志失败：%v", err)
	}

	logger.Info("服务%s卸载成功", serviceName)
	return nil
}

func startService() error {
	logger.Debug("开始启动服务：%s", serviceName)
	m, err := mgr.Connect()
	if err != nil {
		logger.Error("连接服务管理器失败：%v", err)
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		logger.Error("打开服务失败：%v", err)
		return err
	}
	defer s.Close()

	if err := s.Start("is", "manual-start"); err != nil {
		logger.Error("启动服务失败：%v", err)
		return err
	}

	// 等待服务启动
	time.Sleep(500 * time.Millisecond)
	status, err := s.Query()
	if err != nil {
		logger.Error("查询服务状态失败：%v", err)
		return err
	}
	logger.Debug("服务当前状态：%v", status.State)

	logger.Info("服务%s启动成功", serviceName)
	return nil
}

func stopService() error {
	logger.Debug("开始停止服务：%s", serviceName)
	m, err := mgr.Connect()
	if err != nil {
		logger.Error("连接服务管理器失败：%v", err)
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		logger.Error("打开服务失败：%v", err)
		return err
	}
	defer s.Close()

	// 发送停止指令
	status, err := s.Control(svc.Stop)
	if err != nil {
		logger.Error("发送停止指令失败：%v", err)
		return err
	}
	logger.Debug("服务停止指令已发送，当前状态：%v", status.State)

	// 等待服务停止
	for status.State != svc.Stopped {
		time.Sleep(100 * time.Millisecond)
		status, err = s.Query()
		if err != nil {
			logger.Error("查询服务状态失败：%v", err)
			return err
		}
		logger.Debug("等待服务停止，当前状态：%v", status.State)
	}

	logger.Info("服务%s已停止", serviceName)
	return nil
}