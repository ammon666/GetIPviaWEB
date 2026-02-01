package main

import (
	"bytes"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows/registry"
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

	// 开机启动注册表路径（用户级，无需管理员权限）
	runKeyPath = `Software\Microsoft\Windows\CurrentVersion\Run`
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

// 网卡信息结构体（匹配服务端networks字段要求，对齐老代码字段名）
type NetworkInfo struct {
	InterfaceName string `json:"interface_name"` // 网卡名称
	IPAddress     string `json:"ip_address"`     // 对应IP地址（对齐老代码字段名）
}

// 上报数据结构体（严格匹配服务端必填字段，已移除公网IP字段）
type ReportPayload struct {
	UUID       string        `json:"uuid"`      // 必填
	Username   string        `json:"username"`  // 必填
	Networks   []NetworkInfo `json:"networks"`  // 必填（数组）
	TimeStamp  string        `json:"timestamp,omitempty"`
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

	// 业务配置（API Key通过编译注入，不硬编码）
	APIKey                 = "" // 编译时通过-ldflags注入：-X main.APIKey=你的实际APIKey
	WorkersURL             = "https://getip.ammon.de5.net/api/report"  // 上报地址
	ViewURLTemplate        = "https://getip.ammon.de5.net/view/%s"    // 浏览器打开地址
	Timeout                = 10 * time.Second
	DefaultInterval        = 60 * time.Minute // 上报间隔改为60分钟

	// 全局变量
	logger                 *Logger // 增强日志器
	machineFixedUUID       string  // 设备唯一UUID（必填，对齐老代码生成逻辑）
	systemUsername         string  // 系统用户名（必填，对齐老代码获取逻辑）
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

	// 3. 校验API Key（必须通过编译注入）
	if APIKey == "" {
		errMsg := "APIKey未配置！请使用编译命令：go build -ldflags \"-X main.APIKey=你的实际APIKey\" -H=windowsgui"
		logger.Error(errMsg)
		panic(errMsg)
	}
	logger.Info("APIKey注入成功（长度：%d），避免硬编码保障安全", len(APIKey))

	// 4. 初始化系统用户名（对齐老代码获取逻辑）
	systemUsername = getCurrentUsername()
	logger.Info("获取系统用户名：%s", systemUsername)

	// 5. 初始化上报间隔
	reportInterval = DefaultInterval
	logger.Debug("上报间隔初始化：%v", reportInterval)

	// 6. 检测是否首次运行
	if _, err := os.Stat(firstRunFlag); os.IsNotExist(err) {
		isFirstRun = true
		logger.Info("检测到首次运行，将执行：1.添加开机启动 2.弹出浏览器")
		// 首次运行：自动添加开机启动（优先注册服务，失败则用注册表兜底）
		if err := addAutoStart(); err != nil {
			logger.Error("添加开机启动失败：%v", err)
		} else {
			logger.Info("开机启动添加成功")
		}
	} else {
		isFirstRun = false
		logger.Info("非首次运行，跳过浏览器弹窗和开机启动配置")
	}

	// 7. 生成设备唯一UUID（对齐老代码MD5+MAC生成逻辑）
	initMachineFixedUUID()
	logger.Debug("生成设备唯一UUID：%s", machineFixedUUID)
}

// ========== 新增：开机启动相关函数 ==========
// addAutoStart 首次运行时添加开机启动（优先服务模式，失败则用注册表）
func addAutoStart() error {
	// 第一步：尝试注册为Windows服务（最优方案）
	if err := installService(); err != nil {
		logger.Warn("注册服务失败（可能无管理员权限），尝试注册表方式：%v", err)
		// 第二步：服务注册失败，用注册表Run项兜底（用户级，无需管理员权限）
		if err := addToRegistryRun(); err != nil {
			return fmt.Errorf("服务注册和注册表方式均失败：%v", err)
		}
		return nil
	}
	// 服务注册成功后，自动启动服务
	if err := startService(); err != nil {
		logger.Warn("服务注册成功，但启动失败：%v", err)
	}
	return nil
}

// addToRegistryRun 写入用户级注册表Run项，实现开机启动（兜底方案）
func addToRegistryRun() error {
	// 获取程序自身路径
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("获取程序路径失败：%v", err)
	}
	// 转义路径（处理空格）
	exePath = fmt.Sprintf("\"%s\"", exePath)

	// 打开用户级Run注册表项
	key, err := registry.OpenKey(registry.CURRENT_USER, runKeyPath, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("打开注册表项失败：%v", err)
	}
	defer key.Close()

	// 写入开机启动项（名称为服务名，值为程序路径）
	if err := key.SetStringValue(serviceName, exePath); err != nil {
		return fmt.Errorf("写入注册表值失败：%v", err)
	}
	logger.Info("已写入用户级注册表Run项：%s -> %s", serviceName, exePath)
	return nil
}

// ========== 对齐老代码的核心工具函数 ==========
// initMachineFixedUUID 初始化设备固定UUID（完全复用老代码逻辑）
func initMachineFixedUUID() {
	macAddr := getPhysicalNicMAC()
	if macAddr == "" {
		machineFixedUUID = "00000000-0000-0000-0000-000000000000"
		logger.Warn("未获取到MAC，使用默认UUID：%s", machineFixedUUID)
		return
	}

	hash := md5.Sum([]byte(macAddr))
	machineFixedUUID = fmt.Sprintf("%x-%x-%x-%x-%x",
		hash[0:4], hash[4:6], hash[6:8], hash[8:10], hash[10:16])
	logger.Info("初始化UUID：%s", machineFixedUUID)
}

// getPhysicalNicMAC 获取物理网卡MAC（完全复用老代码逻辑，过滤虚拟网卡）
func getPhysicalNicMAC() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		logger.Error("获取网卡列表失败：%v", err)
		return ""
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || iface.HardwareAddr.String() == "" {
			continue
		}

		nicName := strings.ToLower(iface.Name)
		// 过滤虚拟网卡（docker/vmware/virtual/vpn/hyper-v）
		if strings.Contains(nicName, "docker") || strings.Contains(nicName, "vmware") || strings.Contains(nicName, "virtual") ||
			strings.Contains(nicName, "vpn") || strings.Contains(nicName, "hyper-v") {
			continue
		}

		// 只保留物理网卡（ethernet/wlan/wi-fi）
		if strings.Contains(nicName, "ethernet") || strings.Contains(nicName, "wlan") || strings.Contains(nicName, "wi-fi") {
			logger.Debug("找到物理网卡：%s，MAC：%s", iface.Name, iface.HardwareAddr.String())
			return iface.HardwareAddr.String()
		}
	}

	logger.Warn("未找到有效物理网卡MAC")
	return ""
}

// getCurrentUsername 获取系统用户名（完全复用老代码逻辑）
func getCurrentUsername() string {
	currentUser, err := user.Current()
	if err != nil {
		logger.Error("获取用户名失败：%v", err)
		return "未知用户"
	}

	if strings.Contains(currentUser.Username, "\\") {
		parts := strings.Split(currentUser.Username, "\\")
		return parts[len(parts)-1]
	}
	return currentUser.Username
}

// isPrivateIPv4 过滤私有IP（完全复用老代码逻辑）
func isPrivateIPv4(ip net.IP) bool {
	if ip == nil {
		return false
	}
	return ip[0] == 10 || (ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31) ||
		(ip[0] == 192 && ip[1] == 168) || (ip[0] == 169 && ip[1] == 254)
}

// getLocalNetworks 获取本机物理网卡IP（对齐老代码过滤逻辑）
func getLocalNetworks() []NetworkInfo {
	var networkInfos []NetworkInfo
	ifaces, err := net.Interfaces()
	if err != nil {
		logger.Error("获取网卡列表失败：%v", err)
		return networkInfos
	}

	for _, iface := range ifaces {
		// 跳过禁用/回环网卡
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || iface.HardwareAddr.String() == "" {
			continue
		}

		// 过滤虚拟网卡
		nicName := strings.ToLower(iface.Name)
		if strings.Contains(nicName, "docker") || strings.Contains(nicName, "vmware") || strings.Contains(nicName, "virtual") ||
			strings.Contains(nicName, "vpn") || strings.Contains(nicName, "hyper-v") {
			continue
		}

		// 获取网卡地址
		addrs, err := iface.Addrs()
		if err != nil {
			logger.Warn("网卡%s获取地址失败：%v", iface.Name, err)
			continue
		}

		// 过滤私有IPv4地址
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			ip := ipNet.IP.To4()
			if ip == nil || ip.IsLoopback() || !isPrivateIPv4(ip) {
				continue
			}

			ipStr := ip.String()
			logger.Debug("网卡%s有效私有IPv4：%s", iface.Name, ipStr)
			networkInfos = append(networkInfos, NetworkInfo{
				InterfaceName: iface.Name,
				IPAddress:     ipStr,
			})
			break // 每个网卡只取第一个有效IP
		}
	}

	// 兜底：如果没有获取到网卡信息，添加默认值
	if len(networkInfos) == 0 {
		networkInfos = append(networkInfos, NetworkInfo{
			InterfaceName: "default",
			IPAddress:     "127.0.0.1",
		})
		logger.Warn("未获取到有效物理网卡信息，使用默认值")
	}
	return networkInfos
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
		funcNameParts := strings.Split(funcName, ".")
		if len(funcNameParts) > 0 {
			funcName = funcNameParts[len(funcNameParts)-1]
		}
		file = filepath.Base(file)
	}

	// 2. 格式化日志内容
	timestamp := time.Now().Format("2006-01-02 15:04:05.000")
	msg := fmt.Sprintf(format, v...)
	logContent := fmt.Sprintf(
		"[%s] [%s] [%s:%d:%s] %s\n",
		timestamp, level, file, line, funcName, msg,
	)

	// 3. 日志轮转检查
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

	// 5. 写入Windows事件日志
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
	fileInfo, err := os.Stat(l.logFile)
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		l.Warn("获取日志文件信息失败：%v", err)
		return
	}

	if fileInfo.Size() < l.maxSize {
		return
	}

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

	if err := os.Rename(l.logFile, fmt.Sprintf("%s.1", l.logFile)); err != nil {
		l.Error("重命名当前日志失败：%v", err)
		return
	}

	l.Info("日志轮转完成，创建新日志文件")
}

// ======== 核心功能逻辑 ========
// hideConsoleWindow 强制隐藏控制台窗口
func hideConsoleWindow() {
	logger.Debug("尝试隐藏控制台窗口")
	hwnd, _, _ := procGetConsoleWindow.Call()
	if hwnd != 0 {
		procShowWindow.Call(hwnd, uintptr(SW_HIDE))
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

// 主函数：服务入口
func main() {
	logger.Info("程序启动，开始初始化")
	hideConsoleWindow()

	// 解析命令行参数（安装/卸载/启动/停止服务）
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

	// 无参数：判断运行模式（服务/后台）
	isService, err := svc.IsWindowsService()
	if err != nil {
		logger.Error("检测服务环境失败：%v", err)
		return
	}
	if isService {
		logger.Info("检测到服务模式，以Windows服务方式运行")
		if err := svc.Run(serviceName, &ipReportService{}); err != nil {
			logger.Error("服务运行失败：%v", err)
		}
	} else {
		logger.Info("检测到非服务模式，后台运行（无控制台）")
		runBackground()
	}
}

// runBackground 非服务模式后台运行
func runBackground() {
	// 立即上报IP
	logger.Info("后台运行模式：立即执行首次上报")
	if err := reportIP(); err != nil {
		logger.Error("首次上报失败：%v", err)
	} else {
		logger.Info("首次上报成功")
	}

	// 首次运行弹浏览器
	if isFirstRun {
		go func() {
			time.Sleep(1 * time.Second)
			logger.Info("后台运行模式：启动浏览器展示IP页面")
			url := fmt.Sprintf(ViewURLTemplate, machineFixedUUID)
			logger.Debug("浏览器打开URL：%s", url)
			if err := openBrowser(url); err != nil {
				logger.Error("打开浏览器失败：%v", err)
			}
			// 写入首次运行标记
			if err := ioutil.WriteFile(firstRunFlag, []byte(time.Now().String()), 0600); err != nil {
				logger.Error("写入首次运行标记失败：%v", err)
			} else {
				logger.Debug("首次运行标记已写入：%s", firstRunFlag)
			}
		}()
	}

	// 定时上报（无限阻塞）
	ticker := time.NewTicker(reportInterval)
	defer ticker.Stop()
	logger.Info("后台运行模式：开始定时上报（永久运行），间隔：%v", reportInterval)
	for {
		select {
		case <-ticker.C:
			logger.Debug("定时上报触发")
			if err := reportIP(); err != nil {
				logger.Error("定时上报失败：%v", err)
			} else {
				logger.Info("定时上报成功")
			}
		}
	}
}

// ipReportService 实现Windows服务接口
type ipReportService struct{}

// Execute 服务核心逻辑
func (s *ipReportService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	logger.Debug("服务Execute方法启动，参数：%v", args)
	const acceptedCmds = svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPauseAndContinue
	changes <- svc.Status{State: svc.StartPending, WaitHint: 2000}
	logger.Info("服务进入启动中状态")

	// 立即上报IP
	logger.Info("服务启动，立即执行首次上报")
	if err := reportIP(); err != nil {
		logger.Error("首次上报失败：%v", err)
	} else {
		logger.Info("首次上报成功")
	}

	// 首次运行弹浏览器
	if isFirstRun {
		go func() {
			time.Sleep(1 * time.Second)
			logger.Info("启动浏览器展示IP页面")
			url := fmt.Sprintf(ViewURLTemplate, machineFixedUUID)
			logger.Debug("浏览器打开URL：%s", url)
			if err := openBrowser(url); err != nil {
				logger.Error("打开浏览器失败：%v", err)
			}
			if err := ioutil.WriteFile(firstRunFlag, []byte(time.Now().String()), 0600); err != nil {
				logger.Error("写入首次运行标记失败：%v", err)
			} else {
				logger.Debug("首次运行标记已写入：%s", firstRunFlag)
			}
		}()
	}

	// 定时上报
	ticker := time.NewTicker(reportInterval)
	defer ticker.Stop()
	logger.Debug("定时上报ticker已启动，间隔：%v", reportInterval)

	// 服务就绪
	changes <- svc.Status{State: svc.Running, Accepts: acceptedCmds}
	logger.Info("服务已进入运行状态（完全后台）")

	// 服务主循环
loop:
	for {
		select {
		case <-ticker.C:
			logger.Debug("定时上报触发")
			if err := reportIP(); err != nil {
				logger.Error("定时上报失败：%v", err)
			} else {
				logger.Info("定时上报成功")
			}
		case req := <-r:
			logger.Debug("收到服务控制指令：%v", req.Cmd)
			switch req.Cmd {
			case svc.Interrogate:
				changes <- req.CurrentStatus
				logger.Debug("响应服务状态查询指令")
			case svc.Stop, svc.Shutdown:
				logger.Info("收到停止/关机指令，服务即将退出")
				changes <- svc.Status{State: svc.StopPending, WaitHint: 1000}
				break loop
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

	// 服务停止
	changes <- svc.Status{State: svc.Stopped}
	logger.Info("服务已停止")
	return false, 0
}

// reportIP 上报IP到服务器（已移除公网IP相关逻辑）
func reportIP() error {
	logger.Debug("开始执行IP上报逻辑")

	// 1. 获取本机物理网卡信息（对齐老代码过滤逻辑）
	logger.Debug("获取本机物理网卡信息（必填字段）")
	localNetworks := getLocalNetworks()
	logger.Debug("获取到物理网卡信息：%d个", len(localNetworks))

	// 2. 构造上报数据（严格匹配服务端必填字段，已移除IP字段）
	payload := ReportPayload{
		UUID:       machineFixedUUID,       // 老代码逻辑生成的UUID
		Username:   systemUsername,         // 老代码逻辑获取的用户名
		Networks:   localNetworks,          // 老代码逻辑过滤的网卡信息
		TimeStamp:  time.Now().Format(time.RFC3339),
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("序列化上报数据失败：%v", err)
	}
	logger.Debug("上报数据序列化完成：%s", string(payloadBytes))

	// 3. 创建POST请求（保留X-API-Key请求头）
	req, err := http.NewRequest("POST", WorkersURL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return fmt.Errorf("创建HTTP请求失败：%v", err)
	}
	// 必须设置的请求头
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", APIKey) // 编译注入的API Key
	logger.Debug("已添加X-API-Key请求头（长度：%d）", len(APIKey))

	// 4. 发送请求
	client := &http.Client{Timeout: Timeout}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("发送HTTP请求失败：%v", err)
	}
	defer resp.Body.Close()
	logger.Debug("收到HTTP响应，状态码：%d", resp.StatusCode)

	// 5. 解析响应
	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("读取响应体失败：%v", err)
	}
	logger.Debug("响应体内容：%s", string(respBody))

	// 6. 校验响应状态
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("服务器返回错误：%d，内容：%s", resp.StatusCode, string(respBody))
	}

	// 7. 校验业务响应
	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		logger.Warn("解析响应JSON失败（非致命）：%v", err)
		return nil // 响应状态码200，仅JSON解析失败不影响上报结果
	}
	if success, ok := result["success"].(bool); ok && !success {
		errorMsg, _ := result["error"].(string)
		return fmt.Errorf("上报业务失败：%s", errorMsg)
	}

	logger.Debug("IP上报成功完成，服务端返回：%s", string(respBody))
	return nil
}

// openBrowser 后台打开浏览器
func openBrowser(url string) error {
	logger.Debug("尝试打开浏览器，URL：%s", url)
	cmd := exec.Command("cmd", "/c", "start", "", url)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: CREATE_NO_WINDOW,
	}
	if err := cmd.Start(); err != nil {
		logger.Error("启动浏览器进程失败：%v", err)
		return err
	}
	logger.Debug("浏览器进程已启动，PID：%d", cmd.Process.Pid)
	return nil
}

// ======== 服务安装/卸载/启停辅助函数 ========
func installService() error {
	logger.Debug("开始安装服务：%s", serviceName)
	m, err := mgr.Connect()
	if err != nil {
		logger.Error("连接服务管理器失败：%v", err)
		return err
	}
	defer m.Disconnect()

	// 检查服务是否已存在
	if _, err := m.OpenService(serviceName); err == nil {
		errMsg := fmt.Sprintf("服务%s已存在", serviceName)
		logger.Warn(errMsg)
		return fmt.Errorf(errMsg)
	}

	// 获取程序路径
	exePath, err := os.Executable()
	if err != nil {
		logger.Error("获取程序路径失败：%v", err)
		return err
	}
	logger.Debug("程序路径：%s", exePath)

	// 创建服务（设置为自动启动）
	s, err := m.CreateService(
		serviceName,
		exePath,
		mgr.Config{
			DisplayName: displayName,
			Description: serviceDesc,
			StartType:   mgr.StartAutomatic, // 关键：设置为自动启动
		},
	)
	if err != nil {
		logger.Error("创建服务失败：%v", err)
		return err
	}
	defer s.Close()

	// 注册事件日志
	if err := eventlog.InstallAsEventCreate(serviceName, eventlog.Error|eventlog.Warning|eventlog.Info); err != nil {
		logger.Warn("注册事件日志失败：%v", err)
	}

	logger.Info("服务%s安装成功（自动启动）", serviceName)
	return nil
}

func uninstallService() error {
	logger.Debug("开始卸载服务：%s", serviceName)
	// 先停止服务
	if err := stopService(); err != nil {
		if !strings.Contains(err.Error(), "服务未运行") {
			logger.Error("停止服务失败：%v", err)
			return err
		}
		logger.Warn("服务未运行，跳过停止步骤")
	}

	// 连接服务管理器
	m, err := mgr.Connect()
	if err != nil {
		logger.Error("连接服务管理器失败：%v", err)
		return err
	}
	defer m.Disconnect()

	// 删除服务
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

	// 移除事件日志
	if err := eventlog.Remove(serviceName); err != nil {
		logger.Warn("移除事件日志失败：%v", err)
	}

	// 卸载时同时删除注册表开机启动项
	if err := removeFromRegistryRun(); err != nil {
		logger.Warn("删除注册表开机启动项失败：%v", err)
	}

	logger.Info("服务%s卸载成功", serviceName)
	return nil
}

// removeFromRegistryRun 卸载服务时删除注册表Run项
func removeFromRegistryRun() error {
	key, err := registry.OpenKey(registry.CURRENT_USER, runKeyPath, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("打开注册表项失败：%v", err)
	}
	defer key.Close()

	if err := key.DeleteValue(serviceName); err != nil {
		return fmt.Errorf("删除注册表值失败：%v", err)
	}
	logger.Info("已删除用户级注册表Run项：%s", serviceName)
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