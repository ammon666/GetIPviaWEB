package main

import (
	"bytes"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io"
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
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

// 手动声明Windows API常量
const (
	SW_HIDE            = 0
	SW_SHOW            = 1
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

	// 系统卸载注册表路径
	uninstallKeyPath = `Software\Microsoft\Windows\CurrentVersion\Uninstall`
	// 默认安装目录
	defaultInstallDir = `C:\Program Files\IPReportService`
)

// 手动声明Windows API函数
var (
	kernel32                = syscall.NewLazyDLL("kernel32.dll")
	user32                  = syscall.NewLazyDLL("user32.dll")
	procGetConsoleWindow    = kernel32.NewProc("GetConsoleWindow")
	procShowWindow          = user32.NewProc("ShowWindow")
	procSetWindowPos        = user32.NewProc("SetWindowPos")
	procMessageBoxW         = user32.NewProc("MessageBoxW")
)

// MessageBox 封装Windows消息框
func MessageBox(hwnd uintptr, text, caption string, uType uint32) int {
	textPtr, _ := syscall.UTF16PtrFromString(text)
	captionPtr, _ := syscall.UTF16PtrFromString(caption)
	ret, _, _ := procMessageBoxW.Call(
		hwnd,
		uintptr(unsafe.Pointer(textPtr)),
		uintptr(unsafe.Pointer(captionPtr)),
		uintptr(uType),
	)
	return int(ret)
}

// 日志配置结构体
type Logger struct {
	logDir        string
	logFile       string
	maxSize       int64
	maxBackups    int
	eventLog      *eventlog.Log
	serviceName   string
}

// 网卡信息结构体
type NetworkInfo struct {
	InterfaceName string `json:"interface_name"`
	IPAddress     string `json:"ip_address"`
}

// 上报数据结构体
type ReportPayload struct {
	UUID       string        `json:"uuid"`
	Username   string        `json:"username"`
	Networks   []NetworkInfo `json:"networks"`
	TimeStamp  string        `json:"timestamp,omitempty"`
}

// 全局配置
var (
	// 路径配置（基于安装目录）
	installDir             string // 安装目录
	logDir                 string // 日志目录（安装目录/logs）
	logPath                string // 日志文件路径
	firstRunFlag           string // 首次运行标志（安装目录/first_run.flag）

	// 服务核心配置
	serviceName            = "IPReportService"
	displayName            = "IP自动上报服务"
	serviceDesc            = "后台运行，定时上报本机IP信息"

	// 业务配置
	APIKey                 = "" // 编译时通过-ldflags注入
	WorkersURL             = "https://getip.ammon.de5.net/api/report"
	ViewURLTemplate        = "https://getip.ammon.de5.net/view/%s"
	Timeout                = 10 * time.Second
	DefaultInterval        = 60 * time.Minute // 60分钟上报间隔

	// 全局变量
	logger                 *Logger
	machineFixedUUID       string
	systemUsername         string
	isFirstRun             bool
	reportInterval         time.Duration
)

// init：初始化基础配置
func init() {
	// 1. 确定安装目录（运行时推导）
	exePath, err := os.Executable()
	if err != nil {
		panic(fmt.Sprintf("获取程序路径失败：%v", err))
	}
	installDir = filepath.Dir(exePath) // 程序所在目录即为安装目录

	// 2. 初始化路径（全部放在安装目录下）
	logDir = filepath.Join(installDir, "logs")
	logPath = filepath.Join(logDir, "service.log")
	firstRunFlag = filepath.Join(installDir, "first_run.flag")

	// 3. 创建必要目录（安装目录/logs），修改权限为0777确保可写入
	if err := os.MkdirAll(logDir, 0777); err != nil {
		panic(fmt.Sprintf("创建日志目录失败：%v", err))
	}

	// 4. 初始化日志器
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

	// 5. 校验APIKey
	if APIKey == "" {
		errMsg := "APIKey未配置！编译命令示例：go build -ldflags \"-X main.APIKey=你的APIKey\" -H=windowsgui"
		logger.Error(errMsg)
		panic(errMsg)
	}
	logger.Info("APIKey注入成功，安装目录：%s", installDir)

	// 6. 初始化用户名
	systemUsername = getCurrentUsername()
	logger.Info("当前系统用户名：%s", systemUsername)

	// 7. 初始化上报间隔
	reportInterval = DefaultInterval
	logger.Debug("上报间隔初始化：%v", reportInterval)

	// 8. 检测首次运行
	if _, err := os.Stat(firstRunFlag); os.IsNotExist(err) {
		isFirstRun = true
		logger.Info("检测到首次运行，将执行初始化操作")
	} else {
		isFirstRun = false
		logger.Info("非首次运行，跳过初始化")
	}

	// 9. 生成UUID
	initMachineFixedUUID()
	logger.Debug("设备UUID生成完成：%s", machineFixedUUID)
}

// showConsoleWindow 显示控制台窗口
func showConsoleWindow() {
	logger.Debug("显示控制台窗口")
	hwnd, _, _ := procGetConsoleWindow.Call()
	if hwnd != 0 {
		procShowWindow.Call(hwnd, uintptr(SW_SHOW))
	}
}

// ========== 安装/卸载核心函数 ==========
// Install 完整安装流程：拷贝程序到Program Files + 注册服务 + 写入卸载信息 + 启动服务
func Install() error {
	// 兜底校验：管理员权限检查
	if !isAdmin() {
		MessageBox(0, 
			"当前未以管理员权限运行！\n请右键点击程序，选择「以管理员身份运行」后重试。", 
			"权限错误", 
			0x10) // 0x10 = MB_ICONERROR
		return fmt.Errorf("非管理员权限，无法执行安装操作")
	}

	logger.Info("开始执行安装流程...")

	// 1. 拷贝程序到默认安装目录
	if err := copyProgramToInstallDir(); err != nil {
		return fmt.Errorf("拷贝程序失败：%v", err)
	}

	// 2. 注册Windows服务（自动启动）
	if err := installService(); err != nil {
		return fmt.Errorf("注册服务失败：%v", err)
	}

	// 3. 写入卸载信息到注册表
	if err := writeUninstallInfo(); err != nil {
		return fmt.Errorf("写入卸载信息失败：%v", err)
	}

	// 4. 启动服务
	if err := startService(); err != nil {
		logger.Warn("服务注册成功，但启动失败：%v", err)
		MessageBox(0, fmt.Sprintf("服务注册成功，但启动失败：%v\n可手动在服务管理器中启动。", err), "安装警告", 0x30)
	}

	// 5. 创建首次运行标志
	if err := ioutil.WriteFile(firstRunFlag, []byte(time.Now().String()), 0600); err != nil {
		logger.Warn("创建首次运行标志失败：%v", err)
	}

	logger.Info("安装完成！服务已注册并启动")
	MessageBox(0, "服务安装成功！已设置为开机自动启动。", "安装完成", 0x40)
	return nil
}

// Uninstall 完整卸载流程：停止服务 + 删除服务 + 清理注册表 + 删除安装目录
func Uninstall() error {
	logger.Info("开始执行卸载流程...")

	// 1. 检查管理员权限（仅日志，不弹窗）
	if !isAdmin() {
		logger.Error("卸载需要管理员权限，请右键以管理员身份运行")
		return fmt.Errorf("卸载需要管理员权限，请右键以管理员身份运行")
	}

	// 2. 停止服务（自动处理异常，不弹窗）
	if err := stopService(); err != nil {
		if !strings.Contains(err.Error(), "服务未运行") && !strings.Contains(err.Error(), "指定的服务未安装") {
			logger.Warn("停止服务失败：%v", err)
		} else {
			logger.Info("服务未运行，跳过停止操作")
		}
	}

	// 3. 删除服务（自动处理，不弹窗）
	m, err := mgr.Connect()
	if err != nil {
		logger.Error("连接服务管理器失败：%v", err)
		return fmt.Errorf("连接服务管理器失败：%v", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err == nil {
		if err := s.Delete(); err != nil {
			logger.Error("删除服务失败：%v", err)
			return fmt.Errorf("删除服务失败：%v", err)
		}
		s.Close()
		logger.Info("服务已删除")
	} else {
		logger.Info("服务不存在，跳过删除操作")
	}

	// 4. 清理卸载注册表项（自动处理，不弹窗）
	if err := deleteUninstallInfo(); err != nil {
		logger.Warn("清理卸载信息失败：%v", err)
	}

	// 5. 删除安装目录（自动处理，不弹窗）
	if err := os.RemoveAll(defaultInstallDir); err != nil {
		logger.Error("删除安装目录失败：%v", err)
		return fmt.Errorf("删除安装目录失败：%v", err)
	}

	logger.Info("卸载完成！所有文件和服务已清理")
	return nil
}

// copyProgramToInstallDir 拷贝当前程序到默认安装目录
func copyProgramToInstallDir() error {
	// 创建默认安装目录
	if err := os.MkdirAll(defaultInstallDir, 0700); err != nil {
		return err
	}

	// 获取当前程序路径
	srcPath, err := os.Executable()
	if err != nil {
		return err
	}

	// 目标程序路径
	dstPath := filepath.Join(defaultInstallDir, filepath.Base(srcPath))

	// 如果已存在，先删除
	if _, err := os.Stat(dstPath); err == nil {
		if err := os.Remove(dstPath); err != nil {
			return err
		}
	}

	// 拷贝文件
	srcFile, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dstPath)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	if _, err := io.Copy(dstFile, srcFile); err != nil {
		return err
	}

	logger.Info("程序已拷贝到：%s", dstPath)
	return nil
}

// writeUninstallInfo 写入卸载信息到注册表
func writeUninstallInfo() error {
	// 打开卸载注册表项（LOCAL_MACHINE需要管理员权限）
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, uninstallKeyPath, registry.WRITE)
	if err != nil {
		return err
	}
	defer key.Close()

	// 创建当前程序的卸载子项
	uninstallSubKey, _, err := registry.CreateKey(key, serviceName, registry.WRITE)
	if err != nil {
		return err
	}
	defer uninstallSubKey.Close()

	// 写入卸载信息（系统添加/删除程序所需字段）
	uninstallExe := fmt.Sprintf("\"%s\" uninstall", filepath.Join(defaultInstallDir, filepath.Base(os.Args[0])))
	fields := map[string]string{
		"DisplayName":     displayName,
		"DisplayVersion":  "1.0.0",
		"Publisher":       "IPReport Service",
		"UninstallString": uninstallExe,
		"DisplayIcon":     filepath.Join(defaultInstallDir, filepath.Base(os.Args[0])),
		"NoModify":        "1",
		"NoRepair":        "1",
	}

	for k, v := range fields {
		if err := uninstallSubKey.SetStringValue(k, v); err != nil {
			return err
		}
	}

	logger.Info("卸载信息已写入注册表：HKEY_LOCAL_MACHINE\\%s\\%s", uninstallKeyPath, serviceName)
	return nil
}

// deleteUninstallInfo 删除注册表中的卸载信息
func deleteUninstallInfo() error {
	// 删除卸载注册表项
	err := registry.DeleteKey(registry.LOCAL_MACHINE, filepath.Join(uninstallKeyPath, serviceName))
	if err != nil {
		return err
	}

	logger.Info("卸载注册表项已删除")
	return nil
}

// isAdmin 检查是否为管理员权限
func isAdmin() bool {
	var sid *windows.SID

	// 创建管理员组的SID
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid)
	if err != nil {
		logger.Error("创建管理员SID失败：%v", err)
		return false
	}
	defer windows.FreeSid(sid)

	// 获取当前进程的访问令牌
	token := windows.Token(0)
	member, err := token.IsMember(sid)
	if err != nil {
		logger.Error("检查令牌成员失败：%v", err)
		return false
	}

	return member
}

// ========== 核心业务函数 ==========
// initMachineFixedUUID 生成设备固定UUID（基于MAC地址）
func initMachineFixedUUID() {
	macAddr := getPhysicalNicMAC()
	if macAddr == "" {
		machineFixedUUID = "00000000-0000-0000-0000-000000000000"
		logger.Warn("未获取到MAC地址，使用默认UUID")
		return
	}

	hash := md5.Sum([]byte(macAddr))
	machineFixedUUID = fmt.Sprintf("%x-%x-%x-%x-%x",
		hash[0:4], hash[4:6], hash[6:8], hash[8:10], hash[10:16])
	logger.Info("设备UUID生成完成：%s", machineFixedUUID)
}

// getPhysicalNicMAC 获取物理网卡MAC地址
func getPhysicalNicMAC() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		logger.Error("获取网卡列表失败：%v", err)
		return ""
	}

	for _, iface := range ifaces {
		// 过滤虚拟网卡、回环网卡、未启用网卡
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || iface.HardwareAddr.String() == "" {
			continue
		}

		nicName := strings.ToLower(iface.Name)
		// 过滤常见虚拟网卡名称
		if strings.Contains(nicName, "docker") || strings.Contains(nicName, "vmware") || 
			strings.Contains(nicName, "virtual") || strings.Contains(nicName, "vpn") || 
			strings.Contains(nicName, "hyper-v") {
			continue
		}

		// 优先选择物理网卡（以太网/Wi-Fi）
		if strings.Contains(nicName, "ethernet") || strings.Contains(nicName, "wlan") || strings.Contains(nicName, "wi-fi") {
			logger.Debug("找到物理网卡：%s，MAC：%s", iface.Name, iface.HardwareAddr.String())
			return iface.HardwareAddr.String()
		}
	}

	logger.Warn("未找到有效物理网卡MAC地址")
	return ""
}

// getCurrentUsername 获取当前登录用户名
func getCurrentUsername() string {
	currentUser, err := user.Current()
	if err != nil {
		logger.Error("获取当前用户失败：%v", err)
		return "未知用户"
	}

	// 提取纯用户名（去掉域名）
	if strings.Contains(currentUser.Username, "\\") {
		parts := strings.Split(currentUser.Username, "\\")
		return parts[len(parts)-1]
	}
	return currentUser.Username
}

// isPrivateIPv4 判断是否为私有IP
func isPrivateIPv4(ip net.IP) bool {
	if ip == nil || !ip.IsPrivate() {
		return false
	}
	return true
}

// getLocalNetworks 获取本机所有物理网卡的私有IP
func getLocalNetworks() []NetworkInfo {
	var networkInfos []NetworkInfo
	ifaces, err := net.Interfaces()
	if err != nil {
		logger.Error("获取网卡列表失败：%v", err)
		return networkInfos
	}

	for _, iface := range ifaces {
		// 过滤虚拟网卡、回环网卡、未启用网卡
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || iface.HardwareAddr.String() == "" {
			continue
		}

		nicName := strings.ToLower(iface.Name)
		if strings.Contains(nicName, "docker") || strings.Contains(nicName, "vmware") || 
			strings.Contains(nicName, "virtual") || strings.Contains(nicName, "vpn") {
			continue
		}

		// 获取网卡IP地址
		addrs, err := iface.Addrs()
		if err != nil {
			logger.Warn("获取网卡%s地址失败：%v", iface.Name, err)
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok || ipNet.IP.IsLoopback() {
				continue
			}

			// 只保留IPv4私有地址
			ip := ipNet.IP.To4()
			if ip != nil && isPrivateIPv4(ip) {
				networkInfos = append(networkInfos, NetworkInfo{
					InterfaceName: iface.Name,
					IPAddress:     ip.String(),
				})
				logger.Debug("网卡%s有效私有IP：%s", iface.Name, ip.String())
				break // 每个网卡只取第一个有效IP
			}
		}
	}

	if len(networkInfos) == 0 {
		networkInfos = append(networkInfos, NetworkInfo{
			InterfaceName: "default",
			IPAddress:     "127.0.0.1",
		})
		logger.Warn("未获取到有效私有IP，使用回环地址")
	}
	return networkInfos
}

// reportIP 上报IP信息到服务器
func reportIP() error {
	networks := getLocalNetworks()
	payload := ReportPayload{
		UUID:      machineFixedUUID,
		Username:  systemUsername,
		Networks:  networks,
		TimeStamp: time.Now().Format(time.RFC3339),
	}

	// 序列化JSON
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("序列化数据失败：%v", err)
	}

	// 发送POST请求
	req, err := http.NewRequest("POST", WorkersURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("创建请求失败：%v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", APIKey)

	client := &http.Client{Timeout: Timeout}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("发送请求失败：%v", err)
	}
	defer resp.Body.Close()

	// 读取响应
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("读取响应失败：%v", err)
	}

	// 检查响应状态码
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("上报失败，状态码：%d，响应：%s", resp.StatusCode, string(body))
	}

	logger.Debug("IP上报成功，响应：%s", string(body))
	return nil
}

// ========== 服务安装/启停相关函数 ==========
// installService 注册Windows服务
func installService() error {
	logger.Debug("开始注册Windows服务")
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	// 检查服务是否已存在
	if _, err := m.OpenService(serviceName); err == nil {
		return fmt.Errorf("服务%s已存在", serviceName)
	}

	// 获取程序完整路径
	exePath, err := os.Executable()
	if err != nil {
		return err
	}

	// 创建服务（设置为自动启动）
	s, err := m.CreateService(
		serviceName,
		exePath,
		mgr.Config{
			DisplayName: displayName,
			Description: serviceDesc,
			StartType:   mgr.StartAutomatic, // 自动启动
		},
	)
	if err != nil {
		return err
	}
	defer s.Close()

	// 注册事件日志
	if err := eventlog.InstallAsEventCreate(serviceName, eventlog.Error|eventlog.Warning|eventlog.Info); err != nil {
		logger.Warn("注册事件日志失败：%v", err)
	}

	logger.Info("服务%s注册成功（自动启动）", serviceName)
	return nil
}

// startService 启动Windows服务
func startService() error {
	logger.Debug("开始启动服务：%s", serviceName)
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

	// 启动服务
	if err := s.Start("is", "manual-start"); err != nil {
		return err
	}

	// 等待服务启动
	time.Sleep(500 * time.Millisecond)
	status, err := s.Query()
	if err != nil {
		return err
	}

	logger.Info("服务%s启动成功，当前状态：%v", serviceName, status.State)
	return nil
}

// stopService 停止Windows服务
func stopService() error {
	logger.Debug("开始停止服务：%s", serviceName)
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

	// 停止服务
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

	logger.Info("服务%s已停止", serviceName)
	return nil
}

// ========== 日志相关方法 ==========
func (l *Logger) Debug(format string, v ...interface{}) {
	l.log(LogLevelDebug, format, v...)
}

func (l *Logger) Info(format string, v ...interface{}) {
	l.log(LogLevelInfo, format, v...)
}

func (l *Logger) Warn(format string, v ...interface{}) {
	l.log(LogLevelWarn, format, v...)
}

func (l *Logger) Error(format string, v ...interface{}) {
	l.log(LogLevelError, format, v...)
}

func (l *Logger) log(level, format string, v ...interface{}) {
	// 格式化日志内容
	msg := fmt.Sprintf(format, v...)
	timestamp := time.Now().Format("2006-01-02 15:04:05.000")
	logContent := fmt.Sprintf("[%s] [%s] %s\n", timestamp, level, msg)

	// 日志轮转
	l.rotateLogIfNeeded()

	// 写入文件
	f, err := os.OpenFile(l.logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		fmt.Printf("写入日志失败：%v，内容：%s\n", err, logContent)
		return
	}
	defer f.Close()

	if _, err := f.WriteString(logContent); err != nil {
		fmt.Printf("写入日志内容失败：%v\n", err)
	}

	// 写入系统事件日志（如果可用）
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

	// 未达到最大大小，不轮转
	if fileInfo.Size() < l.maxSize {
		return
	}

	l.Info("日志文件超过%dMB，开始轮转", l.maxSize/1024/1024)

	// 删除最旧的备份
	oldestLog := fmt.Sprintf("%s.%d", l.logFile, l.maxBackups)
	if _, err := os.Stat(oldestLog); err == nil {
		if err := os.Remove(oldestLog); err != nil {
			l.Warn("删除最旧日志备份失败：%v", err)
		}
	}

	// 备份文件重命名（从旧到新）
	for i := l.maxBackups - 1; i > 0; i-- {
		src := fmt.Sprintf("%s.%d", l.logFile, i)
		dst := fmt.Sprintf("%s.%d", l.logFile, i+1)
		if _, err := os.Stat(src); err == nil {
			if err := os.Rename(src, dst); err != nil {
				l.Warn("重命名日志备份失败 %s -> %s：%v", src, dst, err)
			}
		}
	}

	// 重命名当前日志为备份
	if err := os.Rename(l.logFile, fmt.Sprintf("%s.1", l.logFile)); err != nil {
		l.Error("重命名当前日志失败：%v", err)
		return
	}

	l.Info("日志轮转完成")
}

// ========== 服务运行相关 ==========
// runService 服务主循环
func runService() {
	logger.Info("服务开始运行，上报间隔：%v", reportInterval)

	// 首次运行立即上报
	if isFirstRun {
		logger.Info("首次运行，立即上报IP信息")
		if err := reportIP(); err != nil {
			logger.Error("首次上报失败：%v", err)
		} else {
			// 更新首次运行标志
			if err := ioutil.WriteFile(firstRunFlag, []byte(time.Now().String()), 0600); err != nil {
				logger.Warn("更新首次运行标志失败：%v", err)
			}
		}
	}

	// 定时上报循环
	ticker := time.NewTicker(reportInterval)
	defer ticker.Stop()

	for range ticker.C {
		logger.Info("开始定时上报IP信息")
		if err := reportIP(); err != nil {
			logger.Error("定时上报失败：%v", err)
		} else {
			logger.Info("定时上报成功")
		}
	}
}

// ========== 主函数 ==========
func main() {
	// 隐藏控制台窗口（服务运行时）
	hideConsoleWindow()

	// 处理命令行参数
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "install":
			if err := Install(); err != nil {
				logger.Error("安装失败：%v", err)
				os.Exit(1)
			}
			os.Exit(0)

		case "uninstall":
			if err := Uninstall(); err != nil {
				logger.Error("卸载失败：%v", err)
				os.Exit(1)
			}
			os.Exit(0)

		case "start":
			if err := startService(); err != nil {
				logger.Error("启动服务失败：%v", err)
				os.Exit(1)
			}
			os.Exit(0)

		case "stop":
			if err := stopService(); err != nil {
				logger.Error("停止服务失败：%v", err)
				os.Exit(1)
			}
			os.Exit(0)

		default:
			logger.Error("未知命令：%s，支持的命令：install/uninstall/start/stop", os.Args[1])
			os.Exit(1)
		}
	}

	// 作为服务运行
	isService, err := svc.IsWindowsService()
	if err != nil {
		logger.Error("检测是否为服务运行失败：%v", err)
		os.Exit(1)
	}

	if isService {
		// 以服务模式运行
		if err := svc.Run(serviceName, &ipReportService{}); err != nil {
			logger.Error("服务运行失败：%v", err)
			os.Exit(1)
		}
	} else {
		// 控制台模式运行（调试用）
		logger.Info("以控制台模式运行（调试）")
		showConsoleWindow()
		runService()
	}
}

// ipReportService 服务实现
type ipReportService struct{}

func (s *ipReportService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	const acceptedCmds = svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPauseAndContinue

	// 设置服务状态
	changes <- svc.Status{State: svc.StartPending, WaitHint: 2000}
	logger.Info("服务启动中...")

	// 启动业务逻辑
	go runService()

	// 设置服务为运行状态
	changes <- svc.Status{State: svc.Running, Accepts: acceptedCmds, WaitHint: 1000}
	logger.Info("服务已启动，等待控制指令")

	// 处理服务控制指令
loop:
	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus

			case svc.Stop, svc.Shutdown:
				logger.Info("收到停止/关机指令，服务即将退出")
				changes <- svc.Status{State: svc.StopPending, WaitHint: 2000}
				break loop

			case svc.Pause:
				logger.Info("收到暂停指令")
				changes <- svc.Status{State: svc.Paused, Accepts: acceptedCmds, WaitHint: 1000}

			case svc.Continue:
				logger.Info("收到继续指令")
				changes <- svc.Status{State: svc.Running, Accepts: acceptedCmds, WaitHint: 1000}

			default:
				logger.Warn("收到未知服务控制指令：%v", c)
				changes <- c.CurrentStatus
			}
		}
	}

	logger.Info("服务已停止")
	changes <- svc.Status{State: svc.Stopped, Accepts: acceptedCmds, WaitHint: 1000}
	return false, 0
}

// hideConsoleWindow 隐藏控制台窗口
func hideConsoleWindow() {
	logger.Debug("隐藏控制台窗口")
	hwnd, _, _ := procGetConsoleWindow.Call()
	if hwnd != 0 {
		procShowWindow.Call(hwnd, uintptr(SW_HIDE))
		procSetWindowPos.Call(
			hwnd,
			0,
			0, 0, 0, 0,
			uintptr(SWP_HIDEWINDOW|SWP_NOMOVE|SWP_NOSIZE),
		)
	}
}