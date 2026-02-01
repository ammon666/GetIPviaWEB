package main

import (
	"bytes"
	"crypto/md5"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/kardianos/service"
)

// ========== 全局配置 ==========
var (
	// 日志路径（服务模式下ProgramData更易访问）
	logPath = filepath.Join(os.Getenv("ProgramData"), "GetIPviaWEB", "service.log")
	// 服务配置（仅保留必选字段，避免版本兼容问题）
	serviceConfig = &service.Config{
		Name:        "GetIPviaWEBService",       // 服务名称（唯一，不可包含空格）
		DisplayName: "IP监控自动上报服务",        // 服务显示名称
		Description: "开机自动运行（未登录也可），定时上报IP信息", // 服务描述
	}

	// Windows API常量（修正类型匹配问题）
	SIGBREAK        = syscall.Signal(21)
	CREATE_NO_WINDOW = 0x08000000 // uint32类型
	SW_HIDE         = 0           // uintptr类型

	// 业务常量
	WorkersURL      = "https://getip.ammon.de5.net/api/report"
	Timeout         = 5 * time.Second
	APIKey          = "9ddae7a3-c730-469e-b644-859880ad9752"
	DefaultInterval = 1 * time.Minute
	ViewURLTemplate = "https://getip.ammon.de5.net/view/%s"

	// 业务全局变量
	machineFixedUUID  string
	isFirstReportSucc = true
	logger           service.Logger // 服务日志
)

// ========== 数据结构 ==========
type ReportData struct {
	UUID      string        `json:"uuid"`
	Username  string        `json:"username"`
	Hostname  string        `json:"hostname"`
	Networks  []NetworkInfo `json:"networks"`
	Timestamp string        `json:"timestamp"`
}

type NetworkInfo struct {
	InterfaceName string `json:"interface_name"`
	IPAddress     string `json:"ip_address"`
	Gateway       string `json:"gateway"`
	SubnetMask    string `json:"subnet_mask"`
}

// ========== 服务实现（核心：开机自启） ==========
type IPReportService struct{}

// Start 服务启动时执行（系统开机/手动启动服务时触发）
func (s *IPReportService) Start(svc service.Service) error {
	// 异步执行业务逻辑，避免阻塞服务管理器
	go s.run()
	return nil
}

// Stop 服务停止时执行
func (s *IPReportService) Stop(svc service.Service) error {
	writeLog("【服务】IP监控服务已停止")
	return nil
}

// run 核心业务逻辑（原有功能全部迁移到这里）
func (s *IPReportService) run() {
	writeLog("【服务】IP监控服务已启动（开机未登录运行模式）")

	// 初始化UUID
	initMachineFixedUUID()

	// 解析上报间隔（服务模式默认1分钟，也可通过参数自定义）
	intervalMin := 1.0
	flag.Parse()
	if *flagInterval > 0 {
		intervalMin = *flagInterval
	}
	reportInterval := time.Duration(intervalMin * 60) * time.Second

	// 初始化定时器
	ticker := time.NewTicker(reportInterval)
	defer ticker.Stop()

	// 首次立即上报
	performReport()

	// 定时循环上报
	for range ticker.C {
		performReport()
	}
}

// ========== 命令行参数定义 ==========
var (
	flagBuild   = flag.Bool("build", false, "仅编译模式（CI环境）")
	flagInterval = flag.Float64("interval", 1.0, "上报间隔（分钟）")
	flagService  = flag.String("service", "", "服务操作：install/uninstall/start/stop/restart")
)

// ========== 工具函数 ==========
// writeLog 统一日志写入（兼容服务/手动模式）
func writeLog(content string) {
	logContent := fmt.Sprintf("[%s] %s\n", time.Now().Format("2006-01-02 15:04:05"), content)
	
	// 服务模式使用service.Logger，手动模式写入文件
	if logger != nil {
		logger.Info(logContent)
	}

	// 确保日志目录存在
	logDir := filepath.Dir(logPath)
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return
	}

	// 写入日志文件
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.WriteString(logContent)
}

// hideConsoleWindow 手动运行时隐藏控制台（修复类型转换）
func hideConsoleWindow() {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	user32 := syscall.NewLazyDLL("user32.dll")
	getConsoleWindow := kernel32.NewProc("GetConsoleWindow")
	showWindow := user32.NewProc("ShowWindow")

	hwnd, _, _ := getConsoleWindow.Call()
	if hwnd != 0 {
		// 修复：SW_HIDE转换为uintptr类型
		showWindow.Call(hwnd, uintptr(SW_HIDE))
	}
}

// setServiceAutoStart 通过sc命令设置服务为自动启动（核心：开机未登录运行）
func setServiceAutoStart(serviceName string) error {
	// sc config 服务名 start= auto（注意start=后有空格）
	cmd := exec.Command("sc", "config", serviceName, "start=", "auto")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: uint32(CREATE_NO_WINDOW),
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("设置自动启动失败：%v，输出：%s", err, string(output))
	}
	writeLog("【服务】成功设置服务为自动启动")
	return nil
}

// openBrowser 打开浏览器（兼容服务模式：登录后才显示，修复类型转换）
func openBrowser(url string) error {
	cmd := exec.Command("cmd", "/c", "start", "", url)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		// 修复：CREATE_NO_WINDOW转换为uint32类型
		CreationFlags: uint32(CREATE_NO_WINDOW),
	}
	cmd.Stdout = nil
	cmd.Stderr = nil

	err := cmd.Start()
	if err != nil {
		writeLog(fmt.Sprintf("【错误】打开浏览器失败：%v", err))
		return err
	}

	go func() {
		_ = cmd.Wait()
	}()
	return nil
}

// ========== 原有业务逻辑（完全保留） ==========
func initMachineFixedUUID() {
	macAddr := getPhysicalNicMAC()
	if macAddr == "" {
		machineFixedUUID = "00000000-0000-0000-0000-000000000000"
		writeLog("【警告】未获取到MAC，使用默认UUID：" + machineFixedUUID)
		return
	}

	hash := md5.Sum([]byte(macAddr))
	machineFixedUUID = fmt.Sprintf("%x-%x-%x-%x-%x",
		hash[0:4], hash[4:6], hash[6:8], hash[8:10], hash[10:16])
	writeLog("【初始化】UUID：" + machineFixedUUID)
}

func getPhysicalNicMAC() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		writeLog(fmt.Sprintf("【错误】获取网卡列表失败：%v", err))
		return ""
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || iface.HardwareAddr.String() == "" {
			continue
		}

		nicName := strings.ToLower(iface.Name)
		if strings.Contains(nicName, "docker") || strings.Contains(nicName, "vmware") || strings.Contains(nicName, "virtual") ||
			strings.Contains(nicName, "vpn") || strings.Contains(nicName, "hyper-v") {
			continue
		}

		if strings.Contains(nicName, "ethernet") || strings.Contains(nicName, "wlan") || strings.Contains(nicName, "wi-fi") {
			writeLog(fmt.Sprintf("【调试】找到物理网卡：%s，MAC：%s", iface.Name, iface.HardwareAddr.String()))
			return iface.HardwareAddr.String()
		}
	}

	writeLog("【警告】未找到有效物理网卡MAC")
	return ""
}

func getActivePhysicalNicInfo() ([]NetworkInfo, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("获取网卡列表失败：%w", err)
	}

	var networkInfos []NetworkInfo
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || iface.HardwareAddr.String() == "" {
			continue
		}

		nicName := strings.ToLower(iface.Name)
		if strings.Contains(nicName, "docker") || strings.Contains(nicName, "vmware") || strings.Contains(nicName, "virtual") {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			writeLog(fmt.Sprintf("【调试】网卡%s获取地址失败：%v", iface.Name, err))
			continue
		}

		gateway, subnetMask := getGatewayAndSubnet(iface.Name)
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
			writeLog(fmt.Sprintf("【调试】网卡%s有效IPv4：%s", iface.Name, ipStr))
			networkInfos = append(networkInfos, NetworkInfo{
				InterfaceName: iface.Name,
				IPAddress:     ipStr,
				Gateway:       gateway,
				SubnetMask:    subnetMask,
			})
			break
		}
	}

	return networkInfos, nil
}

func getGatewayAndSubnet(ifaceName string) (string, string) {
	return "", "" // 保持原有逻辑，如需实现可调用ipconfig解析
}

func isPrivateIPv4(ip net.IP) bool {
	if ip == nil {
		return false
	}
	return ip[0] == 10 || (ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31) ||
		(ip[0] == 192 && ip[1] == 168) || (ip[0] == 169 && ip[1] == 254)
}

func getCurrentUsername() string {
	currentUser, err := user.Current()
	if err != nil {
		writeLog(fmt.Sprintf("【错误】获取用户名失败：%v", err))
		return "未知用户"
	}

	if strings.Contains(currentUser.Username, "\\") {
		parts := strings.Split(currentUser.Username, "\\")
		return parts[len(parts)-1]
	}
	return currentUser.Username
}

func reportToWorkers(data ReportData) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("JSON序列化失败：%w", err)
	}

	client := &http.Client{Timeout: Timeout}
	req, err := http.NewRequest("POST", WorkersURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("创建请求失败：%w", err)
	}

	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("X-API-Key", APIKey)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("发送请求失败：%w", err)
	}
	defer resp.Body.Close()

	var respData map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&respData); err != nil {
		return fmt.Errorf("解析响应失败：%w", err)
	}

	if success, ok := respData["success"].(bool); ok && !success {
		if errMsg, ok := respData["error"].(string); ok {
			return fmt.Errorf("业务错误：%s", errMsg)
		}
		return fmt.Errorf("未知响应：%v", respData)
	}

	return nil
}

func performReport() {
	username := getCurrentUsername()
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "未知主机名"
		writeLog(fmt.Sprintf("【错误】获取主机名失败：%v", err))
	}

	networkInfos, err := getActivePhysicalNicInfo()
	if err != nil {
		writeLog(fmt.Sprintf("【错误】获取网卡信息失败：%v", err))
	}

	reportData := ReportData{
		UUID:      machineFixedUUID,
		Username:  username,
		Hostname:  hostname,
		Networks:  networkInfos,
		Timestamp: time.Now().Format("2006-01-02 15:04:05"),
	}

	if err := reportToWorkers(reportData); err != nil {
		writeLog(fmt.Sprintf("【上报失败】%v", err))
	} else {
		writeLog(fmt.Sprintf("【上报成功】UUID：%s", machineFixedUUID))
		if isFirstReportSucc {
			viewURL := fmt.Sprintf(ViewURLTemplate, machineFixedUUID)
			writeLog(fmt.Sprintf("【首次上报】打开浏览器：%s", viewURL))
			go openBrowser(viewURL)
			isFirstReportSucc = false
		}
	}
}

// ========== 主函数（整合服务/手动模式） ==========
func main() {
	// CI编译模式：直接返回
	if *flagBuild {
		fmt.Println("【编译模式】仅执行编译，不运行程序")
		return
	}

	// 服务模式处理（核心：开机自启）
	if *flagService != "" {
		// 创建服务实例
		svc, err := service.New(&IPReportService{}, serviceConfig)
		if err != nil {
			fmt.Printf("【错误】创建服务失败：%v\n", err)
			os.Exit(1)
		}

		// 初始化服务日志
		logger, err = svc.Logger(nil)
		if err != nil {
			fmt.Printf("【错误】初始化日志失败：%v\n", err)
			os.Exit(1)
		}

		// 执行服务操作
		switch *flagService {
		case "install":
			if err := svc.Install(); err != nil {
				fmt.Printf("【错误】安装服务失败（需管理员权限）：%v\n", err)
				os.Exit(1)
			}
			// 关键：安装后立即设置为自动启动（确保开机未登录运行）
			if err := setServiceAutoStart(serviceConfig.Name); err != nil {
				fmt.Printf("【警告】设置自动启动失败：%v\n", err)
			}
			fmt.Println("【成功】服务安装完成（已设置开机自动运行）")
		case "uninstall":
			if err := svc.Uninstall(); err != nil {
				fmt.Printf("【错误】卸载服务失败（需管理员权限）：%v\n", err)
				os.Exit(1)
			}
			fmt.Println("【成功】服务卸载完成")
		case "start":
			if err := svc.Start(); err != nil {
				fmt.Printf("【错误】启动服务失败（需管理员权限）：%v\n", err)
				os.Exit(1)
			}
			fmt.Println("【成功】服务启动完成")
		case "stop":
			if err := svc.Stop(); err != nil {
				fmt.Printf("【错误】停止服务失败（需管理员权限）：%v\n", err)
				os.Exit(1)
			}
			fmt.Println("【成功】服务停止完成")
		case "restart":
			if err := svc.Stop(); err != nil {
				fmt.Printf("【警告】停止服务失败：%v\n", err)
			}
			time.Sleep(1 * time.Second)
			if err := svc.Start(); err != nil {
				fmt.Printf("【错误】重启服务失败：%v\n", err)
				os.Exit(1)
			}
			fmt.Println("【成功】服务重启完成")
		default:
			fmt.Println("【错误】无效的服务操作，支持：install/uninstall/start/stop/restart")
			os.Exit(1)
		}
		return
	}

	// 手动运行模式（保留原有逻辑，无控制台）
	hideConsoleWindow()
	writeLog("【手动模式】程序已启动（无控制台后台运行）")

	// 手动模式执行业务逻辑
	initMachineFixedUUID()
	reportInterval := time.Duration(*flagInterval * 60) * time.Second
	ticker := time.NewTicker(reportInterval)
	defer ticker.Stop()

	performReport()

	// 处理退出信号
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, SIGBREAK)

	go func() {
		for range ticker.C {
			performReport()
		}
	}()

	<-sigChan
	writeLog("【手动模式】程序已停止")
	ticker.Stop()
}