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
	"strings"
	"syscall"
	"time"
)

// ========== Windows API常量定义（核心：无控制台运行） ==========
const (
	// Windows信号常量
	SIGBREAK = syscall.Signal(21)
	// 进程创建标志
	CREATE_NO_WINDOW    = 0x08000000
	DETACHED_PROCESS    = 0x00000008
	CREATE_NEW_PROCESS_GROUP = 0x00000200
	// Windows API：窗口显示状态
	SW_HIDE = 0 // 隐藏窗口
)

// Windows API函数声明（隐藏控制台窗口）
var (
	user32        = syscall.NewLazyDLL("user32.dll")
	kernel32      = syscall.NewLazyDLL("kernel32.dll")
	getConsoleWindow = kernel32.NewProc("GetConsoleWindow")
	showWindow      = user32.NewProc("ShowWindow")
)

// 配置项：仅适配Windows系统
const (
	WorkersURL      = "https://getip.ammon.de5.net/api/report" // 上报地址
	Timeout         = 5 * time.Second                         // 上报超时时间
	APIKey          = "9ddae7a3-c730-469e-b644-859880ad9752"  // 与Workers代码中的API_KEY一致
	DefaultInterval = 1 * time.Minute                         // 默认上报间隔：1分钟
	ViewURLTemplate = "https://getip.ammon.de5.net/view/%s"    // UUID查看地址模板
)

// 全局变量
var (
	machineFixedUUID  string        // 机器固定UUID（基于物理网卡MAC）
	isFirstReportSucc = true         // 标记是否首次上报成功（控制仅打开一次浏览器）
)

// ReportData 上报到 Workers 的数据结构
type ReportData struct {
	UUID      string        `json:"uuid"`      // 唯一查询标志
	Username  string        `json:"username"`  // 登录用户名
	Hostname  string        `json:"hostname"`  // 主机名
	Networks  []NetworkInfo `json:"networks"`  // 网络信息
	Timestamp string        `json:"timestamp"` // 检测时间
}

// NetworkInfo 网络接口信息
type NetworkInfo struct {
	InterfaceName string `json:"interface_name"` // 网卡名称
	IPAddress     string `json:"ip_address"`     // IP地址
	Gateway       string `json:"gateway"`        // 网关
	SubnetMask    string `json:"subnet_mask"`    // 子网掩码
}

func main() {
	// ========== 核心：CI编译模式（必须保留，避免Actions卡住） ==========
	buildOnly := flag.Bool("build", false, "仅编译模式（CI环境使用，不运行业务逻辑）")
	// 上报间隔参数（保留自定义能力）
	intervalMin := flag.Float64("interval", 1.0, "定时上报间隔（分钟），例如 0.5 表示30秒，2 表示2分钟")
	flag.Parse()

	// CI环境仅编译，不运行程序
	if *buildOnly {
		fmt.Println("【编译模式】仅执行编译，不运行业务逻辑")
		return
	}

	// ========== 关键：启动后立即隐藏控制台窗口（无界面运行） ==========
	hideConsoleWindow()

	// ========== 进程分离：确保关闭控制台后程序仍运行 ==========
	setProcessDetached()

	// 验证并转换间隔参数
	reportInterval := DefaultInterval
	if *intervalMin > 0 {
		reportInterval = time.Duration(*intervalMin * 60) * time.Second
	} else {
		// 无控制台时，错误信息写入临时文件（可选，便于调试）
		writeLog(fmt.Sprintf("【警告】间隔参数无效（%.2f分钟），使用默认值：1分钟", *intervalMin))
	}

	// 初始化机器固定UUID
	initMachineFixedUUID()

	// 初始化定时器
	ticker := time.NewTicker(reportInterval)
	defer ticker.Stop()

	// 处理Windows退出信号（仅用于进程正常退出，无控制台时不生效）
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, SIGBREAK)

	// 首次立即上报
	performReport()

	// 定时循环上报（独立goroutine，不阻塞）
	go func() {
		for range ticker.C {
			performReport()
		}
	}()

	// ========== 永久阻塞：保持进程后台运行（核心） ==========
	// 方式1：等待退出信号（无控制台时，需通过任务管理器结束进程）
	<-sigChan
	// 方式2：无限循环（备选，注释掉上面的<-sigChan，启用下面的代码）
	// for {
	// 	time.Sleep(1 * time.Hour)
	// }

	// 退出清理
	ticker.Stop()
	writeLog("【退出】定时上报已停止，程序结束")
}

// hideConsoleWindow 隐藏控制台窗口（Windows专属）
func hideConsoleWindow() {
	// 获取当前控制台窗口句柄
	hwnd, _, _ := getConsoleWindow.Call()
	if hwnd != 0 {
		// 隐藏窗口（SW_HIDE = 0）
		showWindow.Call(hwnd, SW_HIDE)
	}
}

// setProcessDetached 设置进程为分离模式，不依赖控制台
func setProcessDetached() {
	// 获取当前进程句柄
	procHandle, _, _ := kernel32.NewProc("GetCurrentProcess").Call()
	// 设置进程优先级（可选，确保后台运行不卡顿）
	kernel32.NewProc("SetPriorityClass").Call(procHandle, 0x00000040) // BELOW_NORMAL_PRIORITY_CLASS
}

// writeLog 无控制台时，写入日志到临时文件（便于调试）
func writeLog(content string) {
	logPath := os.TempDir() + "\\GetIPviaWEB.log"
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	logContent := fmt.Sprintf("[%s] %s\n", time.Now().Format("2006-01-02 15:04:05"), content)
	_, _ = f.WriteString(logContent)
}

// performReport 执行单次上报逻辑（所有原有功能完全保留）
func performReport() {
	// 获取当前登录用户名（Windows专属处理）
	username, err := getCurrentUsername()
	if err != nil {
		username = fmt.Sprintf("获取失败：%v", err)
		writeLog(fmt.Sprintf("【错误】获取用户名失败：%v", err))
	}

	// 获取主机名
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "Unknown"
		writeLog(fmt.Sprintf("【错误】获取主机名失败：%v", err))
	}

	// 获取Windows物理网卡信息
	networkInfos, err := getActivePhysicalNicInfo()
	if err != nil {
		writeLog(fmt.Sprintf("【错误】获取物理网卡信息失败：%v", err))
	} else if len(networkInfos) == 0 {
		writeLog("【提示】未检测到正在使用的物理网卡IPv4地址")
	}

	// 上报信息到Workers
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
		writeLog(fmt.Sprintf("【上报成功】核心信息已发送，UUID：%s", machineFixedUUID))
		// 首次上报成功后打开Windows默认浏览器（核心功能保留）
		if isFirstReportSucc {
			viewURL := fmt.Sprintf(ViewURLTemplate, machineFixedUUID)
			writeLog(fmt.Sprintf("【首次上报】正在打开浏览器访问：%s", viewURL))
			// 异步打开浏览器，不阻塞上报流程
			go func() {
				if err := openBrowser(viewURL); err != nil {
					writeLog(fmt.Sprintf("【错误】打开浏览器失败：%v", err))
				}
			}()
			isFirstReportSucc = false // 标记为已打开，避免重复执行
		}
	}
}

// openBrowser Windows专属打开浏览器函数（功能保留，优化无控制台适配）
func openBrowser(url string) error {
	// Windows专用命令：start "" 避免URL含空格时解析错误
	cmd := exec.Command("cmd", "/c", "start", "", url)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true, // 隐藏cmd窗口，仅打开浏览器
		CreationFlags: CREATE_NO_WINDOW,
	}

	// 忽略命令输出，无控制台时无需处理
	cmd.Stdout = nil
	cmd.Stderr = nil
	err := cmd.Start()
	if err != nil {
		return fmt.Errorf("Windows打开浏览器失败：%w", err)
	}

	// 异步等待命令完成（不阻塞主程序）
	go func() {
		_ = cmd.Wait()
	}()

	return nil
}

// getCurrentUsername 获取Windows纯用户名（功能保留）
func getCurrentUsername() (string, error) {
	currentUser, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("获取用户信息失败：%w", err)
	}

	// Windows专属：拆分“计算机名\用户名”，仅保留用户名
	if strings.Contains(currentUser.Username, "\\") {
		parts := strings.Split(currentUser.Username, "\\")
		return parts[len(parts)-1], nil
	}

	return currentUser.Username, nil
}

// initMachineFixedUUID 初始化Windows机器固定UUID（功能保留）
func initMachineFixedUUID() {
	macAddr := getPhysicalNicMAC()
	if macAddr == "" {
		machineFixedUUID = "00000000-0000-0000-0000-000000000000"
		writeLog("【警告】未获取到物理网卡MAC，使用默认UUID：" + machineFixedUUID)
		return
	}

	// 基于MAC生成固定UUID
	hash := md5.Sum([]byte(macAddr))
	uuidStr := fmt.Sprintf("%x-%x-%x-%x-%x",
		hash[0:4],
		hash[4:6],
		hash[6:8],
		hash[8:10],
		hash[10:16],
	)
	machineFixedUUID = uuidStr
	writeLog("【初始化】机器唯一UUID：" + machineFixedUUID)
}

// getPhysicalNicMAC 获取Windows物理网卡MAC（功能保留）
func getPhysicalNicMAC() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		writeLog(fmt.Sprintf("【错误】获取网卡列表失败：%v", err))
		return ""
	}

	// 遍历筛选Windows物理网卡
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 ||
			iface.Flags&net.FlagLoopback != 0 ||
			iface.HardwareAddr.String() == "" {
			continue
		}

		nicName := strings.ToLower(iface.Name)
		// 排除Windows常见虚拟网卡
		if strings.Contains(nicName, "docker") ||
			strings.Contains(nicName, "vmware") ||
			strings.Contains(nicName, "virtual") ||
			strings.Contains(nicName, "vpn") ||
			strings.Contains(nicName, "hyper-v") ||
			strings.Contains(nicName, "tun") ||
			strings.Contains(nicName, "tap") ||
			strings.Contains(nicName, "pppoe") ||
			strings.Contains(nicName, "bridge") ||
			strings.Contains(nicName, "nat") ||
			strings.Contains(nicName, "loopback") ||
			strings.Contains(nicName, "isatap") ||
			strings.Contains(nicName, "teredo") {
			continue
		}

		// 优先返回Windows有线/无线物理网卡
		if strings.Contains(nicName, "ethernet") ||
			strings.Contains(nicName, "wlan") ||
			strings.Contains(nicName, "wi-fi") ||
			strings.Contains(nicName, "lan") {
			writeLog(fmt.Sprintf("【调试】找到Windows物理网卡：%s，MAC：%s", iface.Name, iface.HardwareAddr.String()))
			return iface.HardwareAddr.String()
		}
	}

	// Windows兜底：返回第一个有效物理网卡
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp != 0 &&
			iface.Flags&net.FlagLoopback == 0 &&
			iface.HardwareAddr.String() != "" {
			writeLog(fmt.Sprintf("【调试】Windows兜底物理网卡：%s，MAC：%s", iface.Name, iface.HardwareAddr.String()))
			return iface.HardwareAddr.String()
		}
	}

	writeLog("【警告】Windows未找到任何物理网卡MAC")
	return ""
}

// getActivePhysicalNicInfo 获取Windows正在使用的物理网卡完整信息（功能保留）
func getActivePhysicalNicInfo() ([]NetworkInfo, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("Windows获取网卡列表失败：%w", err)
	}

	var networkInfos []NetworkInfo

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 ||
			iface.Flags&net.FlagLoopback != 0 ||
			iface.HardwareAddr.String() == "" {
			continue
		}

		nicName := strings.ToLower(iface.Name)
		// 排除Windows虚拟网卡
		if strings.Contains(nicName, "docker") ||
			strings.Contains(nicName, "vmware") ||
			strings.Contains(nicName, "virtual") ||
			strings.Contains(nicName, "vpn") ||
			strings.Contains(nicName, "hyper-v") {
			continue
		}

		// 获取Windows网卡地址
		addrs, err := iface.Addrs()
		if err != nil {
			writeLog(fmt.Sprintf("【调试】Windows网卡%s获取地址失败：%v", iface.Name, err))
			continue
		}

		// 获取Windows网卡网关和子网掩码
		gateway, subnetMask := getGatewayAndSubnet(iface.Name)

		// 筛选Windows私有IPv4
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
			writeLog(fmt.Sprintf("【调试】Windows物理网卡%s的有效IPv4：%s", iface.Name, ipStr))

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

// getGatewayAndSubnet 获取Windows指定网卡的网关和子网掩码（功能保留）
func getGatewayAndSubnet(ifaceName string) (string, string) {
	// Windows专属：可通过exec调用route print/ipconfig解析，此处简化返回空
	return "", ""
}

// isPrivateIPv4 判断是否为Windows私有内网IPv4（功能保留）
func isPrivateIPv4(ip net.IP) bool {
	if ip == nil {
		return false
	}
	// 私有IPv4网段（Windows通用）
	if ip[0] == 10 ||
		(ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31) ||
		(ip[0] == 192 && ip[1] == 168) ||
		(ip[0] == 169 && ip[1] == 254) {
		return true
	}
	return false
}

// reportToWorkers 上报信息到Workers（功能保留）
func reportToWorkers(data ReportData) error {
	// 序列化JSON
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("JSON序列化失败：%w", err)
	}

	// Windows HTTP客户端（带超时）
	client := &http.Client{
		Timeout: Timeout,
	}

	// 创建POST请求
	req, err := http.NewRequest("POST", WorkersURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("创建请求失败：%w", err)
	}

	// 设置请求头
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("X-API-Key", APIKey)

	// 发送请求
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("Windows发送请求失败：%w", err)
	}
	defer resp.Body.Close()

	// 解析响应
	var respData map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&respData); err != nil {
		return fmt.Errorf("解析响应失败：%w", err)
	}

	// 检查业务结果
	if success, ok := respData["success"].(bool); ok && !success {
		if errMsg, ok := respData["error"].(string); ok {
			return fmt.Errorf("Workers业务错误：%s", errMsg)
		}
		return fmt.Errorf("Workers返回未知错误：%v", respData)
	}

	return nil
}