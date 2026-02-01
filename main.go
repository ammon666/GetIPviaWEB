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
	"strconv"
	"strings"
	"syscall"
	"time"
)

// 配置项：修正后的正确上报地址（删除了错误的POST%20）
const (
	WorkersURL = "https://getip.ammon.de5.net/api/report" // 正确的上报地址
	Timeout    = 5 * time.Second                         // 上报超时时间
	APIKey     = "9ddae7a3-c730-469e-b644-859880ad9752"  // 需与Workers代码中的API_KEY保持一致
	ProcessName = "ip-monitor-daemon"                    // 进程名（任务管理器可见）
)

// 全局变量：存储机器固定UUID（基于物理网卡MAC，作为唯一查询标识）
var (
	machineFixedUUID string
	daemonMode       bool   // 是否后台运行
	exitSignal       bool   // 退出信号
	pidFile          string // PID文件路径（用于记录进程ID）
)

// ReportData 上报到 Workers 的数据结构（兼容Workers接收格式）
type ReportData struct {
	UUID      string        `json:"uuid"`      // 唯一查询标志（优先字段）
	Username  string        `json:"username"`  // 登录用户名
	Hostname  string        `json:"hostname"`  // 主机名
	Networks  []NetworkInfo `json:"networks"`  // 网络信息
	Timestamp string        `json:"timestamp"` // 检测时间
}

// NetworkInfo 网络接口信息（适配Workers接收格式）
type NetworkInfo struct {
	InterfaceName string `json:"interface_name"` // 网卡名称
	IPAddress     string `json:"ip_address"`     // IP地址
	Gateway       string `json:"gateway"`        // 网关
	SubnetMask    string `json:"subnet_mask"`    // 子网掩码
}

func init() {
	// 注册命令行参数
	flag.BoolVar(&daemonMode, "daemon", false, "以后台守护进程模式运行（脱离控制台）")
	flag.StringVar(&pidFile, "pid", "./ip-monitor.pid", "指定PID文件路径（默认：./ip-monitor.pid）")
	flag.BoolVar(&exitSignal, "stop", false, "停止后台运行的进程（需指定PID文件）")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "IP监控工具使用说明:\n")
		fmt.Fprintf(os.Stderr, "  普通运行: %s\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  后台运行: %s -daemon [-pid 自定义PID文件路径]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  停止后台进程: %s -stop [-pid 自定义PID文件路径]\n", os.Args[0])
	}
}

func main() {
	// 解析命令行参数
	flag.Parse()

	// 处理停止进程指令
	if exitSignal {
		if err := stopDaemon(); err != nil {
			fmt.Printf("停止进程失败: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("进程已成功停止")
		os.Exit(0)
	}

	// 后台运行模式：脱离控制台
	if daemonMode {
		if err := startDaemon(); err != nil {
			fmt.Printf("后台启动失败: %v\n", err)
			os.Exit(1)
		}
	}

	// 1. 初始化机器固定UUID（唯一查询标识，优先初始化）
	initMachineFixedUUID()

	// 2. 获取当前登录用户名（仅保留纯用户名，去掉计算机名）
	username, err := getCurrentUsername()
	if err != nil {
		username = fmt.Sprintf("获取失败：%v", err)
	}

	// 3. 获取主机名
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "Unknown"
	}

	// 4. 获取正在使用的物理网卡私有IPv4地址及网络信息
	networkInfos, err := getActivePhysicalNicInfo()
	if err != nil {
		fmt.Printf("【错误】获取物理网卡信息失败：%v\n", err)
	} else if len(networkInfos) == 0 {
		fmt.Println("【提示】未检测到正在使用的物理网卡IPv4地址")
	} else {
		for i, info := range networkInfos {
			fmt.Printf("【成功】物理网卡%d：%s，IP：%s\n", i+1, info.InterfaceName, info.IPAddress)
		}
	}

	// 5. 输出核心信息（UUID 放到最前面，作为唯一标识）
	fmt.Println("\n==================== IP监控工具 ====================")
	fmt.Printf("机器唯一查询标识（UUID）：%s\n", machineFixedUUID) // 优先展示UUID
	fmt.Printf("当前登录用户名：%s\n", username)
	fmt.Printf("主机名：%s\n", hostname)
	fmt.Printf("检测时间：%s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Println("----------------------------------------------------")
	fmt.Println("物理网卡信息：")
	for i, info := range networkInfos {
		fmt.Printf("  网卡%d：%s\n", i+1, info.InterfaceName)
		fmt.Printf("  IP地址：%s\n", info.IPAddress)
		if info.Gateway != "" {
			fmt.Printf("  网关：%s\n", info.Gateway)
		}
		if info.SubnetMask != "" {
			fmt.Printf("  子网掩码：%s\n", info.SubnetMask)
		}
		fmt.Println("----------------------------------------------------")
	}
	fmt.Println("====================================================")

	// 6. 上报信息到指定地址（UUID 作为核心字段）
	reportData := ReportData{
		UUID:      machineFixedUUID,
		Username:  username,
		Hostname:  hostname,
		Networks:  networkInfos,
		Timestamp: time.Now().Format("2006-01-02 15:04:05"),
	}
	if err := reportToWorkers(reportData); err != nil {
		fmt.Printf("\n【上报失败】%v\n", err)
	} else {
		fmt.Println("\n【上报成功】核心信息已发送到指定地址，UUID：", machineFixedUUID)
	}

	// 7. 后台模式：持续运行（避免进程退出）；前台模式：暂停程序
	if daemonMode {
		fmt.Printf("后台进程已启动，PID：%d，PID文件：%s\n", os.Getpid(), pidFile)
		// 后台持续运行（监听退出信号）
		runDaemonLoop()
	} else {
		// 前台模式：暂停程序（控制台窗口不立即关闭）
		fmt.Println("\n按任意键退出...")
		var input string
		fmt.Scanln(&input)
	}
}

// startDaemon 启动后台守护进程（脱离控制台）
func startDaemon() error {
	// 记录PID到文件
	if err := writePIDFile(); err != nil {
		return err
	}

	// Windows系统：创建无控制台进程
	if isWindows() {
		cmd := exec.Command(os.Args[0], "-daemon", "-pid", pidFile)
		cmd.SysProcAttr = &syscall.SysProcAttr{
			HideWindow:    true,        // 隐藏窗口
			CreationFlags: 0x08000000,  // CREATE_NO_WINDOW
		}
		if err := cmd.Start(); err != nil {
			return fmt.Errorf("创建后台进程失败: %w", err)
		}
		fmt.Printf("后台进程已启动，PID：%d\n", cmd.Process.Pid)
		os.Exit(0)
	}

	// Linux/macOS系统：fork进程脱离终端
	process, err := os.StartProcess(os.Args[0], append([]string{os.Args[0]}, "-daemon", "-pid", pidFile), &os.ProcAttr{
		Files: []*os.File{os.Stdin, os.Stdout, os.Stderr},
		Sys: &syscall.SysProcAttr{
			Setpgid: true,
		},
	})
	if err != nil {
		return fmt.Errorf("fork进程失败: %w", err)
	}
	fmt.Printf("后台进程已启动，PID：%d\n", process.Pid)
	os.Exit(0)

	return nil
}

// runDaemonLoop 后台进程主循环（持续运行，监听退出信号）
func runDaemonLoop() {
	// 监听系统退出信号（Windows/Linux通用）
	sigChan := make(chan os.Signal, 1)
	syscall.RegisterSignal(syscall.SIGINT, sigChan)
	syscall.RegisterSignal(syscall.SIGTERM, sigChan)

	// 持续运行，直到收到退出信号
	ticker := time.NewTicker(10 * time.Second) // 每10秒检测一次（可自定义）
	defer ticker.Stop()

	for {
		select {
		case <-sigChan:
			// 收到退出信号，清理PID文件并退出
			os.Remove(pidFile)
			fmt.Println("后台进程收到退出信号，正在退出...")
			os.Exit(0)
		case <-ticker.C:
			// 后台持续运行：可在此添加定时上报逻辑（可选）
			// fmt.Println("后台进程正常运行中...")
		}
	}
}

// stopDaemon 停止后台运行的进程
func stopDaemon() error {
	// 读取PID文件
	pidStr, err := os.ReadFile(pidFile)
	if err != nil {
		return fmt.Errorf("读取PID文件失败: %w", err)
	}

	pid, err := strconv.Atoi(strings.TrimSpace(string(pidStr)))
	if err != nil {
		return fmt.Errorf("解析PID失败: %w", err)
	}

	// 发送终止信号
	var process *os.Process
	if process, err = os.FindProcess(pid); err != nil {
		return fmt.Errorf("查找进程失败: %w", err)
	}

	// Windows/Linux通用终止信号
	if isWindows() {
		if err := process.Kill(); err != nil {
			return fmt.Errorf("终止进程失败: %w", err)
		}
	} else {
		if err := process.Signal(syscall.SIGTERM); err != nil {
			// 优雅终止失败，强制杀死
			if err := process.Kill(); err != nil {
				return fmt.Errorf("终止进程失败: %w", err)
			}
		}
	}

	// 清理PID文件
	os.Remove(pidFile)

	return nil
}

// writePIDFile 写入PID到文件
func writePIDFile() error {
	pid := os.Getpid()
	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(pid)), 0644); err != nil {
		return fmt.Errorf("写入PID文件失败: %w", err)
	}
	return nil
}

// isWindows 判断是否为Windows系统
func isWindows() bool {
	return strings.Contains(strings.ToLower(os.Getenv("OS")), "windows")
}

// getCurrentUsername 获取纯用户名（去掉Windows的计算机名前缀）
func getCurrentUsername() (string, error) {
	currentUser, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("获取用户信息失败：%w", err)
	}

	// Windows下拆分“计算机名\用户名”，仅保留用户名
	if strings.Contains(currentUser.Username, "\\") {
		parts := strings.Split(currentUser.Username, "\\")
		return parts[len(parts)-1], nil
	}

	// Linux/macOS直接返回用户名
	return currentUser.Username, nil
}

// initMachineFixedUUID 初始化机器固定UUID（基于物理网卡MAC，作为唯一查询标识）
func initMachineFixedUUID() {
	// 获取物理网卡MAC地址
	macAddr := getPhysicalNicMAC()
	if macAddr == "" {
		// 兜底：若获取不到MAC，使用固定默认值（避免空值，仍保证唯一性）
		machineFixedUUID = "00000000-0000-0000-0000-000000000000"
		fmt.Println("【警告】未获取到物理网卡MAC，使用默认UUID（唯一标识）：", machineFixedUUID)
		return
	}

	// 基于MAC地址生成固定UUID（MD5哈希后转换为UUID格式，保证唯一性）
	hash := md5.Sum([]byte(macAddr))
	uuidStr := fmt.Sprintf("%x-%x-%x-%x-%x",
		hash[0:4],
		hash[4:6],
		hash[6:8],
		hash[8:10],
		hash[10:16],
	)
	machineFixedUUID = uuidStr
	fmt.Println("【初始化】机器唯一UUID（查询标识）：", machineFixedUUID)
}

// getPhysicalNicMAC 获取物理网卡的MAC地址（排除虚拟网卡）
func getPhysicalNicMAC() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		fmt.Printf("【错误】获取网卡列表失败：%v\n", err)
		return ""
	}

	// 遍历所有网卡，筛选物理网卡
	for _, iface := range ifaces {
		// 基础筛选：UP状态、非回环、有MAC地址
		if iface.Flags&net.FlagUp == 0 ||
			iface.Flags&net.FlagLoopback != 0 ||
			iface.HardwareAddr.String() == "" {
			continue
		}

		nicName := strings.ToLower(iface.Name)
		// 排除所有虚拟网卡
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

		// 优先返回有线/无线物理网卡MAC
		if strings.Contains(nicName, "ethernet") ||
			strings.Contains(nicName, "wlan") ||
			strings.Contains(nicName, "wi-fi") ||
			strings.Contains(nicName, "lan") {
			fmt.Printf("【调试】找到物理网卡：%s，MAC：%s\n", iface.Name, iface.HardwareAddr.String())
			return iface.HardwareAddr.String()
		}
	}

	// 兜底：返回第一个符合基础条件的物理网卡MAC
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp != 0 &&
			iface.Flags&net.FlagLoopback == 0 &&
			iface.HardwareAddr.String() != "" {
			fmt.Printf("【调试】兜底物理网卡：%s，MAC：%s\n", iface.Name, iface.HardwareAddr.String())
			return iface.HardwareAddr.String()
		}
	}

	fmt.Println("【警告】未找到任何物理网卡MAC")
	return ""
}

// getActivePhysicalNicInfo 获取正在使用的物理网卡完整信息（IP+网关+子网掩码）
func getActivePhysicalNicInfo() ([]NetworkInfo, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("获取网卡列表失败：%w", err)
	}

	var networkInfos []NetworkInfo

	for _, iface := range ifaces {
		// 基础筛选：UP状态、非回环、有MAC
		if iface.Flags&net.FlagUp == 0 ||
			iface.Flags&net.FlagLoopback != 0 ||
			iface.HardwareAddr.String() == "" {
			continue
		}

		nicName := strings.ToLower(iface.Name)
		// 排除虚拟网卡
		if strings.Contains(nicName, "docker") ||
			strings.Contains(nicName, "vmware") ||
			strings.Contains(nicName, "virtual") ||
			strings.Contains(nicName, "vpn") ||
			strings.Contains(nicName, "hyper-v") ||
			strings.Contains(nicName, "tun") ||
			strings.Contains(nicName, "tap") ||
			strings.Contains(nicName, "pppoe") ||
			strings.Contains(nicName, "bridge") ||
			strings.Contains(nicName, "nat") {
			continue
		}

		// 获取当前网卡的所有地址
		addrs, err := iface.Addrs()
		if err != nil {
			fmt.Printf("【调试】网卡%s获取地址失败：%v\n", iface.Name, err)
			continue
		}

		// 获取网关和子网掩码（Windows下通过路由表获取）
		gateway, subnetMask := getGatewayAndSubnet(iface.Name)

		// 遍历地址，筛选私有IPv4
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			// 仅保留IPv4、非回环、私有地址
			ip := ipNet.IP.To4()
			if ip == nil || ip.IsLoopback() || !isPrivateIPv4(ip) {
				continue
			}

			ipStr := ip.String()
			fmt.Printf("【调试】物理网卡%s的有效IPv4：%s\n", iface.Name, ipStr)

			networkInfos = append(networkInfos, NetworkInfo{
				InterfaceName: iface.Name,
				IPAddress:     ipStr,
				Gateway:       gateway,
				SubnetMask:    subnetMask,
			})
			break // 每个网卡只取第一个有效IPv4
		}
	}

	return networkInfos, nil
}

// getGatewayAndSubnet 获取指定网卡的网关和子网掩码（适配Windows）
func getGatewayAndSubnet(ifaceName string) (string, string) {
	// Windows下执行route print获取网关，ipconfig获取子网掩码
	// 这里简化实现，实际可通过exec调用系统命令解析，此处返回空（如需完整功能可扩展）
	return "", ""
}

// isPrivateIPv4 判断是否为私有内网IPv4
func isPrivateIPv4(ip net.IP) bool {
	if ip == nil {
		return false
	}
	// 10.0.0.0/8
	if ip[0] == 10 {
		return true
	}
	// 172.16.0.0/12
	if ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31 {
		return true
	}
	// 192.168.0.0/16
	if ip[0] == 192 && ip[1] == 168 {
		return true
	}
	// 169.254.0.0/16（本地链路地址）
	if ip[0] == 169 && ip[1] == 254 {
		return true
	}
	return false
}

// reportToWorkers 上报核心信息到指定地址（适配Workers的API Key验证）
func reportToWorkers(data ReportData) error {
	// 1. 转换为JSON格式
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("JSON序列化失败：%w", err)
	}

	// 2. 创建HTTP客户端（设置超时）
	client := &http.Client{
		Timeout: Timeout,
	}

	// 3. 发送POST请求到指定地址
	req, err := http.NewRequest("POST", WorkersURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("创建请求失败：%w", err)
	}

	// 设置请求头（包含API Key，与Workers保持一致）
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("X-API-Key", APIKey) // 必须：与Workers的API_KEY匹配

	// 4. 执行请求
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("发送请求失败：%w", err)
	}
	defer resp.Body.Close()

	// 5. 解析响应（兼容Workers的JSON格式）
	var respData map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&respData); err != nil {
		return fmt.Errorf("解析响应失败：%w", err)
	}

	// 6. 检查业务是否成功
	if success, ok := respData["success"].(bool); ok && !success {
		if errMsg, ok := respData["error"].(string); ok {
			return fmt.Errorf("Workers业务错误：%s", errMsg)
		}
		return fmt.Errorf("Workers返回未知错误，响应：%v", respData)
	}

	return nil
}