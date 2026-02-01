package main

import (
	"crypto/md5"
	"fmt"
	"net"
	"os/user"
	"strings"
	"time"
)

// 全局变量：存储机器固定UUID（基于物理网卡MAC）
var machineFixedUUID string

func main() {
	// 1. 初始化机器固定UUID
	initMachineFixedUUID()

	// 2. 获取当前登录用户名（仅保留纯用户名，去掉计算机名）
	username, err := getCurrentUsername()
	if err != nil {
		username = fmt.Sprintf("获取失败：%v", err)
	}

	// 3. 输出核心信息
	fmt.Println("==================== IP监控工具 ====================")
	fmt.Printf("当前登录用户名：%s\n", username)
	fmt.Printf("机器唯一标识（UUID）：%s\n", machineFixedUUID)
	fmt.Printf("检测时间：%s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Println("----------------------------------------------------")

	// 4. 获取正在使用的物理网卡私有IPv4地址
	localIP, err := getActivePhysicalNicIPv4()
	if err != nil {
		fmt.Printf("获取物理网卡IP失败：%v\n", err)
	} else if localIP == "" {
		fmt.Println("未检测到正在使用的物理网卡IPv4地址")
	} else {
		fmt.Printf("正在使用的物理网卡IPv4地址：%s\n", localIP)
	}
	fmt.Println("====================================================")

	// 5. 暂停程序（控制台窗口不立即关闭）
	fmt.Println("\n按任意键退出...")
	var input string
	fmt.Scanln(&input)
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

// initMachineFixedUUID 初始化机器固定UUID（基于物理网卡MAC）
func initMachineFixedUUID() {
	// 获取物理网卡MAC地址
	macAddr := getPhysicalNicMAC()
	if macAddr == "" {
		// 兜底：若获取不到MAC，使用固定默认值（避免空值）
		machineFixedUUID = "00000000-0000-0000-0000-000000000000"
		return
	}

	// 基于MAC地址生成固定UUID（MD5哈希后转换为UUID格式）
	hash := md5.Sum([]byte(macAddr))
	uuidStr := fmt.Sprintf("%x-%x-%x-%x-%x",
		hash[0:4],
		hash[4:6],
		hash[6:8],
		hash[8:10],
		hash[10:16],
	)
	machineFixedUUID = uuidStr
}

// getPhysicalNicMAC 获取物理网卡的MAC地址（排除虚拟网卡）
func getPhysicalNicMAC() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}

	for _, iface := range ifaces {
		// 筛选条件：物理网卡（UP状态、非回环、非虚拟、有MAC）
		if iface.Flags&net.FlagUp == 0 ||          // 网卡未启用
			iface.Flags&net.FlagLoopback != 0 || // 回环网卡
			iface.HardwareAddr.String() == "" {  // 无MAC地址（虚拟网卡）
			continue
		}

		// 排除虚拟网卡（关键词匹配）
		nicName := strings.ToLower(iface.Name)
		if strings.Contains(nicName, "docker") ||
			strings.Contains(nicName, "vmware") ||
			strings.Contains(nicName, "virtual") ||
			strings.Contains(nicName, "vpn") ||
			strings.Contains(nicName, "hyper-v") ||
			strings.Contains(nicName, "tun") ||
			strings.Contains(nicName, "tap") {
			continue
		}

		// 优先返回有线/无线物理网卡MAC
		if strings.Contains(nicName, "ethernet") || strings.Contains(nicName, "wlan") || strings.Contains(nicName, "wi-fi") {
			return iface.HardwareAddr.String()
		}
	}

	// 若未匹配到有线/无线，返回第一个符合条件的物理网卡MAC
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 && iface.HardwareAddr.String() != "" {
			return iface.HardwareAddr.String()
		}
	}

	return ""
}

// getActivePhysicalNicIPv4 获取正在使用的物理网卡私有IPv4地址
// 仅保留：有线(Ethernet)/无线(WLAN)物理网卡、UP状态、私有IPv4、非回环
func getActivePhysicalNicIPv4() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("获取网卡列表失败：%w", err)
	}

	// 优先存储有线网卡IP，其次无线
	var ethernetIP, wlanIP string

	for _, iface := range ifaces {
		// 基础筛选：UP状态、非回环、物理网卡（排除虚拟）
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		// 排除虚拟网卡
		nicName := strings.ToLower(iface.Name)
		if strings.Contains(nicName, "docker") ||
			strings.Contains(nicName, "vmware") ||
			strings.Contains(nicName, "virtual") ||
			strings.Contains(nicName, "vpn") ||
			strings.Contains(nicName, "hyper-v") {
			continue
		}

		// 获取网卡地址
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		// 筛选私有IPv4
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok || ipNet.IP.IsLoopback() || ipNet.IP.To4() == nil {
				continue
			}

			// 确认是私有IPv4
			if isPrivateIPv4(ipNet.IP) {
				// 区分有线/无线网卡，优先选有线
				if strings.Contains(nicName, "ethernet") {
					ethernetIP = ipNet.IP.String()
				} else if strings.Contains(nicName, "wlan") || strings.Contains(nicName, "wi-fi") {
					wlanIP = ipNet.IP.String()
				}
			}
		}
	}

	// 优先返回有线网卡IP，无则返回无线
	if ethernetIP != "" {
		return ethernetIP, nil
	}
	if wlanIP != "" {
		return wlanIP, nil
	}

	// 无符合条件的IP
	return "", nil
}

// isPrivateIPv4 判断是否为私有内网IPv4
func isPrivateIPv4(ip net.IP) bool {
	if ip[0] == 10 {
		return true
	}
	if ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31 {
		return true
	}
	if ip[0] == 192 && ip[1] == 168 {
		return true
	}
	return false
}