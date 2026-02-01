package main

import (
	"fmt"
	"net"
	"time"

	"github.com/google/uuid"
)

func main() {
	// 1. 生成UUID（保留原功能）
	appID := uuid.New().String()
	fmt.Println("==================== IP监控工具 ====================")
	fmt.Printf("App唯一标识（UUID）：%s\n", appID)
	fmt.Printf("检测时间：%s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Println("----------------------------------------------------")

	// 2. 获取正在使用的本地私有IPv4地址
	localIPs, err := getActiveLocalIPv4()
	if err != nil {
		fmt.Printf("获取本地IP失败：%v\n", err)
	} else if len(localIPs) == 0 {
		fmt.Println("未检测到正在使用的本地私有IPv4地址（仅回环/公网/禁用网卡）")
	} else {
		fmt.Println("正在使用的本地私有IPv4地址：")
		for i, ip := range localIPs {
			fmt.Printf("  %d. %s\n", i+1, ip)
		}
	}
	fmt.Println("====================================================")

	// 3. 暂停程序（控制台窗口不立即关闭，方便查看结果）
	fmt.Println("\n按任意键退出...")
	var input string
	fmt.Scanln(&input)
}

// getActiveLocalIPv4 获取正在使用（UP状态）的本地私有IPv4地址
// 私有IP范围：
// - 10.0.0.0/8        (10.x.x.x)
// - 172.16.0.0/12     (172.16.x.x ~ 172.31.x.x)
// - 192.168.0.0/16    (192.168.x.x)
func getActiveLocalIPv4() ([]string, error) {
	// 存储有效IP地址
	var activeIPs []string

	// 1. 获取所有网卡信息
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("获取网卡列表失败：%w", err)
	}

	// 2. 遍历每个网卡，筛选有效条件
	for _, iface := range interfaces {
		// 跳过：网卡状态非UP、回环网卡
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		// 3. 获取当前网卡绑定的所有地址
		addrs, err := iface.Addrs()
		if err != nil {
			fmt.Printf("警告：获取网卡[%s]地址失败：%v\n", iface.Name, err)
			continue
		}

		// 4. 筛选IPv4 + 私有内网IP
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			// 跳过非IPv4、无效IP
			if !ok || ipNet.IP.IsLoopback() || ipNet.IP.To4() == nil {
				continue
			}

			// 检查是否为私有内网IP
			if isPrivateIPv4(ipNet.IP) {
				activeIPs = append(activeIPs, fmt.Sprintf("%s (网卡：%s)", ipNet.IP.String(), iface.Name))
			}
		}
	}

	return activeIPs, nil
}

// isPrivateIPv4 判断IP是否为私有内网IPv4
func isPrivateIPv4(ip net.IP) bool {
	// 10.0.0.0/8
	if ip[0] == 10 {
		return true
	}
	// 172.16.0.0/12 (172.16.x.x ~ 172.31.x.x)
	if ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31 {
		return true
	}
	// 192.168.0.0/16
	if ip[0] == 192 && ip[1] == 168 {
		return true
	}
	return false
}