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

	// 2. 获取本机非回环IPv4地址（保留原核心功能）
	localIP := getLocalIP()
	fmt.Printf("本机有效IPv4地址：%s\n", localIP)
	fmt.Println("====================================================")

	// 3. 暂停程序（控制台窗口不立即关闭，方便查看结果）
	fmt.Println("\n按任意键退出...")
	var input string
	fmt.Scanln(&input)
}

// getLocalIP 获取本机非回环IPv4地址（逻辑与原GUI版本一致）
func getLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return fmt.Sprintf("获取失败：%v", err)
	}

	// 遍历所有网卡地址，筛选非回环IPv4
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if ok && !ipNet.IP.IsLoopback() && ipNet.IP.To4() != nil {
			return ipNet.IP.String()
		}
	}

	return "未检测到有效IPv4地址（仅回环地址/无网络）"
}