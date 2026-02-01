package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/user"
	"strings"
	"time"
)

// 配置项
const (
	WorkersURL = "https://getip.ammon.de5.net/api/report" // 上报地址
	Timeout    = 5 * time.Second                         // 上报超时时间
)

// ReportData 上报数据结构体
type ReportData struct {
	UUID      string              `json:"uuid"`
	Username  string              `json:"username"`
	Hostname  string              `json:"hostname"`
	Networks  []map[string]string `json:"networks"`
	Timestamp string              `json:"timestamp"`
}

// 全局变量：存储机器唯一UUID
var machineFixedUUID string

// getAPIKey 从环境变量读取API Key（适配GitHub Actions Secrets）
func getAPIKey() string {
	apiKey := os.Getenv("WORKERS_API_KEY") // 与Actions中环境变量名一致
	if apiKey == "" {
		fmt.Println("警告：未读取到WORKERS_API_KEY环境变量，使用本地测试值")
		return "local-test-key" // 本地开发兜底，生产环境由Actions注入
	}
	return apiKey
}

// getMachineUUID 基于网卡MAC生成机器唯一UUID
func getMachineUUID() string {
	if machineFixedUUID != "" {
		return machineFixedUUID
	}

	interfaces, err := net.Interfaces()
	if err != nil {
		panic(fmt.Sprintf("获取网卡信息失败：%v", err))
	}

	var macs []string
	for _, iface := range interfaces {
		// 过滤启用的非回环网卡
		if iface.Flags&net.FlagUp != 0 && !strings.HasPrefix(iface.Name, "lo") {
			mac := iface.HardwareAddr.String()
			if mac != "" {
				macs = append(macs, mac)
			}
		}
	}

	if len(macs) == 0 {
		panic("未找到有效物理网卡MAC地址")
	}

	// 用第一个有效MAC生成UUID（去冒号）
	machineFixedUUID = strings.ReplaceAll(macs[0], ":", "")
	return machineFixedUUID
}

// getCurrentUsername 获取当前登录用户名
func getCurrentUsername() string {
	u, err := user.Current()
	if err != nil {
		fmt.Printf("获取用户名失败：%v\n", err)
		return "unknown-user"
	}
	return u.Username
}

// getHostname 获取主机名
func getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		fmt.Printf("获取主机名失败：%v\n", err)
		return "unknown-host"
	}
	return hostname
}

// getNetworkInfos 获取所有网络接口信息
func getNetworkInfos() []map[string]string {
	var infos []map[string]string

	interfaces, err := net.Interfaces()
	if err != nil {
		fmt.Printf("获取网络接口失败：%v\n", err)
		return infos
	}

	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ip := strings.Split(addr.String(), "/")[0]
			infos = append(infos, map[string]string{
				"name":   iface.Name,
				"mac":    iface.HardwareAddr.String(),
				"ip":     ip,
				"status": fmt.Sprintf("%v", iface.Flags),
			})
		}
	}

	return infos
}

// reportToWorkers 上报数据到Workers接口
func reportToWorkers(data ReportData) error {
	// 序列化JSON
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("JSON序列化失败：%w", err)
	}

	// 创建HTTP客户端
	client := &http.Client{Timeout: Timeout}

	// 构建POST请求
	req, err := http.NewRequest("POST", WorkersURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("创建请求失败：%w", err)
	}

	// 设置请求头（含API Key）
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("X-API-Key", getAPIKey())

	// 发送请求
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("发送请求失败：%w", err)
	}
	defer resp.Body.Close()

	// 解析响应
	var respData map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&respData); err != nil {
		return fmt.Errorf("解析响应失败：%w", err)
	}

	// 检查业务状态
	if success, ok := respData["success"].(bool); ok && !success {
		errMsg := "未知错误"
		if msg, ok := respData["error"].(string); ok {
			errMsg = msg
		}
		return fmt.Errorf("Workers业务错误：%s", errMsg)
	}

	return nil
}

func main() {
	// 初始化核心信息
	machineFixedUUID = getMachineUUID()
	username := getCurrentUsername()
	hostname := getHostname()
	networkInfos := getNetworkInfos()

	// 构造上报数据
	reportData := ReportData{
		UUID:      machineFixedUUID,
		Username:  username,
		Hostname:  hostname,
		Networks:  networkInfos,
		Timestamp: time.Now().Format("2006-01-02 15:04:05"),
	}

	// 打印调试信息
	fmt.Println("=== 采集信息 ===")
	fmt.Printf("UUID：%s\n", machineFixedUUID)
	fmt.Printf("用户名：%s\n", username)
	fmt.Printf("主机名：%s\n", hostname)
	fmt.Printf("网络接口数：%d\n", len(networkInfos))
	fmt.Println("=================")

	// 执行上报
	if err := reportToWorkers(reportData); err != nil {
		fmt.Printf("\n【上报失败】%v\n", err)
	} else {
		fmt.Println("\n【上报成功】数据已发送至Workers，UUID：", machineFixedUUID)
	}

	// 本地运行时暂停
	fmt.Println("\n按任意键退出...")
	var input string
	fmt.Scanln(&input)
}