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

// 配置项：修正后的正确上报地址（删除了错误的POST%20）
const (
	WorkersURL = "https://getip.ammon.de5.net/api/report" // 正确的上报地址
	Timeout    = 5 * time.Second                         // 上报超时时间
)

// ReportData 上报数据结构体（补全缺失的结构体定义）
type ReportData struct {
	UUID      string                 `json:"uuid"`
	Username  string                 `json:"username"`
	Hostname  string                 `json:"hostname"`
	Networks  []map[string]string    `json:"networks"`
	Timestamp string                 `json:"timestamp"`
}

// 从环境变量读取API Key（优先环境变量，本地开发可设默认值）
func getAPIKey() string {
	apiKey := os.Getenv("WORKERS_API_KEY") // 对应GitHub环境变量名
	if apiKey == "" {
		// 本地开发兜底值（生产环境需确保环境变量已配置）
		return "default-dev-api-key"
	}
	return apiKey
}

// 全局变量：存储机器固定UUID（基于物理网卡MAC，作为唯一查询标识）
var machineFixedUUID string

// getMachineUUID 生成基于MAC地址的机器唯一UUID（补全net包的使用逻辑）
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
	// 使用第一个有效MAC生成UUID（此处简化，也可结合md5）
	machineFixedUUID = strings.ReplaceAll(macs[0], ":", "")
	return machineFixedUUID
}

// getCurrentUsername 获取当前登录用户名（补全os/user包使用逻辑）
func getCurrentUsername() string {
	u, err := user.Current()
	if err != nil {
		return "unknown-user"
	}
	return u.Username
}

// getHostname 获取主机名
func getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown-host"
	}
	return hostname
}

// getNetworkInfos 获取网络接口信息（补全net/strings包使用逻辑）
func getNetworkInfos() []map[string]string {
	var infos []map[string]string
	interfaces, err := net.Interfaces()
	if err != nil {
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
				"name":    iface.Name,
				"mac":     iface.HardwareAddr.String(),
				"ip":      ip,
				"status":  fmt.Sprintf("%v", iface.Flags),
			})
		}
	}
	return infos
}

func main() {
	// 初始化核心变量（补全缺失的变量定义）
	machineFixedUUID = getMachineUUID()
	username := getCurrentUsername()
	hostname := getHostname()
	networkInfos := getNetworkInfos()

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

	// 暂停（可选，本地运行时保留）
	fmt.Println("\n按任意键退出...")
	var input string
	fmt.Scanln(&input)
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

	// 设置请求头（从环境变量读取API Key）
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("X-API-Key", getAPIKey()) // 替换硬编码的APIKey

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