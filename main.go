package main

import (
	"bytes"
	"crypto/md5"
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

// 从环境变量读取API Key（优先环境变量，本地开发可设默认值）
func getAPIKey() string {
	apiKey := os.Getenv("WORKERS_API_KEY") // 对应GitHub环境变量名
	if apiKey == "" {
		// 本地开发兜底值（也可直接panic强制要求设置环境变量）
		return "default-dev-api-key" // 生产环境需确保环境变量已配置
	}
	return apiKey
}

// 全局变量：存储机器固定UUID（基于物理网卡MAC，作为唯一查询标识）
var machineFixedUUID string

// 以下结构体/函数保持不变，仅修改reportToWorkers中API Key的使用方式
// ...（省略原有结构体定义，与原代码一致）...

func main() {
	// 原有逻辑完全不变...
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

	// 原有暂停逻辑...
}

// ...（省略原有工具函数，与原代码一致）...

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