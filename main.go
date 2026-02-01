package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
)

const (
	ConfigFileName = "config.json"
	LogFileName    = "monitor.log"
	CheckInterval  = 1 * time.Hour
	APIEndpoint    = "https://getip.ammon.de5.net/api/report" // 修改为你的CF Workers地址
	APIKey         = "your-secret-api-key"                        // 修改为你的API密钥
)

type Config struct {
	UUID string `json:"uuid"`
}

type NetworkInfo struct {
	InterfaceName string `json:"interface_name"`
	IPAddress     string `json:"ip_address"`
	Gateway       string `json:"gateway"`
	SubnetMask    string `json:"subnet_mask"`
}

type ReportData struct {
	UUID        string        `json:"uuid"`
	Username    string        `json:"username"`
	Networks    []NetworkInfo `json:"networks"`
	Timestamp   string        `json:"timestamp"`
	Hostname    string        `json:"hostname"`
}

var (
	logTextEdit *walk.TextEdit
	statusLabel *walk.Label
	mainWindow  *walk.MainWindow
)

// 日志记录器
func logMessage(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	logLine := fmt.Sprintf("[%s] %s\n", timestamp, msg)
	
	// 打印到控制台
	fmt.Print(logLine)
	
	// 写入日志文件
	logFile := filepath.Join(getConfigDir(), LogFileName)
	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		f.WriteString(logLine)
		f.Close()
	}
	
	// 更新GUI日志窗口
	if logTextEdit != nil {
		logTextEdit.AppendText(logLine)
	}
}

// 更新状态栏
func updateStatus(status string) {
	if statusLabel != nil {
		statusLabel.SetText(status)
	}
}

// 获取配置目录
func getConfigDir() string {
	appData := os.Getenv("APPDATA")
	if appData == "" {
		appData = os.Getenv("USERPROFILE")
	}
	configDir := filepath.Join(appData, "IPMonitor")
	os.MkdirAll(configDir, 0755)
	return configDir
}

// 加载或生成UUID
func loadOrGenerateUUID() (string, error) {
	configPath := filepath.Join(getConfigDir(), ConfigFileName)
	
	// 尝试读取现有配置
	data, err := os.ReadFile(configPath)
	if err == nil {
		var config Config
		if err := json.Unmarshal(data, &config); err == nil && config.UUID != "" {
			logMessage("已加载现有UUID: %s", config.UUID)
			return config.UUID, nil
		}
	}
	
	// 生成新UUID
	newUUID := uuid.New().String()
	config := Config{UUID: newUUID}
	
	configData, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return "", err
	}
	
	err = os.WriteFile(configPath, configData, 0644)
	if err != nil {
		return "", err
	}
	
	logMessage("生成新UUID: %s", newUUID)
	return newUUID, nil
}

// 获取当前登录用户名
func getUsername() (string, error) {
	currentUser, err := user.Current()
	if err != nil {
		return "", err
	}
	return currentUser.Username, nil
}

// 获取主机名
func getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "Unknown"
	}
	return hostname
}

// 获取默认网关
func getDefaultGateway(iface *net.Interface) string {
	// Windows下获取网关需要执行系统命令或读取路由表
	// 这里使用简化方法：从IP地址推导网关（通常是.1）
	addrs, err := iface.Addrs()
	if err != nil {
		return ""
	}
	
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				// 将最后一个八位组设为1作为网关
				ip := ipnet.IP.To4()
				gateway := fmt.Sprintf("%d.%d.%d.1", ip[0], ip[1], ip[2])
				return gateway
			}
		}
	}
	return ""
}

// 获取网络信息
func getNetworkInfo() ([]NetworkInfo, error) {
	var networks []NetworkInfo
	
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	
	for _, iface := range interfaces {
		// 跳过未启用的接口
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		
		// 跳过回环接口
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() != nil {
					gateway := getDefaultGateway(&iface)
					networks = append(networks, NetworkInfo{
						InterfaceName: iface.Name,
						IPAddress:     ipnet.IP.String(),
						Gateway:       gateway,
						SubnetMask:    fmt.Sprintf("%d.%d.%d.%d", ipnet.Mask[0], ipnet.Mask[1], ipnet.Mask[2], ipnet.Mask[3]),
					})
				}
			}
		}
	}
	
	if len(networks) == 0 {
		return nil, fmt.Errorf("未找到有效的IPv4网络接口")
	}
	
	return networks, nil
}

// 发送数据到Cloudflare
func sendToCloudflare(data ReportData) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}
	
	req, err := http.NewRequest("POST", APIEndpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", APIKey)
	
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	body, _ := io.ReadAll(resp.Body)
	
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("服务器返回错误: %d - %s", resp.StatusCode, string(body))
	}
	
	logMessage("数据已成功发送到Cloudflare")
	return nil
}

// 收集并发送数据
func collectAndSend(deviceUUID string) error {
	updateStatus("正在收集网络信息...")
	
	username, err := getUsername()
	if err != nil {
		logMessage("获取用户名失败: %v", err)
		username = "Unknown"
	}
	
	networks, err := getNetworkInfo()
	if err != nil {
		return fmt.Errorf("获取网络信息失败: %v", err)
	}
	
	hostname := getHostname()
	
	data := ReportData{
		UUID:      deviceUUID,
		Username:  username,
		Networks:  networks,
		Timestamp: time.Now().Format(time.RFC3339),
		Hostname:  hostname,
	}
	
	logMessage("收集到的信息:")
	logMessage("  UUID: %s", data.UUID)
	logMessage("  用户名: %s", data.Username)
	logMessage("  主机名: %s", data.Hostname)
	for i, net := range networks {
		logMessage("  网络接口 %d:", i+1)
		logMessage("    名称: %s", net.InterfaceName)
		logMessage("    IP地址: %s", net.IPAddress)
		logMessage("    网关: %s", net.Gateway)
		logMessage("    子网掩码: %s", net.SubnetMask)
	}
	
	updateStatus("正在发送数据到Cloudflare...")
	err = sendToCloudflare(data)
	if err != nil {
		updateStatus("发送失败: " + err.Error())
		return err
	}
	
	updateStatus("上次更新: " + time.Now().Format("2006-01-02 15:04:05"))
	return nil
}

// 监控主循环
func monitorLoop(deviceUUID string) {
	var lastNetworks []NetworkInfo
	
	// 立即执行一次
	logMessage("========== 程序启动，执行初始数据收集 ==========")
	if err := collectAndSend(deviceUUID); err != nil {
		logMessage("初始数据发送失败: %v", err)
	}
	lastNetworks, _ = getNetworkInfo()
	
	ticker := time.NewTicker(CheckInterval)
	defer ticker.Stop()
	
	checkTicker := time.NewTicker(5 * time.Minute)
	defer checkTicker.Stop()
	
	for {
		select {
		case <-ticker.C:
			logMessage("========== 定时检查（每小时） ==========")
			if err := collectAndSend(deviceUUID); err != nil {
				logMessage("定时发送失败: %v", err)
			}
			lastNetworks, _ = getNetworkInfo()
			
		case <-checkTicker.C:
			currentNetworks, err := getNetworkInfo()
			if err != nil {
				continue
			}
			
			// 检查IP是否变化
			if !networksEqual(lastNetworks, currentNetworks) {
				logMessage("========== 检测到IP地址变化 ==========")
				if err := collectAndSend(deviceUUID); err != nil {
					logMessage("IP变化后发送失败: %v", err)
				}
				lastNetworks = currentNetworks
			}
		}
	}
}

// 比较两个网络信息列表是否相同
func networksEqual(a, b []NetworkInfo) bool {
	if len(a) != len(b) {
		return false
	}
	
	for i := range a {
		if a[i].IPAddress != b[i].IPAddress || a[i].Gateway != b[i].Gateway {
			return false
		}
	}
	
	return true
}

// 创建GUI窗口
func createGUI(deviceUUID string) {
	var err error
	
	mainWindow, err = walk.NewMainWindow()
	if err != nil {
		logMessage("创建窗口失败: %v", err)
		return
	}
	
	err = MainWindow{
		AssignTo: &mainWindow,
		Title:    "IP地址监控程序 - 开发版",
		MinSize:  Size{Width: 800, Height: 600},
		Layout:   VBox{},
		Children: []Widget{
			Label{
				AssignTo: &statusLabel,
				Text:     "初始化中...",
				Font:     Font{PointSize: 10, Bold: true},
			},
			HSeparator{},
			Label{
				Text: "UUID: " + deviceUUID,
				Font: Font{PointSize: 9},
			},
			Label{
				Text: "查询地址: " + strings.Replace(APIEndpoint, "/api/report", "/view/"+deviceUUID, 1),
				Font: Font{PointSize: 9},
			},
			HSeparator{},
			Label{
				Text: "运行日志:",
			},
			TextEdit{
				AssignTo: &logTextEdit,
				ReadOnly: true,
				VScroll:  true,
			},
		},
	}.Create()
	
	if err != nil {
		logMessage("创建窗口失败: %v", err)
		return
	}
	
	// 设置窗口关闭事件
	mainWindow.Closing().Attach(func(canceled *bool, reason walk.CloseReason) {
		*canceled = true
		mainWindow.Hide()
	})
	
	// 启动监控循环
	go monitorLoop(deviceUUID)
	
	mainWindow.Run()
}

func main() {
	logMessage("========== IP地址监控程序启动 ==========")
	logMessage("配置目录: %s", getConfigDir())
	
	// 加载或生成UUID
	deviceUUID, err := loadOrGenerateUUID()
	if err != nil {
		logMessage("UUID处理失败: %v", err)
		fmt.Printf("按回车键退出...")
		fmt.Scanln()
		return
	}
	
	// 创建GUI
	createGUI(deviceUUID)
}
