package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

// ========== 全局配置（核心修改：APIKey改为编译时注入） ==========
var (
	// 日志&标记文件路径（确保Local System账户可访问）
	logPath        = filepath.Join(os.Getenv("ProgramData"), "GetIPviaWEB", "service.log")
	firstRunFlag   = filepath.Join(os.Getenv("ProgramData"), "GetIPviaWEB", "first_run_done") // 首次启动标记文件
	// 服务配置（修复：移除mgr.Config中不存在的Name字段）
	serviceConfig = &mgr.Config{
		DisplayName: "IP监控自动上报服务",        // 服务显示名称
		Description: "开机自动运行，仅首次启动弹浏览器，定时上报IP信息", // 服务描述
	}

	// Windows API常量（修复：CREATE_NO_WINDOW改为uint32类型）
	SIGBREAK        = syscall.Signal(21)
	CREATE_NO_WINDOW = uint32(0x08000000) // 修正为uint32类型
	SW_HIDE         = 0                   // uintptr类型

	// 业务变量（APIKey通过-ldflags编译注入，无默认值）
	APIKey          string // 核心修改：不再硬编码，编译时注入
	WorkersURL      = "https://getip.ammon.de5.net/api/report"
	Timeout         = 5 * time.Second
	DefaultInterval = 1 * time.Minute
	ViewURLTemplate = "https://getip.ammon.de5.net/view/%s"

	// 全局变量（修复：debug.Logger改为eventlog.Log）
	machineFixedUUID string
	logger           *eventlog.Log // 修正日志类型
	reportInterval   time.Duration  // 上报间隔
	isFirstRun       bool           // 是否是首次启动（内存标记，初始为true）
)

// init 初始化函数：校验APIKey，无值则panic（强制要求编译时注入）
func init() {
	// 创建日志目录（确保Local System有权限）
	logDir := filepath.Dir(logPath)
	if err := os.MkdirAll(logDir, 0755); err != nil {
		panic(fmt.Sprintf("创建日志目录失败：%v", err))
	}

	// 校验APIKey（编译时未注入则直接退出）
	if APIKey == "" {
		errMsg := "【致命错误】APIKey未通过-ldflags注入，请检查编译命令！"
		writeLog(errMsg)
		panic(errMsg)
	}
	writeLog(fmt.Sprintf("APIKey注入成功，长度：%d", len(APIKey)))

	// 初始化上报间隔
	reportInterval = DefaultInterval

	// 检查是否首次运行
	if _, err := os.Stat(firstRunFlag); os.IsNotExist(err) {
		isFirstRun = true
		writeLog("检测到首次运行，将启动浏览器展示IP页面")
	} else {
		isFirstRun = false
		writeLog("非首次运行，跳过浏览器启动")
	}

	// 初始化机器UUID（简化版，实际可替换为硬件信息）
	machineFixedUUID = getMachineUUID()
}

// 主函数：服务入口
func main() {
	// 初始化事件日志（修复：调整日志初始化逻辑）
	var err error
	logger, err = eventlog.Open("GetIPviaWEBService")
	if err != nil {
		writeLog(fmt.Sprintf("初始化事件日志失败：%v", err))
		return
	}
	defer logger.Close()

	// 解析命令行参数（安装/卸载/运行服务）
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "install":
			err = installService("GetIPviaWEBService") // 传入服务名称
			if err != nil {
				logger.Error(1, fmt.Sprintf("安装服务失败: %v", err))
				writeLog(fmt.Sprintf("安装服务失败: %v", err))
				return
			}
			logger.Info(1, "服务安装成功")
			writeLog("服务安装成功")
			return
		case "uninstall":
			err = removeService("GetIPviaWEBService")
			if err != nil {
				logger.Error(1, fmt.Sprintf("卸载服务失败: %v", err))
				writeLog(fmt.Sprintf("卸载服务失败: %v", err))
				return
			}
			logger.Info(1, "服务卸载成功")
			writeLog("服务卸载成功")
			return
		}
	}

	// 运行服务
	err = svc.Run("GetIPviaWEBService", &ipReportService{})
	if err != nil {
		logger.Error(1, fmt.Sprintf("运行服务失败: %v", err))
		writeLog(fmt.Sprintf("运行服务失败: %v", err))
		return
	}
}

// ipReportService 实现svc.Handler接口
type ipReportService struct{}

// Execute 服务核心执行逻辑
func (s *ipReportService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPauseAndContinue
	changes <- svc.Status{State: svc.StartPending}
	writeLog("服务启动中...")

	// 首次运行启动浏览器（仅第一次打开时触发）
	if isFirstRun {
		go func() {
			time.Sleep(2 * time.Second) // 延迟启动，避免服务未就绪
			openBrowser(fmt.Sprintf(ViewURLTemplate, machineFixedUUID))
			// 标记首次运行完成（创建标记文件，后续不再弹浏览器）
			if err := ioutil.WriteFile(firstRunFlag, []byte(time.Now().String()), 0644); err != nil {
				writeLog(fmt.Sprintf("写入首次运行标记文件失败：%v", err))
			}
		}()
	}

	// ========== 核心修改：服务启动时立即上报一次IP（每次打开都执行） ==========
	if err := reportIP(); err != nil {
		writeLog(fmt.Sprintf("服务启动立即上报IP失败：%v", err))
		logger.Warning(1, fmt.Sprintf("服务启动立即上报IP失败：%v", err))
	} else {
		writeLog("服务启动立即上报IP成功")
	}

	// 启动定时上报协程（按间隔重复上报）
	ticker := time.NewTicker(reportInterval)
	defer ticker.Stop()

	// 服务就绪
	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}
	writeLog("服务启动成功，开始定时上报IP")

	// 服务主循环
loop:
	for {
		select {
		case <-ticker.C:
			// 定时上报IP
			if err := reportIP(); err != nil {
				writeLog(fmt.Sprintf("IP上报失败：%v", err))
				logger.Warning(1, fmt.Sprintf("IP上报失败：%v", err))
			} else {
				writeLog("IP上报成功")
			}
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				writeLog("收到停止/关机指令，服务正在退出")
				changes <- svc.Status{State: svc.StopPending}
				break loop
			case svc.Pause:
				writeLog("服务暂停")
				ticker.Stop()
				changes <- svc.Status{State: svc.Paused, Accepts: cmdsAccepted}
			case svc.Continue:
				writeLog("服务恢复运行")
				ticker.Reset(reportInterval)
				changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}
			default:
				writeLog(fmt.Sprintf("收到未知指令: %v", c))
				logger.Error(1, fmt.Sprintf("收到未知指令: %v", c))
			}
		}
	}

	// 服务退出
	changes <- svc.Status{State: svc.Stopped}
	writeLog("服务已停止")
	return
}

// reportIP 上报IP信息到服务器
func reportIP() error {
	// 获取公网IP（简化版，实际可替换为更可靠的接口）
	ip, err := getPublicIP()
	if err != nil {
		return fmt.Errorf("获取公网IP失败：%v", err)
	}

	// 构造上报数据
	payload := map[string]string{
		"api_key":   APIKey,
		"uuid":      machineFixedUUID,
		"ip":        ip,
		"timestamp": time.Now().Format(time.RFC3339),
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("序列化上报数据失败：%v", err)
	}

	// 发送HTTP请求
	client := &http.Client{Timeout: Timeout}
	req, err := http.NewRequest("POST", WorkersURL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return fmt.Errorf("创建HTTP请求失败：%v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("发送HTTP请求失败：%v", err)
	}
	defer resp.Body.Close()

	// 检查响应状态
	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("服务器返回错误状态码：%d，响应内容：%s", resp.StatusCode, string(body))
	}

	return nil
}

// getPublicIP 获取公网IP（简化实现）
func getPublicIP() (string, error) {
	client := &http.Client{Timeout: Timeout}
	resp, err := client.Get("https://api.ipify.org?format=text")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	ipBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(ipBytes), nil
}

// getMachineUUID 生成机器唯一标识（简化版）
func getMachineUUID() string {
	// 实际场景可替换为读取硬件信息（如主板序列号）
	return fmt.Sprintf("machine-%s", time.Now().UnixNano())
}

// openBrowser 打开浏览器（Windows专用）
func openBrowser(url string) {
	cmd := exec.Command("cmd", "/c", "start", "", url)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: CREATE_NO_WINDOW, // 已修正为uint32类型
	}
	if err := cmd.Start(); err != nil {
		writeLog(fmt.Sprintf("启动浏览器失败：%v", err))
	}
}

// writeLog 写入日志到文件
func writeLog(msg string) {
	logMsg := fmt.Sprintf("[%s] %s\n", time.Now().Format("2006-01-02 15:04:05"), msg)
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fmt.Printf("写入日志失败：%v，日志内容：%s\n", err, logMsg)
		return
	}
	defer f.Close()
	_, _ = f.WriteString(logMsg)
}

// installService 安装Windows服务（修复：传入服务名称参数）
func installService(serviceName string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err == nil {
		s.Close()
		return fmt.Errorf("服务%s已存在", serviceName)
	}

	exePath, err := os.Executable()
	if err != nil {
		return err
	}

	// 修复：创建服务时传入serviceName，而非在Config中设置
	s, err = m.CreateService(serviceName, exePath, *serviceConfig)
	if err != nil {
		return err
	}
	defer s.Close()

	return nil
}

// removeService 卸载Windows服务
func removeService(serviceName string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("服务%s不存在：%v", serviceName, err)
	}
	defer s.Close()

	err = s.Delete()
	if err != nil {
		return err
	}

	return nil
}