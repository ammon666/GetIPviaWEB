package main

import (
	"fmt"
	"net"
	"time"

	"github.com/google/uuid"
	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
)

// 全局窗口变量
var mainWindow *walk.MainWindow

func main() {
	// 创建UUID示例（验证uuid依赖）
	appID := uuid.New().String()

	// 获取本机IP示例
	localIP := getLocalIP()

	// 构建Windows GUI窗口（验证walk依赖）
	if err := MainWindow{
		Title:   fmt.Sprintf("IP Monitor - %s", appID),
		Size:    Size{Width: 400, Height: 300},
		Layout:  VBox{},
		Children: []Widget{
			TextEdit{
				ReadOnly: true,
				Text:     fmt.Sprintf("本机IP地址：%s\n检测时间：%s\nAppID：%s", localIP, time.Now().Format("2006-01-02 15:04:05"), appID),
			},
		},
	}.Create(&mainWindow); err != nil {
		walk.MsgBox(nil, "错误", fmt.Sprintf("启动失败：%v", err), walk.MsgBoxIconError)
		return
	}

	// 运行窗口
	mainWindow.Run()
}

// getLocalIP 获取本机非回环IP地址
func getLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "获取失败：" + err.Error()
	}

	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if ok && !ipNet.IP.IsLoopback() && ipNet.IP.To4() != nil {
			return ipNet.IP.String()
		}
	}

	return "未检测到有效IP"
}