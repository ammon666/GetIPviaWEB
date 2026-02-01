module ip-monitor

go 1.21

// Windows专用：仅保留必要的标准库间接依赖
require (
	golang.org/x/net v0.23.0
	golang.org/x/sys v0.19.0
)