module ip-monitor

go 1.21

// 注：代码仅依赖Go标准库，无任何第三方依赖
// 以下为Go标准库的间接依赖（执行go mod tidy会自动生成）
require (
	golang.org/x/net v0.23.0
	golang.org/x/sys v0.19.0
	golang.org/x/text v0.14.0
)