module ip-monitor

go 1.21

require (
	github.com/google/uuid v1.6.0
	github.com/lxn/walk v0.0.0-20220712152122-205f7c9b459c
)

// 重定向到社区镜像仓库，且代理可直接获取
replace github.com/lxn/walk => github.com/rocket049/walk v0.0.0-20220712152122-205f7c9b459c