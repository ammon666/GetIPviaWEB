module ip-monitor

go 1.21

require (
	github.com/google/uuid v1.6.0
	github.com/lxn/walk v0.0.0-20220712152122-205f7c9b459c
	github.com/lxn/win v0.0.0-20220712152122-205f7c9b459c // indirect
)

// 核心修复：将原lxn/walk/win替换为社区维护的镜像仓库，解决版本无法识别问题
replace github.com/lxn/walk => github.com/rocket049/walk v0.0.0-20220712152122-205f7c9b459c
replace github.com/lxn/win => github.com/rocket049/win v0.0.0-20220712152122-205f7c9b459c