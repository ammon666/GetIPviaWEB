module ip-monitor

go 1.21

// 仅保留UUID依赖，彻底移除walk相关依赖
require github.com/google/uuid v1.6.0