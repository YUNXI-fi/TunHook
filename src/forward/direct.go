package forward

import (
	"strings"

	"tunhook/config"
)

// DirectForwarder 目标地址为本机（127.0.0.1 / 0.0.0.0 等）且目标端口与监听端口相同时使用：
// 服务本身已在监听该端口，无需再启动 TCP/UDP 转发器（避免端口冲突），直接使用本地地址即可。
// 规则仍然入库并在列表中展示（running=true），仅不产生实际监听。
type DirectForwarder struct {
	key string
}

func NewDirectForwarder(rule config.ForwardRule) *DirectForwarder {
	return &DirectForwarder{key: ruleKey(rule)}
}

func (f *DirectForwarder) Start() error   { return nil }
func (f *DirectForwarder) Stop()          {}
func (f *DirectForwarder) TXBytes() int64 { return 0 }
func (f *DirectForwarder) RXBytes() int64 { return 0 }
func (f *DirectForwarder) ConnCount() int { return 0 }
func (f *DirectForwarder) GetClients() []ClientInfo {
	return nil
}

// IsLocalDirectTarget 判断是否属于"本机直连"场景：
// 非网关协议，目标地址为本机地址（回环/通配/本机主机名），且目标端口与监听端口相同。
// 此时服务已在本地监听该端口，无需启用转发。
func IsLocalDirectTarget(rule config.ForwardRule) bool {
	proto := strings.ToLower(rule.Protocol)
	if proto == "gateway" || proto == "http" || proto == "https" {
		return false
	}
	if rule.RemotePort <= 0 || rule.RemotePort != rule.LocalPort {
		return false
	}
	addr := strings.ToLower(strings.TrimSpace(rule.RemoteAddr))
	switch addr {
	case "127.0.0.1", "0.0.0.0", "::1", "::", "localhost":
		return true
	}
	return false
}
