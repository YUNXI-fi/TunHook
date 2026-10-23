// 真实 UPnP IGD 网关联调测试（默认不运行，需显式加 -tags=liveupnp）。
// 用途：在装有 TunHook 的真实局域网内验证 IGD 发现 → 添加映射 → 删除映射链路。
// 运行：go test -tags=liveupnp -run TestUPnPLive -v ./stunhole/

//go:build liveupnp

package stunhole

import (
	"context"
	"math/rand"
	"net"
	"testing"
	"time"
)

func TestUPnPLive(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	mapper, gw, err := discoverIGD(ctx)
	if err != nil {
		t.Fatalf("discoverIGD: %v", err)
	}
	t.Logf("网关: %s", gw)
	if ext, err := mapper.GetExternalIPAddress(); err == nil {
		t.Logf("IGD 上报外网地址: %s（注意：运营商一层 NAT 时可能与 STUN 地址不同）", ext)
	}

	// 与生产一致：按到网关的真实源 IP 选择内网地址（兼容安全模式 IGD）
	internal := chooseInternalIP(net.IPv4zero, gw)
	if internal == "" {
		t.Fatal("无法确定映射内网地址")
	}
	t.Logf("映射内网地址: %s", internal)
	proto, desc := "TCP", upnpDesc("live-test")

	// 外部端口可能已被其他设备映射（718），随机挑几个候选重试
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	var port uint16
	var ok bool
	for i := 0; i < 5; i++ {
		cand := uint16(30000 + rng.Intn(30000))
		err := mapper.AddPortMapping("", cand, proto, cand, internal, true, desc, 300)
		if err == nil {
			port, ok = cand, true
			break
		}
		t.Logf("端口 %d 添加失败：%v", cand, err)
	}
	if !ok {
		t.Fatal("连续 5 个候选端口均添加失败")
	}
	t.Logf("映射已添加: 外部 %s/%d -> %s:%d", proto, port, internal, port)

	time.Sleep(time.Second)

	if err := mapper.DeletePortMapping("", port, proto); err != nil {
		t.Fatalf("DeletePortMapping: %v", err)
	}
	t.Log("映射已删除")
}
