package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"tunhook/stunhole"

	"go.uber.org/zap"
)

// ============= STUN 打洞暴露 API =============
//
// 本地 UDP/TCP 端口经 STUN 打洞暴露到公网（尽力而为）：创建/启停/删除。
// 打洞受 NAT 类型限制，CGNAT / 对称 NAT 下无法公网直连（无中继兜底）。

// stunholeRateSamples 通道实时速率采样状态（id → 相邻两次列表轮询的累计值差值），
// 与转发规则 fwdRateSample 同一模式：速率 = 累计差值 / 采样间隔。
var stunholeRateSamples sync.Map

type stunholeRateSample struct {
	lastTx, lastRx int64
	lastT          time.Time
}

// stunholeSampleRate 采样单个通道的实时速率（字节/秒，>=0）。
func stunholeSampleRate(key string, txBytes, rxBytes int64) (rateTx, rateRx float64) {
	now := time.Now()
	v, _ := stunholeRateSamples.LoadOrStore(key, &stunholeRateSample{})
	a := v.(*stunholeRateSample)
	if a.lastT.IsZero() {
		a.lastTx, a.lastRx, a.lastT = txBytes, rxBytes, now
		return 0, 0
	}
	dt := now.Sub(a.lastT).Seconds()
	if dt > 0 {
		if txBytes > a.lastTx {
			rateTx = float64(txBytes-a.lastTx) / dt
		}
		if rxBytes > a.lastRx {
			rateRx = float64(rxBytes-a.lastRx) / dt
		}
	}
	a.lastTx, a.lastRx, a.lastT = txBytes, rxBytes, now
	return rateTx, rateRx
}

// handleStunHoleList 返回全部打洞通道（含运行态与实时速率）。
func (s *Server) handleStunHoleList(w http.ResponseWriter, r *http.Request) {
	holes := s.stunholeMgr.List()
	items := make([]map[string]interface{}, 0, len(holes))
	for _, h := range holes {
		rateTx, rateRx := stunholeSampleRate(h.ID, h.TxBytes, h.RxBytes)
		items = append(items, map[string]interface{}{
			"id": h.ID, "name": h.Name, "proto": h.Proto,
			"listen_port": h.ListenPort, "target": h.Target,
			"listen_ip": h.ListenIP, "listen_iface": h.ListenIface,
			"listen_addr":     h.ListenAddr,
			"webhook_mode":    h.WebhookMode,
			"webhook_trigger": h.WebhookTrigger,
			"webhook_channel": h.WebhookChannel,
			"webhook_group":   h.WebhookGroup,
			"webhook_url":     h.WebhookURL, "webhook_method": h.WebhookMethod, "webhook_body": h.WebhookBody,
			"webhook_headers": h.WebhookHeaders, "webhook_callback": h.WebhookCallback, "webhook_no_check": h.WebhookNoCheck,
			"log_level": h.LogLevel, "log_entries": h.LogEntries,
			"rate_limit_kb": h.RateLimitKB, "max_conns": h.MaxConns,
			"udp_timeout_ms": h.UDPTimeoutMS, "udp_max_sessions": h.UDPMaxSessions, "udp_block_size": h.UDPBlockSize,
			"max_failures":     h.MaxFailures,
			"use_default_stun": h.UseDefaultStun, "stun_servers": h.StunServers,
			"enabled": h.Enabled,
			"running": h.Running, "public": h.Public,
			"status": h.Status, "last_error": h.LastError,
			"updated_at": h.UpdatedAt,
			"rx_bytes":   h.RxBytes, "tx_bytes": h.TxBytes,
			"conns": h.Conns,
			"rate":  map[string]float64{"tx": rateTx, "rx": rateRx},
		})
	}
	s.writeJSON(w, http.StatusOK, apiOK(items))
}

// normalizeStunWebhook 校验并归一化 STUN 通道的 Webhook 联动字段（create / update 共用）：
//   - auto：清空通道 ID（联动首次触发时自动创建并回写），校验分组存在
//   - custom：校验回调接口配置（URL 格式、请求方式白名单），通道 ID 由联动自动分配
//   - select / 空：兼容旧数据按 select 处理（通道 ID 空 = 不联动）
//
// 校验通过返回空串，失败返回错误信息。
func (s *Server) normalizeStunWebhook(h *stunhole.Hole) string {
	// 触发条件：枚举校验（空 = addr_change 默认）
	switch h.WebhookTrigger {
	case "", "addr_change", "every_probe", "first_time":
	default:
		return "触发条件无效"
	}
	if h.WebhookTrigger == "" {
		h.WebhookTrigger = "addr_change"
	}
	switch h.WebhookMode {
	case "auto":
		h.WebhookChannel = ""
		h.WebhookGroup = strings.TrimSpace(h.WebhookGroup)
		if !s.whRecv.groupExists(h.WebhookGroup) {
			return "所选分组不存在"
		}
	case "custom":
		h.WebhookChannel = ""
		h.WebhookURL = strings.TrimSpace(h.WebhookURL)
		h.WebhookMethod = strings.TrimSpace(strings.ToUpper(h.WebhookMethod))
		h.WebhookHeaders = strings.TrimSpace(h.WebhookHeaders)
		h.WebhookCallback = strings.TrimSpace(h.WebhookCallback)
		if len(h.WebhookCallback) > 64 {
			h.WebhookCallback = h.WebhookCallback[:64]
		}
		if h.WebhookURL != "" && !strings.HasPrefix(h.WebhookURL, "http://") && !strings.HasPrefix(h.WebhookURL, "https://") {
			return "回调接口地址需为 http(s) 地址"
		}
		switch h.WebhookMethod {
		case "", "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD":
		default:
			return "请求方式无效（GET/POST/PUT/DELETE/PATCH/HEAD）"
		}
	default:
		h.WebhookMode = "select"
		h.WebhookChannel = strings.TrimSpace(h.WebhookChannel)
	}
	return ""
}

// handleStunHoleCreate 创建打洞通道并立即尝试打洞。
func (s *Server) handleStunHoleCreate(w http.ResponseWriter, r *http.Request) {
	var h stunhole.Hole
	if err := json.NewDecoder(r.Body).Decode(&h); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("请求体解析失败"))
		return
	}
	if msg := s.normalizeStunWebhook(&h); msg != "" {
		s.writeJSON(w, http.StatusOK, apiErr(msg))
		return
	}
	created, err := s.stunholeMgr.Create(h, true)
	if err != nil {
		s.writeJSON(w, http.StatusOK, apiErr("创建失败: "+err.Error()))
		return
	}
	s.logger.Info("STUN 打洞通道已创建", zap.String("id", created.ID), zap.Int("port", created.ListenPort))
	s.writeJSON(w, http.StatusOK, apiOK(created))
}

// handleStunHoleStart 启动通道（重试打洞）。
func (s *Server) handleStunHoleStart(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.stunholeMgr.Start(id)
	h, ok := s.stunholeMgr.Get(id)
	if !ok {
		s.writeJSON(w, http.StatusNotFound, apiErr("通道不存在"))
		return
	}
	s.writeJSON(w, http.StatusOK, apiOK(h))
}

// handleStunHoleStop 停止通道。
func (s *Server) handleStunHoleStop(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.stunholeMgr.Stop(id)
	h, ok := s.stunholeMgr.Get(id)
	if !ok {
		s.writeJSON(w, http.StatusNotFound, apiErr("通道不存在"))
		return
	}
	s.writeJSON(w, http.StatusOK, apiOK(h))
}

// handleStunHoleUpdate 更新通道配置（运行中的通道自动重启生效）。
func (s *Server) handleStunHoleUpdate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req stunhole.Hole
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("请求体解析失败"))
		return
	}
	updated, err := func() (stunhole.Hole, error) {
		if msg := s.normalizeStunWebhook(&req); msg != "" {
			return stunhole.Hole{}, errors.New(msg)
		}
		return s.stunholeMgr.Update(id, req)
	}()
	if err != nil {
		s.writeJSON(w, http.StatusOK, apiErr("更新失败: "+err.Error()))
		return
	}
	s.writeJSON(w, http.StatusOK, apiOK(updated))
}

// handleStunHoleLogs 返回通道事件日志（内存环形缓冲，最近 200 条）。
func (s *Server) handleStunHoleLogs(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok := s.stunholeMgr.Get(id); !ok {
		s.writeJSON(w, http.StatusNotFound, apiErr("通道不存在"))
		return
	}
	s.writeJSON(w, http.StatusOK, apiOK(s.stunholeMgr.Logs(id)))
}

// handleStunHoleDelete 删除通道；auto/custom 模式"一同创建"的联动 Webhook 通道一并清理，
// select 模式关联的是用户已有通道，仅解除引用不删除。
func (s *Server) handleStunHoleDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	h, _ := s.stunholeMgr.Get(id)
	if err := s.stunholeMgr.Delete(id); err != nil {
		s.writeJSON(w, http.StatusOK, apiErr("删除失败: "+err.Error()))
		return
	}
	if h.WebhookChannel != "" && (h.WebhookMode == "auto" || h.WebhookMode == "custom") {
		// 与 Webhook 页面删除同口径：删记录并级联清理 frpc 自定义域名代理
		s.deleteWhChannelCascade(h.WebhookChannel)
	}
	s.writeJSON(w, http.StatusOK, apiMsg("已删除"))
}
