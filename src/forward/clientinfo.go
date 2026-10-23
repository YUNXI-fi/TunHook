package forward

import "time"

// ClientInfo 描述一个客户端连接的流量统计信息。
type ClientInfo struct {
	Addr    string  `json:"addr"`     // 客户端地址（IP:port）
	TxBytes int64   `json:"tx_bytes"` // 累计上传字节
	RxBytes int64   `json:"rx_bytes"` // 累计下载字节
	TxRate  float64 `json:"tx_rate"`  // 上传速率（字节/秒）
	RxRate  float64 `json:"rx_rate"`  // 下载速率（字节/秒）
}

// rateTick 基于两次采样的累计字节差计算瞬时速率，并推进采样点。
func rateTick(lastTx, lastRx *int64, last *time.Time, tx, rx int64, now time.Time) (float64, float64) {
	dt := now.Sub(*last).Seconds()
	if dt < 0.001 {
		dt = 0.001
	}
	txRate := float64(tx-*lastTx) / dt
	rxRate := float64(rx-*lastRx) / dt
	if txRate < 0 {
		txRate = 0
	}
	if rxRate < 0 {
		rxRate = 0
	}
	*lastTx = tx
	*lastRx = rx
	*last = now
	return txRate, rxRate
}
