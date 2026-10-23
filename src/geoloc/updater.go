package geoloc

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"tunhook/store"

	"go.uber.org/zap"
)

// Update 全量更新：下载全部启用数据源并重建对应 IP 段。
func (d *DB) Update(ctx context.Context) error {
	return d.UpdateSources(ctx, nil)
}

// UpdateSources 增量更新：仅更新指定数据源（ids 为 nil/空时更新全部启用源）。
// 逐个源「下载→校验→事务替换→更新元数据→缓存」，单源失败不影响其他源；
// 全部完成后重建内存索引并持久化最近更新时间。
// ctx 取消时停止后续数据源（已完成的源保持新数据不变）。
func (d *DB) UpdateSources(ctx context.Context, ids []int64) error {
	d.mu.Lock()
	if d.updating {
		d.mu.Unlock()
		return fmt.Errorf("归属地数据正在更新中")
	}
	d.updating = true
	d.mu.Unlock()
	defer func() {
		d.mu.Lock()
		d.updating = false
		d.progDone = 0
		d.progTotal = 0
		d.mu.Unlock()
	}()

	if d.st == nil {
		return fmt.Errorf("数据库未初始化")
	}

	sources, err := d.selectSources(ids)
	if err != nil {
		return err
	}
	if len(sources) == 0 {
		return fmt.Errorf("没有可更新的数据源（请先同步数据源目录）")
	}

	d.mu.Lock()
	d.progDone = 0
	d.progTotal = int64(len(sources))
	d.mu.Unlock()

	client := &http.Client{Timeout: 60 * time.Second}
	okCount, failCount := 0, 0
	var lastErr error
	for _, src := range sources {
		if err := ctx.Err(); err != nil {
			d.logger.Info("IP归属地数据更新已中断",
				zap.Int("success", okCount), zap.Int("failed", failCount))
			lastErr = err
			failCount++
			break
		}
		if err := d.updateOne(ctx, client, src); err != nil {
			failCount++
			lastErr = err
			d.logger.Warn("数据源更新失败",
				zap.String("class", src.Class), zap.String("url", src.URL), zap.Error(err))
		} else {
			okCount++
			// 单源成功后实时重载该分类索引，让统计数字在更新过程中同步变化
			d.mu.Lock()
			d.reloadCategoryLocked(src.Category)
			d.mu.Unlock()
		}
		d.mu.Lock()
		d.progDone++
		d.mu.Unlock()
	}

	d.mu.Lock()
	d.rebuildIndexLocked()
	if okCount > 0 {
		now := time.Now()
		d.lastUpdate = now
		_ = d.st.SetSetting(KeyLastUpdate, now.Format(time.RFC3339))
	}
	d.mu.Unlock()

	d.logger.Info("IP归属地数据更新完成",
		zap.Int("success", okCount), zap.Int("failed", failCount))
	if failCount > 0 {
		return fmt.Errorf("%d 个数据源更新失败（成功 %d）：%v", failCount, okCount, lastErr)
	}
	return nil
}

// selectSources 按 ids 过滤数据源；空 ids 时返回全部启用源。
func (d *DB) selectSources(ids []int64) ([]store.GeoSource, error) {
	all, err := d.st.ListGeoSources()
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		var out []store.GeoSource
		for _, s := range all {
			if s.Enabled {
				out = append(out, s)
			}
		}
		return out, nil
	}
	want := make(map[int64]bool, len(ids))
	for _, id := range ids {
		want[id] = true
	}
	var out []store.GeoSource
	for _, s := range all {
		if want[s.ID] {
			out = append(out, s)
		}
	}
	return out, nil
}

// updateOne 更新单个数据源：下载 → 解析校验 → 事务替换 → 更新元数据 → 缓存。
func (d *DB) updateOne(ctx context.Context, client *http.Client, src store.GeoSource) error {
	if src.URL == "" {
		return fmt.Errorf("数据源链接为空")
	}
	data, err := downloadWithLogger(ctx, d.logger, client, src.URL, DefaultMaxRetries)
	if err != nil {
		d.markSourceStatus(src.ID, "error")
		return err
	}
	ranges, skipped, err := ParseData(string(data), src.Category, src.Name, src.Class)
	if err != nil {
		d.markSourceStatus(src.ID, "error")
		return fmt.Errorf("解析数据失败: %w", err)
	}
	// 事务内全量替换该源的 IP 段（失败不影响其他源与已有数据）
	if err := d.st.ReplaceGeoRangesBySource(src.ID, ranges); err != nil {
		d.markSourceStatus(src.ID, "error")
		return fmt.Errorf("写入数据库失败: %w", err)
	}
	ipCount := CountIPAddresses(ranges)
	now := time.Now().Format(time.RFC3339)
	if err := d.st.SetGeoSourceMeta(src.ID, ipCount, now); err != nil {
		return err
	}
	d.markSourceStatus(src.ID, "ok")
	// 缓存原始数据，供重启兜底导入
	d.cacheSourceData(src.ID, data)
	d.logger.Info("数据源更新完成",
		zap.String("class", src.Class),
		zap.Int("ranges", len(ranges)),
		zap.Int64("ip_count", ipCount),
		zap.Int64("skipped", skipped),
	)
	return nil
}

// markSourceStatus 记录数据源最近更新/检测状态。
func (d *DB) markSourceStatus(id int64, status string) {
	_ = d.st.SetGeoSourceStatus(id, status, time.Now().Format(time.RFC3339))
}

// cacheSourceData 把下载的原始数据写入缓存目录（dataDir/geoloc/cache/{id}.txt）。
func (d *DB) cacheSourceData(id int64, data []byte) {
	dir := filepath.Join(d.dataDir, "geoloc", "cache")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return
	}
	if err := os.WriteFile(filepath.Join(dir, strconv.FormatInt(id, 10)+".txt"), data, 0644); err != nil {
		d.logger.Warn("缓存数据源数据失败", zap.Int64("source", id), zap.Error(err))
	}
}
