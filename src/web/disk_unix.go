//go:build !windows

package web

import (
	"math"
	"syscall"
)

// systemDiskPercent 返回当前工作目录所在文件系统的已用百分比（保留 1 位小数）。
// 读取失败时返回 0，不影响系统信息接口的其余字段。
func systemDiskPercent() float64 {
	var st syscall.Statfs_t
	if err := syscall.Statfs(".", &st); err != nil {
		return 0
	}
	total := uint64(st.Blocks) * uint64(st.Bsize)
	if total == 0 {
		return 0
	}
	free := uint64(st.Bavail) * uint64(st.Bsize)
	used := total - free
	return math.Round(float64(used)/float64(total)*1000) / 10
}
