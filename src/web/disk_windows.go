//go:build windows

package web

// systemDiskPercent 在 Windows 上暂未实现，返回 0（前端显示为 0%）。
func systemDiskPercent() float64 { return 0 }
