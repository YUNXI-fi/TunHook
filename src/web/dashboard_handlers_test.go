package web

import (
	"testing"

	"tunhook/config"
)

// TestNormalizeDashboardItems 覆盖布局项结构校验：
// 空 id / 重复 id 被丢弃，超长 id 被丢弃，条目数量受上限约束，其余保持原顺序。
func TestNormalizeDashboardItems(t *testing.T) {
	in := []config.DashboardItem{
		{ID: "system", Visible: true},
		{ID: "  ", Visible: true},                     // 空 id：丢弃
		{ID: "system", Visible: false},                // 重复 id：丢弃（保留首个）
		{ID: "network", Visible: false},               // 隐藏项也要保留
		{ID: string(make([]byte, 41)), Visible: true}, // 超长 id：丢弃
	}
	out := normalizeDashboardItems(in)
	if len(out) != 2 {
		t.Fatalf("应保留 2 项，实际 %d 项: %+v", len(out), out)
	}
	if out[0].ID != "system" || !out[0].Visible {
		t.Errorf("首项应为 system(可见)，实际 %+v", out[0])
	}
	if out[1].ID != "network" || out[1].Visible {
		t.Errorf("次项应为 network(隐藏)，实际 %+v", out[1])
	}

	// 数量上限
	many := make([]config.DashboardItem, 0, dashboardLayoutLimit+10)
	for i := 0; i < dashboardLayoutLimit+10; i++ {
		many = append(many, config.DashboardItem{ID: "item" + string(rune('a'+i%26)) + string(rune('a'+i/26)), Visible: true})
	}
	if got := len(normalizeDashboardItems(many)); got != dashboardLayoutLimit {
		t.Errorf("超出上限时应截断为 %d 项，实际 %d", dashboardLayoutLimit, got)
	}
}

// TestNormalizeFieldList 覆盖卡片内字段 id 列表（隐藏行 / 行顺序）的结构校验：
// 空值 / 重复 / 超长被丢弃，数量受上限约束；全部被丢弃时归一化为 nil（等价于全部显示 / 默认顺序）。
func TestNormalizeFieldList(t *testing.T) {
	in := []string{"cpu", "  ", "memrate", "cpu", string(make([]byte, 41)), " time "}
	out := normalizeFieldList(in, dashboardFieldLimit)
	want := []string{"cpu", "memrate", "time"}
	if len(out) != len(want) {
		t.Fatalf("应保留 %d 项，实际 %d 项: %+v", len(want), len(out), out)
	}
	for i := range want {
		if out[i] != want[i] {
			t.Errorf("第 %d 项应为 %q，实际 %q", i, want[i], out[i])
		}
	}

	if got := normalizeFieldList([]string{"", "   "}, dashboardFieldLimit); got != nil {
		t.Errorf("全部无效时应返回 nil，实际 %+v", got)
	}
	if got := normalizeFieldList(nil, dashboardFieldLimit); got != nil {
		t.Errorf("空输入应返回 nil，实际 %+v", got)
	}

	// 数量上限
	many := make([]string, 0, dashboardFieldLimit+10)
	for i := 0; i < dashboardFieldLimit+10; i++ {
		many = append(many, "f"+string(rune('a'+i%26))+string(rune('a'+i/26)))
	}
	if got := len(normalizeFieldList(many, dashboardFieldLimit)); got != dashboardFieldLimit {
		t.Errorf("超出上限时应截断为 %d 项，实际 %d", dashboardFieldLimit, got)
	}
}

// TestNormalizeDashboardItemsKeepsFields 确认行配置（隐藏行与行顺序）随布局项一起通过校验，不会在保存链路中丢失。
func TestNormalizeDashboardItemsKeepsFields(t *testing.T) {
	out := normalizeDashboardItems([]config.DashboardItem{
		{ID: "system", Visible: true, HiddenFields: []string{"cpu", "", "cpu", "time"}, FieldOrder: []string{"time", "cpu", "time", "os"}},
	})
	if len(out) != 1 {
		t.Fatalf("应保留 1 项，实际 %d 项", len(out))
	}
	if len(out[0].HiddenFields) != 2 || out[0].HiddenFields[0] != "cpu" || out[0].HiddenFields[1] != "time" {
		t.Errorf("隐藏行应为 [cpu time]，实际 %+v", out[0].HiddenFields)
	}
	if len(out[0].FieldOrder) != 3 || out[0].FieldOrder[0] != "time" || out[0].FieldOrder[1] != "cpu" || out[0].FieldOrder[2] != "os" {
		t.Errorf("行顺序应为 [time cpu os]（去重且保持顺序），实际 %+v", out[0].FieldOrder)
	}
}
