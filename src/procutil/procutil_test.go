package procutil

import (
	"os"
	"path/filepath"
	"testing"
)

// TestAliveAndAliveAs 覆盖三个关键判断：
// 自身进程（身份匹配）为真；存活但身份不匹配为假（PID 被复用场景）；不存在的 PID 为假。
func TestAliveAndAliveAs(t *testing.T) {
	self := os.Getpid()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("取自身可执行文件失败: %v", err)
	}
	if !Alive(self) {
		t.Error("自身进程应判定为存活")
	}
	if !AliveAs(self, exe) {
		t.Errorf("AliveAs(自身, %s) 应为 true", exe)
	}
	// 存活但绝不可能是我们启动的程序（模拟残留 PID 被无关进程复用）
	if AliveAs(self, filepath.Join(t.TempDir(), "frpc")) {
		t.Error("身份不匹配时应为 false，否则会误判运行中并误杀无关进程")
	}
	if Alive(0) || Alive(-1) {
		t.Error("非法 PID 应判定为不存活")
	}
	if AliveAs(999999, exe) {
		t.Error("不存在的 PID 应为 false")
	}
	if AliveAs(self, "") {
		t.Error("未提供二进制路径时应为 false（无法确认身份即不认）")
	}
}

// TestExeMatches 覆盖内核升级（rename 替换二进制）后 exe 带 " (deleted)" 后缀的比对。
func TestExeMatches(t *testing.T) {
	bin := "/data/frp/frpc"
	if !ExeMatches(bin, bin) {
		t.Error("路径相同应匹配")
	}
	if !ExeMatches(bin+" (deleted)", bin) {
		t.Error("升级替换后带 (deleted) 后缀应仍匹配")
	}
	if ExeMatches("/data/frp/frpc-old", bin) {
		t.Error("不同二进制不应匹配")
	}
	if ExeMatches("/usr/bin/sleep", bin) {
		t.Error("无关程序不应匹配")
	}
}

// TestPIDFromFile 覆盖 pid 文件读取：原始值读取（不做存活校验）与异常内容。
func TestPIDFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.pid")
	if got := PIDFromFile(path); got != 0 {
		t.Errorf("文件不存在应返回 0，实际 %d", got)
	}
	if err := os.WriteFile(path, []byte("12345\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if got := PIDFromFile(path); got != 12345 {
		t.Errorf("应读出原始 PID 12345，实际 %d", got)
	}
	// 进程已退出的 PID 也要能读出（否则 pid 文件永远清理不掉）
	if err := os.WriteFile(path, []byte("999999"), 0644); err != nil {
		t.Fatal(err)
	}
	if got := PIDFromFile(path); got != 999999 {
		t.Errorf("已退出进程的 PID 仍应可读，实际 %d", got)
	}
	if err := os.WriteFile(path, []byte("not-a-pid"), 0644); err != nil {
		t.Fatal(err)
	}
	if got := PIDFromFile(path); got != 0 {
		t.Errorf("非法内容应返回 0，实际 %d", got)
	}
}
