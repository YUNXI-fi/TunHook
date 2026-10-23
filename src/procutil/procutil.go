// Package procutil 提供进程管理的公共工具：PID 文件读取与「存活 + 身份」判断。
//
// 为什么需要身份校验：pid 文件在进程被强杀（SIGKILL/断电/OOM）后会残留，残留 PID 可能被
// 系统复用给一个无关进程。只做 kill(pid, 0) 存活探测会产生两个后果：
//   - 状态误报「运行中」：界面显示隧道在跑，实际早已退出，用户点启动又被拒绝；
//   - 误杀无关进程：Stop 时会向该 PID（甚至整个进程组）发 SIGTERM，可能干掉用户的其他服务。
//
// 因此「进程存活」必须与「是我们自己启动的那个程序」一起判断：读取 /proc/<pid>/exe
// 与期望的二进制路径比对，无法确认身份时一律视为「不是自己」（宁可状态保守，也不误杀）。
package procutil

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// Alive 进程是否存活（kill 0 探测，不做身份校验）。
func Alive(pid int) bool {
	if pid <= 0 {
		return false
	}
	return syscall.Kill(pid, 0) == nil
}

// AliveAs 进程是否存活且确实是 bin 指向的程序。
// bin 为空或无法读取 /proc/<pid>/exe 时返回 false（无法确认身份即不认）。
func AliveAs(pid int, bin string) bool {
	if !Alive(pid) || strings.TrimSpace(bin) == "" {
		return false
	}
	exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return false
	}
	return ExeMatches(exe, bin)
}

// ExeMatches 比对 /proc/<pid>/exe 目标与期望的二进制路径。
// 内核升级会用 rename 原子替换二进制，运行中的旧进程其 exe 会带上 " (deleted)" 后缀，需容忍。
func ExeMatches(exe, bin string) bool {
	return filepath.Clean(strings.TrimSuffix(exe, " (deleted)")) == filepath.Clean(bin)
}

// PIDFromFile 读取 pid 文件中的原始值（不做存活校验，供清理与比对使用）。
// 进程退出后其 PID 会被复用，因此「存活校验后的 PID」不能用于判断 pid 文件是否属于自己，
// 否则文件永远清不掉。
func PIDFromFile(path string) int {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	return pid
}
