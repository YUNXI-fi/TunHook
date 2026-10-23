//go:build !windows

package forward

import (
	"syscall"

	"golang.org/x/sys/unix"
)

func setReuseAddr(fd uintptr) error {
	return syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
}

// setReusePort 允许同一端口的多个 socket 共存（穿透保活连接与监听/转发 socket 共享端口）。
func setReusePort(fd uintptr) error {
	return syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, unix.SO_REUSEPORT, 1)
}

// setReuseAddrPort 同时设置 SO_REUSEADDR 与 SO_REUSEPORT（同端口复用穿透方案必需）。
func setReuseAddrPort(fd uintptr) error {
	if err := setReuseAddr(fd); err != nil {
		return err
	}
	return setReusePort(fd)
}
