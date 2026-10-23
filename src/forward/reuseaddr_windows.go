//go:build windows

package forward

import "syscall"

func setReuseAddr(fd uintptr) error {
	return syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
}

// Windows 无 SO_REUSEPORT，复用端口依赖 SO_REUSEADDR。
func setReusePort(fd uintptr) error {
	return nil
}

func setReuseAddrPort(fd uintptr) error {
	return setReuseAddr(fd)
}
