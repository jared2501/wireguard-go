package device

import (
	"syscall"

	"golang.org/x/sys/windows"
)

func netControl(_, _ string, conn syscall.RawConn) (err error) {
	err2 := conn.Control(func(fd uintptr) {
		err = windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_REUSEADDR, 1)
	})
	if err == nil {
		return err2
	}
	return err
}
