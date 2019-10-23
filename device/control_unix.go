// +build !windows

package device

import (
	"syscall"

	"golang.org/x/sys/unix"
)

func netControl(network, address string, conn syscall.RawConn) (err error) {
	err2 := conn.Control(func(fd uintptr) {
		err = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
	})
	if err == nil {
		return err2
	}
	return err
}
