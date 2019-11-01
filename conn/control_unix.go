// +build !windows

package conn

import (
	"syscall"

	"golang.org/x/sys/unix"
)

func netControl(network, address string, conn syscall.RawConn) (err error) {
	err2 := conn.Control(func(fd uintptr) {
		err = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
	})
	if err != nil {
		return err
	}
	if err2 != nil {
		return err2
	}
	// SO_REUSEADDR on Linux/Windows is equivalent ot SO_REUSEPORT on
	// BSD/macOS, so we set it too on non-Linux systems.
	// For a detailed explanation of the difference between these socket
	// options on Linux and BSD see https://stackoverflow.com/a/14388707.
	err2 = conn.Control(func(fd uintptr) {
		err = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	})
	if err != nil {
		return err
	}
	return err2
}
