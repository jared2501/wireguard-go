/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2019 WireGuard LLC. All Rights Reserved.
 */

package conn

func (bind *nativeBind) PeekLookAtSocketFd4() (fd int, err error) {
	sysconn, err := bind.ipv4.SyscallConn()
	if err != nil {
		return
	}
	err = sysconn.Control(func(f uintptr) {
		fd = int(f)
	})
	if err != nil {
		return
	}
	return
}

func (bind *nativeBind) PeekLookAtSocketFd6() (fd int, err error) {
	sysconn, err := bind.ipv6.SyscallConn()
	if err != nil {
		return
	}
	err = sysconn.Control(func(f uintptr) {
		fd = int(f)
	})
	if err != nil {
		return
	}
	return
}
