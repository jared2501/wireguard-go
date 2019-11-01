/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2019 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"errors"
	"net"
	"strings"
)

const (
	ConnRoutineNumber = 2
)

/* A Bind handles listening on a port for both IPv6 and IPv4 UDP traffic
 */
type Bind interface {
	LastMark() uint32
	SetMark(value uint32) error
	ReceiveIPv6(buff []byte) (int, Endpoint, *net.UDPAddr, error)
	ReceiveIPv4(buff []byte) (int, Endpoint, *net.UDPAddr, error)
	Send(buff []byte, end Endpoint) error
	Close() error
}

type BindToInterface interface {
	BindToInterface4(interfaceIndex uint32, blackhole bool) error
	BindToInterface6(interfaceIndex uint32, blackhole bool) error
}

/* An Endpoint maintains the source/destination caching for a peer
 *
 * dst : the remote address of a peer ("endpoint" in uapi terminology)
 * src : the local address from which datagrams originate going to the peer
 */
type Endpoint interface {
	ClearSrc()           // clears the source address
	SrcToString() string // returns the local source address (ip:port)
	DstToString() string // returns the destination address (ip:port)
	DstToBytes() []byte  // used for mac2 cookie calculations
	DstIP() net.IP
	SrcIP() net.IP
	UpdateDst(addr *net.UDPAddr) error
}

func parseEndpoint(s string) (*net.UDPAddr, error) {
	// ensure that the host is an IP address

	host, _, err := net.SplitHostPort(s)
	if err != nil {
		return nil, err
	}
	if i := strings.LastIndexByte(host, '%'); i > 0 && strings.IndexByte(host, ':') >= 0 {
		// Remove the scope, if any. ResolveUDPAddr below will use it, but here we're just
		// trying to make sure with a small sanity test that this is a real IP address and
		// not something that's likely to incur DNS lookups.
		host = host[:i]
	}
	if ip := net.ParseIP(host); ip == nil {
		return nil, errors.New("Failed to parse IP address: " + host)
	}

	// parse address and port

	addr, err := net.ResolveUDPAddr("udp", s)
	if err != nil {
		return nil, err
	}
	ip4 := addr.IP.To4()
	if ip4 != nil {
		addr.IP = ip4
	}
	return addr, err
}
