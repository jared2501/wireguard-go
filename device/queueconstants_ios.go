// +build ios

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2019 WireGuard LLC. All Rights Reserved.
 */

package device

/* Fit within memory limits for iOS's Network Extension API, which has stricter requirements */

const (
	QueueOutboundSize          = 64
	QueueInboundSize           = 64
	QueueHandshakeSize         = 64
	MaxSegmentSize             = 1700
	PreallocatedBuffersPerPool = 64
)
