/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2019 WireGuard LLC. All Rights Reserved.
 */

package ratelimiter

import (
	"net"
	"sync"
	"time"
)

const (
	packetsPerSecond   = 20
	packetsBurstable   = 5
	garbageCollectTime = time.Second
	packetCost         = 1000000000 / packetsPerSecond
	maxTokens          = packetCost * packetsBurstable
)

var timeNow = time.Now

type RatelimiterEntry struct {
	sync.Mutex
	lastTime time.Time
	tokens   int64
}

type Ratelimiter struct {
	ticker *time.Ticker

	sync.RWMutex
	stopReset chan struct{}
	tableIPv4 map[[net.IPv4len]byte]*RatelimiterEntry
	tableIPv6 map[[net.IPv6len]byte]*RatelimiterEntry
}

func (rate *Ratelimiter) Close() {
	rate.Lock()
	defer rate.Unlock()

	if rate.stopReset != nil {
		close(rate.stopReset)
	}
}

func (rate *Ratelimiter) Init() {
	rate.Lock()
	defer rate.Unlock()

	// stop any ongoing garbage collection routine

	if rate.stopReset != nil {
		close(rate.stopReset)
	}

	rate.stopReset = make(chan struct{})
	rate.tableIPv4 = make(map[[net.IPv4len]byte]*RatelimiterEntry)
	rate.tableIPv6 = make(map[[net.IPv6len]byte]*RatelimiterEntry)

	// start garbage collection routine
	rate.ticker = time.NewTicker(time.Second)
	go func() {
		rate.ticker.Stop()
		for {
			select {
			case _, ok := <-rate.stopReset:
				rate.ticker.Stop()
				if ok {
					rate.ticker = time.NewTicker(time.Second)
				} else {
					return
				}
			case <-rate.ticker.C:
				rate.cleanup()
			}
		}
	}()
}

func (rate *Ratelimiter) cleanup() {
	rate.Lock()
	defer rate.Unlock()

	for key, entry := range rate.tableIPv4 {
		entry.Lock()
		if timeNow().Sub(entry.lastTime) > garbageCollectTime {
			delete(rate.tableIPv4, key)
		}
		entry.Unlock()
	}

	for key, entry := range rate.tableIPv6 {
		entry.Lock()
		if timeNow().Sub(entry.lastTime) > garbageCollectTime {
			delete(rate.tableIPv6, key)
		}
		entry.Unlock()
	}

	if len(rate.tableIPv4) == 0 && len(rate.tableIPv6) == 0 {
		rate.ticker.Stop()
	}
}

func (rate *Ratelimiter) Allow(ip net.IP) bool {
	var entry *RatelimiterEntry
	var keyIPv4 [net.IPv4len]byte
	var keyIPv6 [net.IPv6len]byte

	// lookup entry

	IPv4 := ip.To4()
	IPv6 := ip.To16()

	rate.RLock()

	if IPv4 != nil {
		copy(keyIPv4[:], IPv4)
		entry = rate.tableIPv4[keyIPv4]
	} else {
		copy(keyIPv6[:], IPv6)
		entry = rate.tableIPv6[keyIPv6]
	}

	rate.RUnlock()

	// make new entry if not found

	if entry == nil {
		entry = new(RatelimiterEntry)
		entry.tokens = maxTokens - packetCost
		entry.lastTime = timeNow()
		rate.Lock()
		if IPv4 != nil {
			rate.tableIPv4[keyIPv4] = entry
			if len(rate.tableIPv4) == 1 && len(rate.tableIPv6) == 0 {
				rate.stopReset <- struct{}{}
			}
		} else {
			rate.tableIPv6[keyIPv6] = entry
			if len(rate.tableIPv6) == 1 && len(rate.tableIPv4) == 0 {
				rate.stopReset <- struct{}{}
			}
		}
		rate.Unlock()
		return true
	}

	// add tokens to entry

	entry.Lock()
	now := timeNow()
	entry.tokens += now.Sub(entry.lastTime).Nanoseconds()
	entry.lastTime = now
	if entry.tokens > maxTokens {
		entry.tokens = maxTokens
	}

	// subtract cost of packet

	if entry.tokens > packetCost {
		entry.tokens -= packetCost
		entry.Unlock()
		return true
	}
	entry.Unlock()
	return false
}
