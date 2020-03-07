/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2019 WireGuard LLC. All Rights Reserved.
 */

// Package ratelimiter implements an IP-based token bucket rate
// limiter with hardcoded rates.
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
	packetCost         = int64(time.Second) / packetsPerSecond
	maxTokens          = packetCost * packetsBurstable
)

var timeNow = time.Now

// bucket is one token bucket. It accumulates 1 token per nanosecond,
// up to maxTokens. packetCost is the target qps, converted to a
// number of nanoseconds between allowed packets (not counting burst
// capacity).
type bucket struct {
	sync.Mutex
	lastTime time.Time // last time tokens were taken out.
	tokens   int64     // remaining tokens as of lastTime.
}

// Ratelimiter is a per-IP token bucket rate limiter with hardcoded
// settings.
type Ratelimiter struct {
	ticker *time.Ticker
	once   sync.Once // gates lazy initialization

	sync.RWMutex
	closed bool
	// Send a struct{}{} to signal to the GC goroutine to start
	// collecting old token buckets. Close the channel to shut down
	// the goroutine.
	stopReset chan struct{}
	tableIPv4 map[[net.IPv4len]byte]*bucket
	tableIPv6 map[[net.IPv6len]byte]*bucket
}

// Close shuts down the rate limiter's maintenance goroutine.
func (rate *Ratelimiter) Close() {
	rate.Lock()
	defer rate.Unlock()

	if rate.closed {
		return
	}

	rate.closed = true
	if rate.stopReset != nil {
		close(rate.stopReset)
	}
}

// init initializes the rate limiter.
func (rate *Ratelimiter) init() {
	rate.Lock()
	defer rate.Unlock()

	rate.stopReset = make(chan struct{})
	rate.tableIPv4 = make(map[[net.IPv4len]byte]*bucket)
	rate.tableIPv6 = make(map[[net.IPv6len]byte]*bucket)

	// start garbage collection routine
	rate.ticker = time.NewTicker(time.Second)
	go func() {
		// Initially stop the ticker because no token buckets
		// exist. The first token bucket to be created will restart
		// the ticker via rate.stopReset.
		rate.ticker.Stop()
		for {
			select {
			case _, ok := <-rate.stopReset:
				rate.ticker.Stop()
				if !ok {
					return
				}
				rate.ticker = time.NewTicker(time.Second)
			case <-rate.ticker.C:
				rate.cleanup()
			}
		}
	}()
}

// cleanup deletes token buckets that have not been accessed for at
// least garbageCollectTime.
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

	// No more work left to do, quiesce the GC goroutine. It will be
	// restarted when a token bucket is created.
	if len(rate.tableIPv4) == 0 && len(rate.tableIPv6) == 0 {
		rate.ticker.Stop()
	}
}

func (rate *Ratelimiter) Allow(ip net.IP) bool {
	rate.once.Do(rate.init)

	var (
		entry   *bucket
		keyIPv4 [net.IPv4len]byte
		keyIPv6 [net.IPv6len]byte
	)

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

	if entry == nil {
		// Need a new bucket, with the current packet's cost already
		// deducted.
		entry = &bucket{
			tokens:   maxTokens - packetCost,
			lastTime: timeNow(),
		}
		rate.Lock()
		if IPv4 != nil {
			rate.tableIPv4[keyIPv4] = entry
			// First bucket, start GCing
			if len(rate.tableIPv4) == 1 && len(rate.tableIPv6) == 0 {
				rate.stopReset <- struct{}{}
			}
		} else {
			rate.tableIPv6[keyIPv6] = entry
			// First bucket, start GCing
			if len(rate.tableIPv6) == 1 && len(rate.tableIPv4) == 0 {
				rate.stopReset <- struct{}{}
			}
		}
		rate.Unlock()
		return true
	}

	entry.Lock()
	defer entry.Unlock()

	// Update bucket's token count.
	now := timeNow()
	entry.tokens += now.Sub(entry.lastTime).Nanoseconds()
	entry.lastTime = now
	if entry.tokens > maxTokens {
		entry.tokens = maxTokens
	}

	// Subtract cost of packet
	if entry.tokens < packetCost {
		return false
	}
	entry.tokens -= packetCost
	return true
}
