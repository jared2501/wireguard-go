// Package tokenbucket implements a Token Bucket.
//
// This package is like golang.org/x/time/rate, with two notable differences.
//
// The first is there is a lot less code, with far fewer options.
// This pakcage will cover fewer cases.
//
// The second is there is no locking in the TokenBucket.
// It is up to the caller to do locking, and fancier locking schemes
// are possible. For example, using a RWMutex the Check method can be called
// while holding the R-lock, and the W-lock only required for the Add method.
//
// For general details about the algorithm see
// https://en.wikipedia.org/wiki/Token_bucket.
package tokenbucket

import (
	"time"
)

// TokenBucket is a token bucket.
//
// The token bucket starts out filled to Cap.
// Tokens can be removed by calling Take.
// The bucket refills with tokens over time, with one token
// being added for every Fill duration that passes.
type TokenBucket struct {
	Cap  int           // capacity of the bucket
	Fill time.Duration // time to add one token from the bucket

	removed int       // number of tokens removed
	last    time.Time // last time a token was removed from the bucket
}

// CanTake determines if there is a token available to take.
//
// This function does not modify any state, so it can be guarded
// by the read lock of a RWMutex.
func (b *TokenBucket) CanTake(now time.Time) (ok bool) {
	return b.removed < b.Cap || now.Sub(b.last) >= b.Fill
}

// Take attempts to take a token from the bucket.
// Take reports whether it suceeded or not.
func (b *TokenBucket) Take(now time.Time) bool {
	if b.last.IsZero() {
		b.last = now
	}
	if diff := now.Sub(b.last); diff > 0 {
		add := int(diff / b.Fill)
		if add > b.removed {
			add = b.removed
		}
		b.removed -= add
		b.last = b.last.Add(time.Duration(add) * b.Fill)
	}
	if b.removed < b.Cap {
		b.removed++
		return true
	}
	return false
}
