package tokenbucket

import (
	"sync"
	"testing"
	"time"
)

type event struct {
	offset time.Duration
	want   bool
}

func TestFill(t *testing.T) {
	t.Parallel()

	b := &TokenBucket{
		Cap:  3,
		Fill: 4 * time.Second,
	}
	base := time.Now()
	if !b.CanTake(base) {
		t.Fatal("initial b.Check failed")
	}

	events := []event{
		{0, true},
		{0, true},
		{0, true},
		{0, false}, // bucket full
		{11, true},
		{12, true},
		{13, true},
		{14, false}, // bucket full
		{17, true},  // one token fell out of the bucket
		{17, false},
		{24, true},
		{25, true},
		{25, false},
		{26, false},
		{29, true},
		{29, false},
		{40, true},
		{40, true},
		{40, true},
		{40, false},
	}

	for i, ev := range events {
		evt := base.Add(ev.offset * time.Second)
		got := b.CanTake(evt)
		t.Logf("i=%d: offset=%d, Check=%v, b.removed=%d, b.last(from base)=%v", i, ev.offset, got, b.removed, b.last.Sub(base))
		if got != ev.want {
			t.Errorf("i=%d, offset=%d: Check=%v, want %v", i, ev.offset, got, ev.want)
		}
		if got2 := b.Take(evt); got2 != got {
			t.Errorf("i=%d, CanTake=%v but Take=%v", i, got, got2)
		}
	}
}

func TestLocking(t *testing.T) {
	t.Parallel()

	var mu sync.RWMutex
	b := &TokenBucket{
		Cap:  100,
		Fill: 1 * time.Second,
	}

	base := time.Now()

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			now := base
			for i := 0; i < 100; i++ {
				now = now.Add(time.Second / 10)

				// Simultaneous calls to CanTake should be safe.
				mu.RLock()
				b.CanTake(now)
				mu.RUnlock()

				mu.Lock()
				b.Take(now)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
}

func TestAverage(t *testing.T) {
	t.Parallel()

	b := &TokenBucket{
		Cap:  50,
		Fill: time.Second / 50,
	}

	total := 0
	start := time.Now()
	now := start
	for i := 0; i < 250; i++ {
		now = now.Add(b.Fill)
		removed, last := b.removed, b.last
		can := b.CanTake(now)
		did := b.Take(now)
		if can != did {
			t.Errorf("i=%d, bad take: can=%v, did=%v (b.removed=%d, now.Sub(b.last)=%v)", i, can, did, removed, now.Sub(last))
		} else if did {
			t.Logf("i=%d, can=%v, did=%v", i, can, did)
		}
		if did {
			total++
		}
	}

	// Across 250 time periods of size b.Fill, we should see the bucket fill 10 times.
	rounds := 5
	if want := rounds * b.Cap; want != total {
		t.Errorf("total=%d want %d (rounds=%d, cap=%d)", total, want, rounds, b.Cap)
	}
}
