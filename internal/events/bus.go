// Package events provides a bounded publish/subscribe bus for query events.
package events

import (
	"sync"
	"sync/atomic"
)

// Bus fans out items to subscribers with per-subscriber bounded buffers.
// Publishing never blocks: a slow subscriber drops items and counts them.
type Bus[T any] struct {
	mu   sync.RWMutex
	subs map[uint64]chan T
	next atomic.Uint64

	dropped atomic.Int64
}

func New[T any]() *Bus[T] {
	return &Bus[T]{subs: make(map[uint64]chan T)}
}

// Subscribe registers a channel with the given buffer size. Call the returned
// function to unsubscribe; the channel is closed on unsubscribe.
func (b *Bus[T]) Subscribe(buf int) (uint64, <-chan T, func()) {
	ch := make(chan T, buf)
	id := b.next.Add(1)
	b.mu.Lock()
	b.subs[id] = ch
	b.mu.Unlock()
	unsub := func() {
		b.mu.Lock()
		if c, ok := b.subs[id]; ok {
			delete(b.subs, id)
			close(c)
		}
		b.mu.Unlock()
	}
	return id, ch, unsub
}

// Publish delivers v to every subscriber without blocking.
func (b *Bus[T]) Publish(v T) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for _, ch := range b.subs {
		select {
		case ch <- v:
		default:
			b.dropped.Add(1)
		}
	}
}

// Dropped returns the number of items lost because subscribers were full.
func (b *Bus[T]) Dropped() int64 { return b.dropped.Load() }
