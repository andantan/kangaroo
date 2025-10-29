package atomic

import (
	"sync"
)

type SignedInteger interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64
}

type UnsignedInteger interface {
	~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 | ~uintptr
}

type Integer interface {
	SignedInteger | UnsignedInteger
}

type AtomicCounter[N Integer] struct {
	lock sync.RWMutex
	n    N
}

func NewAtomicCounter[N Integer](initialValue N) *AtomicCounter[N] {
	return &AtomicCounter[N]{
		n: initialValue,
	}
}

func (c *AtomicCounter[N]) Get() N {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.n
}

func (c *AtomicCounter[N]) Set(newValue N) {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.n = newValue
}

func (c *AtomicCounter[N]) Add(val N) N {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.n += val
	return c.n
}

func (c *AtomicCounter[N]) Increment() N {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.n++
	return c.n
}

func (c *AtomicCounter[N]) Sub(val N) N {
	c.lock.Lock()
	defer c.lock.Unlock()

	switch any(c.n).(type) {
	case uint, uint8, uint16, uint32, uint64, uintptr:
		if c.n < val {
			c.n = 0
		} else {
			c.n -= val
		}
	default:
		c.n -= val
	}

	return c.n
}

func (c *AtomicCounter[N]) Decrement() N {
	c.lock.Lock()
	defer c.lock.Unlock()

	switch any(c.n).(type) {
	case uint, uint8, uint16, uint32, uint64, uintptr:
		if c.n > 0 {
			c.n--
		}
	default:
		c.n--
	}
	return c.n
}

func (c *AtomicCounter[N]) CompareAndSwap(old, new N) bool {
	c.lock.Lock()
	defer c.lock.Unlock()
	if c.n == old {
		c.n = new
		return true
	}
	return false
}

func (c *AtomicCounter[N]) Equal(other N) bool {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.n == other
}

func (c *AtomicCounter[N]) Gt(other N) bool {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.n > other
}

func (c *AtomicCounter[N]) Gte(other N) bool {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.n >= other
}

func (c *AtomicCounter[N]) Lt(other N) bool {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.n < other
}

func (c *AtomicCounter[N]) Lte(other N) bool {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.n <= other
}
