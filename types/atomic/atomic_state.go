package atomic

import (
	"sync"
)

type State interface {
	~int8 | ~uint8
}

type AtomicState[S State] struct {
	lock  sync.RWMutex
	state S
}

func NewAtomicState[S State](initialState S) *AtomicState[S] {
	return &AtomicState[S]{
		state: initialState,
	}
}

func (a *AtomicState[S]) Set(new S) {
	a.lock.Lock()
	defer a.lock.Unlock()
	a.state = new
}

func (a *AtomicState[S]) CompareAndSwap(old, new S) bool {
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.state == old {
		a.state = new
		return true
	}
	return false
}

func (a *AtomicState[S]) Get() S {
	a.lock.RLock()
	defer a.lock.RUnlock()
	return a.state
}

func (a *AtomicState[S]) Equal(other S) bool {
	a.lock.RLock()
	defer a.lock.RUnlock()
	return a.state == other
}

func (a *AtomicState[S]) Gt(other S) bool {
	a.lock.RLock()
	defer a.lock.RUnlock()
	return a.state > other
}

func (a *AtomicState[S]) Gte(other S) bool {
	a.lock.RLock()
	defer a.lock.RUnlock()
	return a.state >= other
}

func (a *AtomicState[S]) Lt(other S) bool {
	a.lock.RLock()
	defer a.lock.RUnlock()
	return a.state < other
}

func (a *AtomicState[S]) Lte(other S) bool {
	a.lock.RLock()
	defer a.lock.RUnlock()
	return a.state <= other
}
