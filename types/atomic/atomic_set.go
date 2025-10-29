package atomic

import (
	kangaroocollection "github.com/andantan/kangaroo/types/collection"
	"sync"
)

type AtomicSet[K comparable] struct {
	lock sync.RWMutex
	s    *kangaroocollection.Set[K]
}

func NewAtomicSet[K comparable]() *AtomicSet[K] {
	return &AtomicSet[K]{
		s: kangaroocollection.NewSet[K](),
	}
}

func (s *AtomicSet[K]) Add(k K) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.s.Add(k)
}

func (s *AtomicSet[K]) Remove(k K) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.s.Remove(k)
}

func (s *AtomicSet[K]) RemoveBatch(ks []K) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.s.RemoveBatch(ks)
}

func (s *AtomicSet[K]) Contains(k K) bool {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.s.Contains(k)
}

func (s *AtomicSet[K]) Len() int {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.s.Len()
}

func (s *AtomicSet[K]) Clear() {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.s.Clear()
}

func (s *AtomicSet[K]) Values() []K {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.s.Values()
}

func (s *AtomicSet[K]) Reset(ks []K) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.s.Reset(ks)
}

func (s *AtomicSet[K]) Iterator() func(yield func(K) bool) {
	s.lock.RLock()
	snapshot := s.s.Values()
	s.lock.RUnlock()
	return func(yield func(K) bool) {
		for _, k := range snapshot {
			if !yield(k) {
				return
			}
		}
	}
}

func (s *AtomicSet[K]) Range(f func(k K) bool) {
	s.lock.RLock()
	defer s.lock.RUnlock()
	iterator := s.s.Iterator()
	iterator(func(k K) bool {
		return f(k)
	})
}
