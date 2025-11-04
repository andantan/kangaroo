package atomic

import (
	"sync"

	"github.com/andantan/kangaroo/types/collection"
)

type AtomicList[T comparable] struct {
	lock sync.RWMutex
	list *collection.List[T]
}

func NewAtomicList[T comparable]() *AtomicList[T] {
	return &AtomicList[T]{
		list: collection.NewList[T](),
	}
}

func (l *AtomicList[T]) Insert(e T) {
	l.lock.Lock()
	defer l.lock.Unlock()

	l.list.Insert(e)
}

func (l *AtomicList[T]) Get(index int) (T, error) {
	l.lock.RLock()
	defer l.lock.RUnlock()

	return l.list.Get(index)
}

func (l *AtomicList[T]) Pop(index int) error {
	l.lock.Lock()
	defer l.lock.Unlock()

	return l.list.Pop(index)
}

func (l *AtomicList[T]) Remove(e T) {
	l.lock.Lock()
	defer l.lock.Unlock()

	l.list.Remove(e)
}

func (l *AtomicList[T]) Clear() {
	l.lock.Lock()
	defer l.lock.Unlock()

	l.list.Clear()
}

func (l *AtomicList[T]) GetIndex(e T) (int, error) {
	l.lock.RLock()
	defer l.lock.RUnlock()

	return l.list.GetIndex(e)
}

func (l *AtomicList[T]) Contains(e T) bool {
	l.lock.RLock()
	defer l.lock.RUnlock()

	return l.list.Contains(e)
}

func (l *AtomicList[T]) First() (T, error) {
	l.lock.RLock()
	defer l.lock.RUnlock()

	return l.list.First()
}

func (l *AtomicList[T]) Last() (T, error) {
	l.lock.RLock()
	defer l.lock.RUnlock()

	return l.list.Last()
}

func (l *AtomicList[T]) Len() int {
	l.lock.RLock()
	defer l.lock.RUnlock()

	return l.list.Len()
}

func (l *AtomicList[T]) GetData() []T {
	l.lock.RLock()
	defer l.lock.RUnlock()

	return l.list.GetData()
}

// Iterator for read only
func (l *AtomicList[T]) Iterator() func(yield func(T) bool) {
	l.lock.RLock()
	snapshot := l.list.GetData()
	l.lock.RUnlock()

	return func(yield func(T) bool) {
		for _, v := range snapshot {
			if !yield(v) {
				return
			}
		}
	}
}

// ForEach read & write iterator
func (l *AtomicList[T]) ForEach(f func(index int, value T)) {
	l.lock.RLock()
	defer l.lock.RUnlock()

	iterator := l.list.Iterator()
	index := 0
	iterator(func(value T) bool {
		f(index, value)
		index++
		return true
	})
}
