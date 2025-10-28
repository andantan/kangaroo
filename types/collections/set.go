package collections

type Set[T comparable] struct {
	data map[T]struct{}
}

func NewSet[T comparable]() *Set[T] {
	return &Set[T]{
		data: make(map[T]struct{}),
	}
}

func (s *Set[T]) Add(e T) {
	s.data[e] = struct{}{}
}

func (s *Set[T]) Remove(e T) {
	delete(s.data, e)
}

func (s *Set[T]) Contains(e T) bool {
	_, ok := s.data[e]
	return ok
}

func (s *Set[T]) Len() int {
	return len(s.data)
}

func (s *Set[T]) Clear() {
	s.data = make(map[T]struct{})
}

func (s *Set[T]) Values() []T {
	values := make([]T, 0, len(s.data))
	for k := range s.data {
		values = append(values, k)
	}
	return values
}

func (s *Set[T]) Iterator() func(yield func(T) bool) {
	return func(yield func(T) bool) {
		for v := range s.data {
			if !yield(v) {
				return
			}
		}
	}
}
