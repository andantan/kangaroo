package collection

type Set[K comparable] struct {
	data map[K]struct{}
}

func NewSet[K comparable]() *Set[K] {
	return &Set[K]{
		data: make(map[K]struct{}),
	}
}

func (s *Set[K]) Add(k K) {
	s.data[k] = struct{}{}
}

func (s *Set[K]) Remove(k K) {
	delete(s.data, k)
}

func (s *Set[K]) RemoveBatch(ks []K) {
	for _, k := range ks {
		delete(s.data, k)
	}
}

func (s *Set[K]) Contains(k K) bool {
	_, ok := s.data[k]
	return ok
}

func (s *Set[K]) Len() int {
	return len(s.data)
}

func (s *Set[K]) Clear() {
	s.data = make(map[K]struct{})
}

func (s *Set[K]) Reset(ks []K) {
	s.data = make(map[K]struct{})

	for _, k := range ks {
		s.data[k] = struct{}{}
	}
}

func (s *Set[K]) Values() []K {
	snapsnot := make([]K, 0, len(s.data))
	for k := range s.data {
		snapsnot = append(snapsnot, k)
	}
	return snapsnot
}

func (s *Set[K]) Iterator() func(yield func(K) bool) {
	return func(yield func(K) bool) {
		for v := range s.data {
			if !yield(v) {
				return
			}
		}
	}
}
