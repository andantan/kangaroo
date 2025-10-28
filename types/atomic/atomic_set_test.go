package atomic

import (
	"math/rand"
	"strconv"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAtomicSet_AddAndContains(t *testing.T) {
	s := NewAtomicSet[string]()

	// Add & Len
	s.Add("apple")
	s.Add("banana")
	assert.Equal(t, 2, s.Len())

	// Adding a duplicate should not change the length
	s.Add("apple")
	assert.Equal(t, 2, s.Len())

	// Contains
	assert.True(t, s.Contains("banana"))
	assert.False(t, s.Contains("cherry"))
}

func TestAtomicSet_Remove(t *testing.T) {
	s := NewAtomicSet[string]()
	s.Add("cat")
	s.Add("dog")

	s.Remove("cat")
	assert.Equal(t, 1, s.Len())
	assert.False(t, s.Contains("cat"))

	// Removing a non-existent element should do nothing
	s.Remove("tiger")
	assert.Equal(t, 1, s.Len())
}

func TestAtomicSet_Clear(t *testing.T) {
	s := NewAtomicSet[int]()
	s.Add(1)
	s.Add(2)
	s.Clear()
	assert.Equal(t, 0, s.Len())
	assert.False(t, s.Contains(1))
}

func TestAtomicSet_Reset(t *testing.T) {
	s := NewAtomicSet[string]()
	s.Add("a")
	s.Add("b")

	s.Reset([]string{"x", "y", "z"})
	assert.Equal(t, 3, s.Len())
	assert.False(t, s.Contains("a"))
	assert.True(t, s.Contains("y"))
}

func TestAtomicSet_RemoveBatch(t *testing.T) {
	s := NewAtomicSet[string]()
	s.Add("apple")
	s.Add("banana")
	s.Add("cherry")
	s.Add("durian")

	assert.Equal(t, 4, s.Len())

	keysToRemove := []string{"banana", "durian", "fig"}
	s.RemoveBatch(keysToRemove)

	assert.Equal(t, 2, s.Len(), "length should be 2 after removing the batch")
	assert.True(t, s.Contains("apple"))
	assert.False(t, s.Contains("banana"), "'banana' should have been removed")
	assert.True(t, s.Contains("cherry"))
	assert.False(t, s.Contains("durian"), "'durian' should have been removed")
}

func TestAtomicSet_Values(t *testing.T) {
	s := NewAtomicSet[int]()
	s.Add(10)
	s.Add(20)
	s.Add(30)

	values := s.Values()
	assert.ElementsMatch(t, []int{10, 20, 30}, values)
}

func TestAtomicSet_RangeAndIterator(t *testing.T) {
	s := NewAtomicSet[string]()
	s.Add("a")
	s.Add("b")

	// Range
	rangeResult := make(map[string]struct{})
	s.Range(func(k string) bool {
		rangeResult[k] = struct{}{}
		return true
	})
	assert.Equal(t, 2, len(rangeResult))
	assert.Contains(t, rangeResult, "a")
	assert.Contains(t, rangeResult, "b")

	// Iterator
	iteratorResult := make(map[string]struct{})
	for k := range s.Iterator() {
		iteratorResult[k] = struct{}{}
	}
	assert.Equal(t, 2, len(iteratorResult))
	assert.Contains(t, iteratorResult, "a")
	assert.Contains(t, iteratorResult, "b")
}

func TestAtomicSet_RaceCondition(t *testing.T) {
	s := NewAtomicSet[string]()
	var wg sync.WaitGroup
	numGoroutines := 20
	opsPerGoroutine := 100

	for i := 0; i < 100; i++ {
		s.Add(strconv.Itoa(i))
	}

	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				key := strconv.Itoa(rand.Intn(200))
				op := rand.Intn(9)

				switch op {
				case 0:
					s.Add(key)
				case 1:
					s.Remove(key)
				case 2:
					s.Contains(key)
				case 3:
					s.Len()
				case 4:
					s.Values()
				case 5:
					s.Range(func(k string) bool {
						return true
					})
				case 6:
					for range s.Iterator() {
					}
				case 7:
					if rand.Intn(10) == 0 {
						s.Reset([]string{"reset_val"})
					}
				case 8:
					batchToRemove := make([]string, 0, 5)
					for i := 0; i < 5; i++ {
						batchToRemove = append(batchToRemove, strconv.Itoa(rand.Intn(200)))
					}
					s.RemoveBatch(batchToRemove)
				}
			}
		}()
	}
	wg.Wait()

	t.Logf("Race condition test finished with final set length: %d", s.Len())
}
