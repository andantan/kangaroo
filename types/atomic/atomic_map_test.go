package atomic

import (
	"math/rand"
	"strconv"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAtomicMap_BasicCRUD(t *testing.T) {
	m := NewAtomicMap[string, int]()

	// Add & Len
	m.Put("apple", 10)
	m.Put("banana", 20)
	assert.Equal(t, 2, m.Len())

	// Get
	val, ok := m.Get("apple")
	assert.True(t, ok)
	assert.Equal(t, 10, val)

	_, ok = m.Get("cherry")
	assert.False(t, ok)

	// Exists
	assert.True(t, m.Exists("banana"))
	assert.False(t, m.Exists("durian"))

	// Remove
	m.Remove("apple")
	assert.Equal(t, 1, m.Len())
	assert.False(t, m.Exists("apple"))
}

func TestAtomicMap_PutIfNotExist(t *testing.T) {
	m := NewAtomicMap[string, int]()

	added := m.PutIfNotExist("apple", 100)
	assert.True(t, added, "should add a new element")
	assert.Equal(t, 1, m.Len())

	added = m.PutIfNotExist("apple", 200)
	assert.False(t, added, "should not add an existing element")
	val, _ := m.Get("apple")
	assert.Equal(t, 100, val, "value should not be updated")
}

func TestAtomicMap_Clear(t *testing.T) {
	m := NewAtomicMap[string, int]()
	m.Put("a", 1)
	m.Put("b", 2)
	m.Clear()
	assert.Equal(t, 0, m.Len())
	assert.False(t, m.Exists("a"))
	assert.Equal(t, 0, len(m.m))
}

func TestAtomicMap_KeysAndValues(t *testing.T) {
	m := NewAtomicMap[string, int]()
	m.Put("a", 1)
	m.Put("b", 2)
	m.Put("c", 3)

	// Keys
	keys := m.Keys()
	assert.ElementsMatch(t, []string{"a", "b", "c"}, keys)

	// Values
	values := m.Values()
	assert.ElementsMatch(t, []int{1, 2, 3}, values)
}

func TestAtomicMap_RangeAndIterator(t *testing.T) {
	m := NewAtomicMap[string, int]()
	m.Put("a", 1)
	m.Put("b", 2)
	m.Put("c", 3)

	// Range
	rangeResult := make(map[string]int)
	m.Range(func(k string, v int) bool {
		rangeResult[k] = v
		return true
	})
	assert.Equal(t, map[string]int{"a": 1, "b": 2, "c": 3}, rangeResult)

	// Iterator
	iteratorResult := make(map[string]int)
	for k, v := range m.Iterator() {
		iteratorResult[k] = v
	}
	assert.Equal(t, map[string]int{"a": 1, "b": 2, "c": 3}, iteratorResult)
}

func TestAtomicMap_ConcurrentReadWrite(t *testing.T) {
	m := NewAtomicMap[string, int]()
	var wg sync.WaitGroup
	numGoroutines := 100

	for i := 0; i < numGoroutines; i++ {
		m.Put(strconv.Itoa(i), i)
	}

	wg.Add(numGoroutines * 2)

	for i := 0; i < numGoroutines; i++ {
		go func(i int) {
			defer wg.Done()
			_, ok := m.Get(strconv.Itoa(i))
			assert.True(t, ok)
		}(i)

		go func(i int) {
			defer wg.Done()
			m.Put(strconv.Itoa(i+numGoroutines), i)
		}(i)
	}

	wg.Wait()
	assert.Equal(t, numGoroutines*2, m.Len())
}

func TestAtomicMap_RaceCondition(t *testing.T) {
	m := NewAtomicMap[string, int]()
	var wg sync.WaitGroup
	numGoroutines := 20
	opsPerGoroutine := 100

	for i := 0; i < 100; i++ {
		m.Put(strconv.Itoa(i), i)
	}

	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				key := strconv.Itoa(rand.Intn(200))
				op := rand.Intn(10)

				switch op {
				case 0:
					m.Put(key, j)
				case 1:
					m.Get(key)
				case 2:
					m.Remove(key)
				case 3:
					m.Exists(key)
				case 4:
					m.PutIfNotExist(key, j)
				case 5:
					m.Len()
				case 6:
					m.Keys()
				case 7:
					m.Values()
				case 8:
					m.Range(func(k string, v int) bool {
						return true
					})
				case 9:
					for range m.Iterator() {
					}
				}
			}
		}()
	}
	wg.Wait()

	t.Logf("Race condition test finished with final map length: %d", m.Len())
}
